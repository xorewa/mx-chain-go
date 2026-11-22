package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestQualLocalnetSmokeUsesOperatorsAndAlwaysStops(t *testing.T) {
	operator, err := os.ReadFile("../../scripts/testnet/smoke.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"", "config", "start", "health", "stop"} {
		t.Run("refuse_"+fault, func(t *testing.T) {
			directory := t.TempDir()
			for _, name := range []string{"include", "node"} {
				if err := os.Mkdir(filepath.Join(directory, name), 0700); err != nil {
					t.Fatal(err)
				}
			}
			files := map[string]string{
				"smoke.sh":          string(operator),
				"variables.sh":      "export TESTNETDIR=\"$PACKAGE\"\n",
				"include/config.sh": "validateNativeLocalnetOptions() { :; }\n",
				"include/tools.sh":  "nativeRuntimeLimit() { :; }\nnativeTermUIStatus() { :; }\ntmuxCommand() { if [[ \"$1\" == list-panes && \"$4\" == \"#{pane_pid}\" ]]; then echo $$; elif [[ \"$1\" == list-sessions && \"$3\" == \"#{session_name}\" ]]; then printf 'sp2-runtime\\nsp2-termui\\n'; fi; }\n",
				"node/termui":       "synthetic executable identity fixture",
			}
			for _, stage := range []string{"config", "start", "health", "stop"} {
				body := "#!/bin/bash\necho " + stage + " >> \"$TRACE\"\n"
				if stage == fault {
					body += "exit 29\n"
				}
				files[stage+".sh"] = body
			}
			for name, body := range files {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			trace := filepath.Join(directory, "trace")
			command := exec.Command("/bin/bash", "--noprofile", "--norc", filepath.Join(directory, "smoke.sh"))
			command.Env = []string{"PATH=/usr/bin:/bin", "PACKAGE=" + directory, "TRACE=" + trace, "LOCAL_OVERRIDES=" + filepath.Join(directory, "inputs.sh")}
			output, err := command.CombinedOutput()
			code := 0
			if err != nil {
				exit, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			want := "config\nstart\nhealth\nstop\n"
			expected := 0
			switch fault {
			case "config":
				want = "config\n"
				expected = 29
			case "start":
				want = "config\nstart\n"
				expected = 29
			case "health":
				expected = 29
			case "stop":
				expected = 1
			}
			raw, readErr := os.ReadFile(trace)
			if code != expected || readErr != nil || string(raw) != want {
				t.Fatalf("smoke routing: exit %d, trace %q, read %v: %s", code, raw, readErr, output)
			}
		})
	}
}

func TestQualLocalnetPackageIdentityBindsBytesAndRejectsLinks(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	directory := filepath.Join(parent, "package")
	for _, name := range []string{"filegen/filegen", "seednode/seednode", "node/node", "node/termui", "proxy/proxy"} {
		path := filepath.Join(directory, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("synthetic executable fixture"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	run := func(packagePath string) ([]byte, error) {
		command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$CONFIG_FUNCTIONS"; nativePackageIdentity`)
		command.Env = []string{"PATH=/usr/bin:/bin", "TESTNETDIR=" + packagePath, "CONFIG_FUNCTIONS=" + filepath.Join(root, "scripts/testnet/include/config.sh")}
		return command.CombinedOutput()
	}
	first, err := run(directory)
	if err != nil || !strings.HasPrefix(string(first), "Native execution package SHA-256: ") {
		t.Fatalf("package identity: %v: %s", err, first)
	}
	second, err := run(directory)
	if err != nil || string(first) != string(second) {
		t.Fatalf("unchanged package identity differs: %v: %s", err, second)
	}
	if err := os.WriteFile(filepath.Join(directory, "node/config.toml"), []byte("experimental input"), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := run(directory)
	if err != nil || string(first) == string(changed) {
		t.Fatalf("changed package input did not invalidate identity: %v: %s", err, changed)
	}
	aliases := t.TempDir()
	rootLink := filepath.Join(aliases, "package-link")
	parentLink := filepath.Join(aliases, "parent-link")
	if err := os.Symlink(directory, rootLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(parent, parentLink); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, path string }{
		{"root link", rootLink},
		{"ancestor link", filepath.Join(parentLink, "package")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := run(tc.path)
			if err == nil || !strings.Contains(string(output), "expected a canonical package directory") {
				t.Fatalf("expected path refusal, got %v: %s", err, output)
			}
			if strings.Contains(string(output), "Native execution package SHA-256") {
				t.Fatalf("aliased package produced an identity: %s", output)
			}
		})
	}
	if err := os.Symlink(filepath.Join(directory, "node/config.toml"), filepath.Join(directory, "linked-config.toml")); err != nil {
		t.Fatal(err)
	}
	if output, err := run(directory); err == nil {
		t.Fatalf("symlink package admitted: %s", output)
	}
}

func TestQualLocalnetPreflightChecksExpectedPackageIdentity(t *testing.T) {
	for _, tc := range []struct {
		name             string
		start            bool
		legacyMode       bool
		changeBeforeLoad bool
		changeOnLoad     bool
		args             func(string) []string
		wantCalls        string
		wantRefusal      string
	}{
		{name: "loader-only review", args: func(string) []string { return nil }, wantCalls: "load\nload\n"},
		{name: "matching package", wantCalls: "load\nload\n"},
		{name: "changed before preflight", changeBeforeLoad: true, wantRefusal: "package identity mismatch before loader checks"},
		{name: "changed during preflight", changeOnLoad: true, wantCalls: "load\nload\n", wantRefusal: "package identity mismatch after loader checks"},
		{name: "malformed expected hash", args: func(string) []string { return []string{"--expect-package-sha256", "invalid"} }, wantRefusal: "expected a lowercase SHA-256 digest"},
		{name: "start with prepared package", start: true, wantCalls: "load\nload\nseed\nobservers\nvalidators\ntermui\nproxy\n"},
		{name: "start refuses changed package", start: true, changeBeforeLoad: true, wantRefusal: "package identity mismatch before loader checks"},
		{name: "start refuses loader write", start: true, changeOnLoad: true, wantCalls: "load\nload\n", wantRefusal: "package identity mismatch after loader checks"},
		{name: "start refuses prepared package in legacy mode", start: true, legacyMode: true, wantRefusal: "prepared package requires native localnet mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pkg := filepath.Join(dir, "prepared package")
			entry := filepath.Join(dir, "operator")
			trace := filepath.Join(dir, "loader calls")
			source := "../../scripts/testnet"
			for _, name := range []string{"preflight.sh", "include/config.sh"} {
				body, err := os.ReadFile(filepath.Join(source, name))
				if err != nil {
					t.Fatal(err)
				}
				qualWriteLocalnetIdentityFixture(t, entry, name, body)
			}
			operator := "preflight.sh"
			qualWriteLocalnetIdentityFixture(t, entry, "variables.sh", []byte(`export TESTNETDIR="$QUAL_PACKAGE" NATIVE_CONFIG_PREFLIGHT=${QUAL_MODE:-1} OUTPUT_ROLLBACK_EPOCH=2
USE_PROXY=1
USE_TXGEN=0
SHARDCOUNT=3
USETMUX=1
USE_HARDFORK=0
COPY_BACK_CONFIGS=0
NODE_WATCHER=0
MULTI_KEY_NODES=0
SKIP_VALIDATOR_IDX=-1
SKIP_OBSERVER_IDX=-1
SEEDNODE_DELAY=0
NODE_DELAY=0
PROXY_DELAY=0
`))
			if tc.start {
				operator = "start.sh"
				body, err := os.ReadFile(filepath.Join(source, operator))
				if err != nil {
					t.Fatal(err)
				}
				qualWriteLocalnetIdentityFixture(t, entry, operator, body)
				for name, fixture := range map[string]string{
					"include/build.sh":      `prepareFolders() { echo prepare >> "$QUAL_TRACE"; return 23; }`,
					"include/validators.sh": `startValidators() { echo validators >> "$QUAL_TRACE"; }`,
					"include/observers.sh":  `startObservers() { echo observers >> "$QUAL_TRACE"; }`,
					"include/tools.sh": `nativeRuntimeLimit() { :; }
startSeednode() { echo seed >> "$QUAL_TRACE"; }
startTermUI() { echo termui >> "$QUAL_TRACE"; }
startProxy() { echo proxy >> "$QUAL_TRACE"; }
showTerminalSession() { :; }
stopNativeLocalnet() { echo cleanup >> "$QUAL_TRACE"; }
`,
				} {
					qualWriteLocalnetIdentityFixture(t, entry, name, []byte(fixture))
				}
			}
			// The filegen stub records argument flow without launching anything.
			qualWriteLocalnetIdentityFixture(t, pkg, "filegen/filegen", []byte("#!/bin/bash\nprintf 'load\\n' >> \"$QUAL_TRACE\"\nif [[ $QUAL_CHANGED == 1 ]]; then\n printf 'changed' > \"$QUAL_PACKAGE/node/genesis.json\"\nfi\n"))
			for _, name := range []string{"seednode/seednode", "node/node", "node/termui", "proxy/proxy", "node/genesis.json"} {
				qualWriteLocalnetIdentityFixture(t, pkg, name, []byte("qualification fixture"))
			}

			setup := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$CONFIG_FUNCTIONS"; nativePackageIdentity`)
			setup.Env = []string{"PATH=/usr/bin:/bin", "TESTNETDIR=" + pkg, "CONFIG_FUNCTIONS=" + filepath.Join(entry, "include/config.sh")}
			output, err := setup.CombinedOutput()
			if err != nil {
				t.Fatalf("package identity fixture: %v: %s", err, output)
			}
			fields := strings.Fields(strings.TrimPrefix(string(output), "Native execution package SHA-256: "))
			if len(fields) != 2 || len(fields[0]) != 64 || fields[1] != "-" {
				t.Fatalf("unexpected identity output %q", output)
			}
			if tc.changeBeforeLoad {
				qualWriteLocalnetIdentityFixture(t, pkg, "node/genesis.json", []byte("edited input"))
			}
			args := []string{"--expect-package-sha256", fields[0]}
			if tc.args != nil {
				args = tc.args(fields[0])
			}
			argv := append([]string{"--noprofile", "--norc", filepath.Join(entry, operator)}, args...)
			command := exec.Command("/bin/bash", argv...)
			command.Env = []string{"PATH=/usr/bin:/bin", "QUAL_PACKAGE=" + pkg, "QUAL_TRACE=" + trace}
			if tc.changeOnLoad {
				command.Env = append(command.Env, "QUAL_CHANGED=1")
			}
			if tc.legacyMode {
				command.Env = append(command.Env, "QUAL_MODE=0")
			}
			output, err = command.CombinedOutput()
			if tc.wantRefusal == "" {
				if err != nil {
					t.Fatalf("preflight rejected matching package: %v: %s", err, output)
				}
			} else if err == nil || !strings.Contains(string(output), tc.wantRefusal) {
				t.Fatalf("expected refusal %q, got %v: %s", tc.wantRefusal, err, output)
			}
			calls, err := os.ReadFile(trace)
			if err != nil && !os.IsNotExist(err) || string(calls) != tc.wantCalls {
				t.Fatalf("loader calls: got %q (%v), want %q", calls, err, tc.wantCalls)
			}
		})
	}
}

func qualWriteLocalnetIdentityFixture(t *testing.T, dir, path string, body []byte) {
	t.Helper()
	full := filepath.Join(dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, body, 0700); err != nil {
		t.Fatal(err)
	}
}
