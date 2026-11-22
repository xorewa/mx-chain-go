package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func qualLocalnetConfigWithOverrides(t *testing.T, overrides string) string {
	t.Helper()
	body, err := os.ReadFile("../../scripts/testnet/include/config.sh")
	if err != nil {
		t.Fatal(err)
	}
	return string(body) + "\n" + overrides
}

func TestQualLocalnetStartStopsBeforeSeedOnPreflightRefusal(t *testing.T) {
	for _, fault := range []string{"preflight", "build", "prepare", "node", "termui", "copy", "seed config", "seed update", "node config", "node update", "proxy folders", "proxy"} {
		t.Run(fault, func(t *testing.T) { qualLocalnetStartRefusal(t, fault) })
	}
}

func TestQualLocalnetStartRejectsUnpermittedModeBeforeBuild(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	operator, err := os.ReadFile(filepath.Join(root, "scripts/testnet/start.sh"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join(root, "scripts/testnet/include/config.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, override := range []string{"USE_TXGEN=1", "USE_HARDFORK=1", "COPY_BACK_CONFIGS=1", "NODE_WATCHER=1", "MULTI_KEY_NODES=1", "SKIP_VALIDATOR_IDX=0", "SKIP_OBSERVER_IDX=1", "SHARDCOUNT=2", "USE_PROXY=0"} {
		t.Run(override, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Mkdir(filepath.Join(directory, "include"), 0700); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{
				"start.sh": string(operator), "include/config.sh": string(config),
				"variables.sh":          "NATIVE_CONFIG_PREFLIGHT=1\nSHARDCOUNT=3\nUSETMUX=1\nUSE_PROXY=1\nUSE_TXGEN=0\nUSE_HARDFORK=0\nCOPY_BACK_CONFIGS=0\nNODE_WATCHER=0\nMULTI_KEY_NODES=0\nSKIP_VALIDATOR_IDX=-1\nSKIP_OBSERVER_IDX=-1\n" + override + "\n",
				"include/build.sh":      "prepareFolders() { touch \"$MARKER\"; return 23; }\n",
				"include/tools.sh":      "nativeRuntimeLimit() { :; }\n",
				"include/validators.sh": "", "include/observers.sh": "",
			} {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			marker := filepath.Join(directory, "build-reached")
			command := exec.Command("/bin/bash", "--noprofile", "--norc", filepath.Join(directory, "start.sh"))
			command.Env = []string{"PATH=/usr/bin:/bin", "MARKER=" + marker}
			output, err := command.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 {
				t.Fatalf("unpermitted native mode reached build: %v: %s", err, output)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("unpermitted mode changed the package", err)
			}
		})
	}
}

func TestQualLocalnetStartCleansPartialLaunch(t *testing.T) {
	operator, err := os.ReadFile("../../scripts/testnet/start.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"seed", "observers", "validators", "ui", "proxy"} {
		t.Run(fault, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Mkdir(filepath.Join(directory, "include"), 0700); err != nil {
				t.Fatal(err)
			}
			stages := map[string]string{}
			for _, stage := range []string{"seed", "observers", "validators", "ui", "proxy"} {
				stages[stage] = "echo " + stage + " >> \"$TRACE\"; touch \"$MARKER\""
			}
			stages[fault] += "; return 29"
			for name, body := range map[string]string{
				"start.sh":              string(operator),
				"variables.sh":          "NATIVE_CONFIG_PREFLIGHT=1\nUSE_PROXY=1\nUSE_TXGEN=0\nALWAYS_UPDATE_CONFIGS=0\nSEEDNODE_DELAY=0\nNODE_DELAY=0\nPROXY_DELAY=0\n",
				"include/build.sh":      "prepareFolders() { :; }\nbuildSeednode() { :; }\nbuildNode() { :; }\nbuildTermUI() { :; }\nprepareFolders_Proxy() { :; }\nbuildProxy() { :; }\n",
				"include/config.sh":     qualLocalnetConfigWithOverrides(t, "validateNativeLocalnetOptions() { :; }\ncopySeednodeConfig() { :; }\nupdateSeednodeConfig() { :; }\nnativePackageIdentity() { :; }\npreflightConfig() { :; }\n"),
				"include/validators.sh": "startValidators() { " + stages["validators"] + "; }\n",
				"include/observers.sh":  "startObservers() { " + stages["observers"] + "; }\n",
				"include/tools.sh":      "nativeRuntimeLimit() { :; }\nstartSeednode() { " + stages["seed"] + "; }\nshowTerminalSession() { :; }\nstartTermUI() { " + stages["ui"] + "; }\nstartProxy() { " + stages["proxy"] + "; }\nstopNativeLocalnet() { echo cleanup >> \"$TRACE\"; rm -f -- \"$MARKER\"; }\n",
			} {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			marker, trace := filepath.Join(directory, "owned-process"), filepath.Join(directory, "trace")
			command := exec.Command("/bin/bash", "--noprofile", "--norc", filepath.Join(directory, "start.sh"))
			command.Env = []string{"PATH=/usr/bin:/bin", "MARKER=" + marker, "TRACE=" + trace}
			output, err := command.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 29 {
				t.Fatalf("launch refusal lost: %v: %s", err, output)
			}
			raw, err := os.ReadFile(trace)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{}
			for _, stage := range []string{"seed", "observers", "validators", "ui", "proxy"} {
				want = append(want, stage)
				if stage == fault {
					break
				}
			}
			want = append(want, "cleanup")
			if string(raw) != strings.Join(want, "\n")+"\n" {
				t.Fatalf("continued after failed %s or missed cleanup: %s", fault, raw)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("partial launch remained", err)
			}
		})
	}
}

func TestQualLocalnetNodeIterationPropagatesLaunchRefusal(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"Observers", "Validators", "ValidatorsMultiKey"} {
		for _, fault := range []string{"0", "2"} {
			t.Run(kind+fault, func(t *testing.T) {
				command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/observers.sh"
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/validators.sh"
sleep() { :; }
start() { printf '%s\n' "$2"; [[ "$2" != "$FAULT" ]] || return 29; }
"iterateOver$KIND" start
`)
				command.Env = []string{"PATH=/usr/bin:/bin", "MULTIVERSXTESTNETSCRIPTSDIR=" + filepath.Join(root, "scripts/testnet"), "KIND=" + kind, "FAULT=" + fault, "SHARDCOUNT=3", "SHARD_OBSERVERCOUNT=1", "META_OBSERVERCOUNT=1", "SHARD_VALIDATORCOUNT=1", "META_VALIDATORCOUNT=1", "SKIP_VALIDATOR_IDX=-1", "SKIP_OBSERVER_IDX=-1"}
				output, err := command.CombinedOutput()
				exit, ok := err.(*exec.ExitError)
				want := "0\n"
				if fault == "2" {
					want = "0\n1\n2\n"
				}
				if !ok || exit.ExitCode() != 29 || string(output) != want {
					t.Fatalf("node iteration swallowed refusal: %v: %s", err, output)
				}
			})
		}
	}
}

func qualLocalnetStartRefusal(t *testing.T, fault string) {
	t.Helper()
	operator, err := os.ReadFile("../../scripts/testnet/start.sh")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err = os.Mkdir(filepath.Join(directory, "include"), 0700); err != nil {
		t.Fatal(err)
	}
	stages := map[string]string{"build": ":", "prepare": ":", "node": ":", "termui": ":", "copy": ":", "seed config": ":", "seed update": ":", "node config": ":", "node update": ":", "proxy folders": ":", "proxy": ":"}
	preflight, expected := "return 17", 17
	if fault != "preflight" {
		stages[fault], preflight, expected = "return 23", ":", 23
	}
	for name, body := range map[string]string{
		"start.sh":              string(operator),
		"variables.sh":          "NATIVE_CONFIG_PREFLIGHT=1\nUSE_PROXY=1\nUSE_TXGEN=0\nALWAYS_UPDATE_CONFIGS=1\nSEEDNODE_DELAY=0\nNODE_DELAY=0\nPROXY_DELAY=0\n",
		"include/build.sh":      "prepareFolders() { " + stages["prepare"] + "; }\nbuildSeednode() { " + stages["build"] + "; }\nbuildNode() { " + stages["node"] + "; }\nbuildTermUI() { " + stages["termui"] + "; }\nprepareFolders_Proxy() { " + stages["proxy folders"] + "; }\nbuildProxy() { " + stages["proxy"] + "; }\n",
		"include/config.sh":     qualLocalnetConfigWithOverrides(t, "validateNativeLocalnetOptions() { :; }\ncopyConfig() { "+stages["copy"]+"; }\ncopySeednodeConfig() { "+stages["seed config"]+"; }\nupdateSeednodeConfig() { "+stages["seed update"]+"; }\ncopyNodeConfig() { "+stages["node config"]+"; }\nupdateNodeConfig() { "+stages["node update"]+"; }\nnativePackageIdentity() { :; }\npreflightConfig() { "+preflight+"; }\n"),
		"include/validators.sh": "startValidators() { :; }\n",
		"include/observers.sh":  "startObservers() { :; }\n",
		"include/tools.sh":      "nativeRuntimeLimit() { :; }\nstartSeednode() { touch \"$MARKER\"; }\nshowTerminalSession() { :; }\nstartTermUI() { :; }\nstartProxy() { :; }\n",
	} {
		if err = os.WriteFile(filepath.Join(directory, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(directory, "seed-started")
	command := exec.Command("/bin/bash", "--noprofile", "--norc", filepath.Join(directory, "start.sh"))
	command.Env = []string{"PATH=/usr/bin:/bin", "MARKER=" + marker}
	output, err := command.CombinedOutput()
	exit, isExit := err.(*exec.ExitError)
	if !isExit || exit.ExitCode() != expected {
		t.Fatalf("start ignored native loader refusal: %v: %s", err, output)
	}
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("seed started after loader refusal", err)
	}
}

func TestQualLocalnetExplicitInputFile(t *testing.T) {
	variables, err := os.ReadFile("../../scripts/testnet/variables.sh")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	scripts := filepath.Join(directory, "scripts/testnet")
	if err = os.MkdirAll(scripts, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(scripts, "variables.sh"), variables, 0600); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(directory, "explicit inputs.sh")
	if err = os.WriteFile(inputs, []byte("SHARDCOUNT=3\nSHARD_VALIDATORCOUNT=1\nMETA_VALIDATORCOUNT=2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", "source \"$MULTIVERSXTESTNETSCRIPTSDIR/variables.sh\"; printf '%s\\n' \"$SHARDCOUNT\" \"$SHARD_VALIDATORCOUNT\" \"$META_VALIDATORCOUNT\"")
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + directory, "MULTIVERSXTESTNETSCRIPTSDIR=" + scripts, "LOCAL_OVERRIDES=" + inputs}
	output, err := command.CombinedOutput()
	if err != nil || string(output) != "3\n1\n2\n" {
		t.Fatalf("explicit localnet inputs were ignored: %v: %q", err, output)
	}
	link := filepath.Join(directory, "symlink.sh")
	if err = os.Symlink(inputs, link); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"relative.sh", filepath.Join(directory, "missing.sh"), link} {
		command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", "source \"$MULTIVERSXTESTNETSCRIPTSDIR/variables.sh\" || exit; echo continued")
		command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + directory, "MULTIVERSXTESTNETSCRIPTSDIR=" + scripts, "LOCAL_OVERRIDES=" + invalid}
		if output, err = command.CombinedOutput(); err == nil || strings.Contains(string(output), "continued") {
			t.Fatalf("invalid input path continued: %q: %v: %s", invalid, err, output)
		}
	}
}

func TestQualLocalnetPreflightUsesFinalNativeInputs(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, refusal := range []string{"", "validator", "observer"} {
		t.Run("refuse_"+refusal, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "package with spaces")
			if err := os.MkdirAll(filepath.Join(directory, "filegen"), 0700); err != nil {
				t.Fatal(err)
			}
			capture := filepath.Join(directory, "calls")
			binary := "#!/bin/bash\nprintf '%s\\n' CALL \"$@\" >> \"$CAPTURE\"\nfor arg in \"$@\"; do\n if [[ -n $REFUSE && $arg == *config_${REFUSE}.toml ]]; then exit 19; fi\ndone\n"
			if err := os.WriteFile(filepath.Join(directory, "filegen/filegen"), []byte(binary), 0700); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", "source \"$CONFIG_FUNCTIONS\"; preflightConfig")
			command.Env = []string{"PATH=/usr/bin:/bin", "CONFIG_FUNCTIONS=" + filepath.Join(root, "scripts/testnet/include/config.sh"),
				"TESTNETDIR=" + directory, "CONFIGGENERATOROUTPUTDIR=output", "NATIVE_CONFIG_PREFLIGHT=1", "OUTPUT_ROLLBACK_EPOCH=2",
				"SHARDCOUNT=3", "SHARD_VALIDATORCOUNT=1", "SHARD_OBSERVERCOUNT=1", "SHARD_CONSENSUS_SIZE=1", "META_VALIDATORCOUNT=2", "META_OBSERVERCOUNT=1", "META_CONSENSUS_SIZE=1",
				"GENESIS_STAKE_TYPE=direct", "HYSTERESIS=0", "ROUND_DURATION_IN_MS=6000", "MULTI_KEY_NODES=0", "CAPTURE=" + capture, "REFUSE=" + refusal}
			output, err := command.CombinedOutput()
			if refusal == "" {
				if err != nil {
					t.Fatalf("preflight: %v: %s", err, output)
				}
			} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 19 {
				t.Fatalf("native loader refusal was lost: %v: %s", err, output)
			}
			raw, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			calls := strings.Split(strings.TrimSuffix(string(raw), "\n"), "CALL\n")[1:]
			wantCalls := 2
			if refusal == "validator" {
				wantCalls = 1
			}
			if len(calls) != wantCalls {
				t.Fatalf("expected %d loader calls, got %q", wantCalls, raw)
			}
			for i, call := range calls {
				role := []string{"validator", "observer"}[i]
				args := strings.Split(strings.TrimSuffix(call, "\n"), "\n")
				for _, required := range []string{"--validate-only", "--loopback-only"} {
					if !strings.Contains("\n"+call, "\n"+required+"\n") {
						t.Fatalf("missing %s: %q", required, args)
					}
				}
				for flag, want := range map[string]string{
					"output-directory": filepath.Join(directory, "node/config"), "node-config": filepath.Join(directory, "node/config/config_"+role+".toml"),
					"epoch-config": filepath.Join(directory, "node/config/enableEpochs.toml"), "output-rollback-epoch": "2", "num-of-shards": "3",
					"economics-config":           filepath.Join(directory, "node/config/economics.toml"),
					"num-of-nodes-in-each-shard": "1", "consensus-group-size": "1", "num-of-metachain-nodes": "2", "metachain-consensus-group-size": "1",
					"node-p2p-config": filepath.Join(directory, "node/config/p2p.toml"), "seednode-p2p-config": filepath.Join(directory, "seednode/config/p2p.toml"),
					"node-preferences": filepath.Join(directory, "node/config/prefs.toml"),
				} {
					got := ""
					for j := 0; j+1 < len(args); j++ {
						if strings.TrimLeft(args[j], "-") == flag {
							got = args[j+1]
						}
					}
					if got != want {
						t.Fatalf("%s loader %s: got %q, want %q", role, flag, got, want)
					}
				}
			}
		})
	}
}

func TestQualLocalnetRestartEntryPreflightsBeforeSeed(t *testing.T) {
	source, err := os.ReadFile("../../scripts/testnet/start.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, fault, trace string
		args               []string
		exit               int
	}{
		{name: "orphan-option", args: []string{"--restart-view-receipt", "/receipt", "receipt-digest"}, exit: 1},
		{name: "wrong-arity", args: []string{"--expect-package-sha256", "seal", "--restart-view-receipt", "/receipt"}, exit: 1},
		{name: "bad-override", fault: "override", trace: "override\n", exit: 17},
		{name: "bad-view", fault: "view", trace: "override\nvariables\nrestart\n", exit: 29},
		{name: "accepted-view", trace: "override\nvariables\nrestart\nseed\nobservers\nvalidators\ntermui\nproxy\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, script := range map[string]string{
				"start.sh":     string(source),
				"variables.sh": "echo variables >> \"$TRACE\"\nNATIVE_CONFIG_PREFLIGHT=1\nUSE_PROXY=1\nUSE_TXGEN=0\nSEEDNODE_DELAY=0\nNODE_DELAY=0\nPROXY_DELAY=0\n",
				"include/config.sh": qualLocalnetConfigWithOverrides(t, `
validateNativeLocalnetOptions() { :; }
preflightRestartOverride() { [[ "$*" == 'seal /receipt receipt-digest' ]] || return 2; echo override >> "$TRACE"; if [[ $FAULT == override ]]; then return 17; fi; }
preflightExpectedRestartView() { [[ "$*" == 'seal /receipt receipt-digest' ]] || return 2; echo restart >> "$TRACE"; if [[ $FAULT == view ]]; then return 29; fi; }
preflightExpectedPackage() { echo unexpected-cold >> "$TRACE"; return 33; }
`),
				"include/build.sh":      "prepareFolders() { echo unexpected-generation >> \"$TRACE\"; return 34; }\n",
				"include/observers.sh":  "startObservers() { echo observers >> \"$TRACE\"; }\n",
				"include/validators.sh": "startValidators() { echo validators >> \"$TRACE\"; }\n",
				"include/tools.sh": `
nativeRuntimeLimit() { :; }
startSeednode() { echo seed >> "$TRACE"; }
showTerminalSession() { :; }
startTermUI() { echo termui >> "$TRACE"; }
startProxy() { echo proxy >> "$TRACE"; }
stopNativeLocalnet() { echo unexpected-cleanup >> "$TRACE"; }
`,
			} {
				qualWriteLocalnetIdentityFixture(t, dir, name, []byte(script))
			}
			args := tc.args
			if args == nil {
				args = []string{"--expect-package-sha256", "seal", "--restart-view-receipt", "/receipt", "receipt-digest"}
			}
			trace := filepath.Join(dir, "trace")
			cmd := exec.Command("/bin/bash", append([]string{"--noprofile", "--norc", filepath.Join(dir, "start.sh")}, args...)...)
			cmd.Env = []string{"PATH=/usr/bin:/bin", "TRACE=" + trace, "FAULT=" + tc.fault}
			raw, err := cmd.CombinedOutput()
			var status int
			if err != nil {
				exit, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatal(err)
				}
				status = exit.ExitCode()
			}
			steps, err := os.ReadFile(trace)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if status != tc.exit || string(steps) != tc.trace {
				t.Fatalf("exit %d trace %q output %q", status, steps, raw)
			}
		})
	}
}

func TestQualLocalnetStartRefusesMissingProvenanceBeforeEffects(t *testing.T) {
	start, err := os.ReadFile("../../scripts/testnet/start.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, record, overlay, trace string
		restart                      bool
	}{
		{name: "record-only", record: "fixture-record", trace: "variables\n"},
		{name: "overlay-only", overlay: "/fixture-overlay", trace: "variables\n"},
		{name: "both-without-admission", record: "fixture-record", overlay: "/fixture-overlay", trace: "variables\n"},
		{name: "restart-without-admission", record: "fixture-record", overlay: "/fixture-overlay", trace: "override\nvariables\n", restart: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			qualWriteLocalnetIdentityFixture(t, dir, "start.sh", start)
			qualWriteLocalnetIdentityFixture(t, dir, "variables.sh", []byte("echo variables >> \"$TRACE\"\nNATIVE_CONFIG_PREFLIGHT=1\n"))
			config := qualLocalnetConfigWithOverrides(t, `
preflightRestartOverride() { [[ "$*" == 'seal /receipt receipt-digest' ]] || return 2; echo override >> "$TRACE"; }
preflightExpectedRestartView() { echo unexpected-restart >> "$TRACE"; return 33; }
preflightExpectedPackage() { echo unexpected-package >> "$TRACE"; return 33; }
`)
			qualWriteLocalnetIdentityFixture(t, dir, "include/config.sh", []byte(config))
			for _, name := range []string{"build", "validators", "observers", "tools"} {
				body := "echo unexpected-include-" + name + " >> \"$TRACE\"\nreturn 23\n"
				qualWriteLocalnetIdentityFixture(t, dir, "include/"+name+".sh", []byte(body))
			}
			argv := []string{"--noprofile", "--norc", filepath.Join(dir, "start.sh")}
			if tc.restart {
				argv = append(argv, "--expect-package-sha256", "seal", "--restart-view-receipt", "/receipt", "receipt-digest")
			}
			trace := filepath.Join(dir, "trace")
			cmd := exec.Command("/bin/bash", argv...)
			cmd.Env = []string{"PATH=/usr/bin:/bin", "TRACE=" + trace, "NATIVE_DRWA_STARTUP_RECORD=" + tc.record, "NATIVE_DRWA_OVERLAY=" + tc.overlay}
			raw, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 {
				t.Fatalf("provenance refusal: %v: %s", err, raw)
			}
			steps, err := os.ReadFile(trace)
			if err != nil || string(steps) != tc.trace {
				t.Fatalf("provenance refusal reached a later effect: %v: %q", err, steps)
			}
		})
	}
}
