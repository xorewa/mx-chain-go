package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQualLocalnetTerminalUsesPrivateSocketAndQuotedDirectory(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "package with spaces")
	bin := filepath.Join(directory, "bin")
	if err := os.MkdirAll(bin, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "tmux"), []byte("#!/bin/sh\nprintf '%s\\0' \"$@\" >> \"$CAPTURE\"\nprintf '\\n' >> \"$CAPTURE\"\nif [ \"$1\" = -f ]; then shift 2; fi\nif [ \"$1\" = -S ]; then shift 2; fi\n[ \"$1\" != has-session ]\n"), 0700); err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(directory, "commands")
	socket := filepath.Join(directory, "tmux.sock")
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `
source "$TERMINAL_FUNCTIONS"
setTerminalSession experimental-runtime || exit
setWorkdirForNextCommands "$TESTNETDIR/node"
runCommandInTerminal './node --help'
runCommandInTerminal './node --version'
`)
	command.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "TERMINAL_FUNCTIONS=" + filepath.Join(root, "scripts/testnet/include/terminal.sh"), "CAPTURE=" + capture, "TESTNETDIR=" + directory, "TMUX_SOCKET=" + socket, "USETMUX=1", "NATIVE_CONFIG_PREFLIGHT=1", "LOCALNET_MAX_SECONDS=30"}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("terminal invocation: %v: %s", err, output)
	}
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	sawDirectory := false
	commands := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		args := strings.Split(strings.TrimSuffix(line, "\x00"), "\x00")
		if len(args) < 5 || args[0] != "-f" || args[1] != "/dev/null" || args[2] != "-S" || args[3] != socket {
			t.Fatalf("tmux invocation escaped private socket: %q", args)
		}
		args = args[4:]
		commands[args[0]] = true
		if args[0] == "send-keys" && len(args) > 3 && strings.HasPrefix(args[3], "cd ") {
			want := "cd -- " + strings.ReplaceAll(filepath.Join(directory, "node"), " ", "\\ ")
			if args[3] != want {
				t.Fatalf("directory was not shell quoted: got %q want %q", args[3], want)
			}
			sawDirectory = true
		}
	}
	if !sawDirectory {
		t.Fatal("terminal did not bind its working directory")
	}
	for _, name := range []string{"has-session", "new-session", "split-window", "select-layout", "send-keys"} {
		if !commands[name] {
			t.Fatalf("missing terminal consumer: %s", name)
		}
	}
}

func TestQualLocalnetTerminalRefusesUnboundSocket(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "outside", "terminal emulator", "missing lifetime", "zero lifetime", "excess lifetime", "injected lifetime"} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			bin := filepath.Join(directory, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "tmux"), []byte("#!/bin/sh\ntouch \"$MARKER\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			socket, useTmux := "", "1"
			if name == "outside" {
				socket = filepath.Join(filepath.Dir(directory), "other-session.sock")
			}
			if name == "terminal emulator" {
				socket, useTmux = filepath.Join(directory, "tmux.sock"), "0"
			}
			lifetime := "30"
			switch name {
			case "missing lifetime":
				socket, lifetime = filepath.Join(directory, "tmux.sock"), ""
			case "zero lifetime":
				socket, lifetime = filepath.Join(directory, "tmux.sock"), "0"
			case "excess lifetime":
				socket, lifetime = filepath.Join(directory, "tmux.sock"), "601"
			case "injected lifetime":
				socket, lifetime = filepath.Join(directory, "tmux.sock"), "1;touch injected"
			}
			marker := filepath.Join(directory, "tmux-invoked")
			command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$TERMINAL_FUNCTIONS"; setTerminalSession experimental-runtime`)
			command.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "TERMINAL_FUNCTIONS=" + filepath.Join(root, "scripts/testnet/include/terminal.sh"), "TESTNETDIR=" + directory, "TMUX_SOCKET=" + socket, "USETMUX=" + useTmux, "NATIVE_CONFIG_PREFLIGHT=1", "LOCALNET_MAX_SECONDS=" + lifetime, "MARKER=" + marker}
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("unbound terminal admitted: %s", output)
			}
			if _, err = os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("tmux reached before private target admission", err)
			}
		})
	}
}

func TestQualLocalnetTerminalNativeSocket(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("", "ct-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	directory := filepath.Join(base, "native package with spaces")
	if err := os.MkdirAll(filepath.Join(directory, "node"), 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "tmux.sock")
	terminalEnv := []string{"PATH=/usr/bin:/bin", "SHELL=/bin/bash", "HOME=" + directory, "TERMINAL_FUNCTIONS=" + filepath.Join(root, "scripts/testnet/include/terminal.sh"), "TESTNETDIR=" + directory, "TMUX_SOCKET=" + socket, "USETMUX=1", "NATIVE_CONFIG_PREFLIGHT=1", "LOCALNET_MAX_SECONDS=30"}
	t.Cleanup(func() {
		stop := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$TERMINAL_FUNCTIONS"; stopNativeLocalnet`)
		stop.Env = terminalEnv
		output, err := stop.CombinedOutput()
		if err != nil {
			t.Errorf("private terminal cleanup: %v: %s", err, output)
		}
	})
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `
source "$TERMINAL_FUNCTIONS"
for role in multiversx-tools multiversx-nodes sp2-termui; do
  setTerminalSession "$role" || exit
  setWorkdirForNextCommands "$TESTNETDIR/node"
  runCommandInTerminal "/bin/sh -c 'printf native-terminal > terminal.marker; exec /bin/sleep 60'" || exit
done
`)
	command.Env = terminalEnv
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("native private terminal: %v: %s", err, output)
	}
	sessions, err := exec.Command("/usr/bin/tmux", "-f", "/dev/null", "-S", socket, "list-sessions", "-F", "#{session_name}").CombinedOutput()
	if err != nil || strings.TrimSpace(string(sessions)) != "sp2-runtime\nsp2-termui" {
		t.Fatalf("localnet requires one runtime and one TermUI session: %v: %s", err, sessions)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		raw, err := os.ReadFile(filepath.Join(directory, "node/terminal.marker"))
		if err == nil && string(raw) == "native-terminal" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("native terminal did not execute in package directory: %v: %s", err, raw)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestQualLocalnetStopDoesNotTouchGlobalSessions(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for _, name := range []string{"bin", "include"} {
		if err := os.Mkdir(filepath.Join(directory, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range [][2]string{{"stop.sh", "scripts/testnet/stop.sh"}, {"include/terminal.sh", "scripts/testnet/include/terminal.sh"}} {
		raw, err := os.ReadFile(filepath.Join(root, pair[1]))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, pair[0]), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, raw := range map[string]string{
		"variables.sh":          "NATIVE_CONFIG_PREFLIGHT=1\nUSETMUX=1\nUSE_PROXY=0\nUSE_TXGEN=0\n",
		"include/tools.sh":      "source \"$MULTIVERSXTESTNETSCRIPTSDIR/include/terminal.sh\"\nstopSeednode() { :; }\n",
		"include/validators.sh": "stopValidators() { :; }\n",
		"include/observers.sh":  "stopObservers() { :; }\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "bin/tmux"), []byte("#!/bin/sh\nprintf '%s\\0' \"$@\" >> \"$CAPTURE\"\nprintf '\\n' >> \"$CAPTURE\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(directory, "commands")
	socket := filepath.Join(directory, "tmux.sock")
	command := exec.Command("/bin/bash", "--noprofile", "--norc", filepath.Join(directory, "stop.sh"))
	command.Env = []string{"PATH=" + filepath.Join(directory, "bin") + ":/usr/bin:/bin", "CAPTURE=" + capture, "TMUX_SOCKET=" + socket, "TESTNETDIR=" + directory}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("private stop: %v: %s", err, output)
	}
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		args := strings.Split(strings.TrimSuffix(line, "\x00"), "\x00")
		if len(args) < 5 || args[0] != "-f" || args[1] != "/dev/null" || args[2] != "-S" || args[3] != socket {
			t.Fatalf("shutdown reached an unowned server: %q", args)
		}
	}
}

func TestQualLocalnetTerminalExpiresWithoutController(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("", "ce-")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "tmux.sock")
	t.Cleanup(func() {
		_ = exec.Command("/usr/bin/tmux", "-f", "/dev/null", "-S", socket, "kill-server").Run()
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `
source "$TERMINAL_FUNCTIONS"
setTerminalSession multiversx-tools || exit
setWorkdirForNextCommands "$TESTNETDIR"
runCommandInTerminal "/bin/sh -c 'touch started; exec /bin/sleep 60'" || exit
`)
	command.Env = []string{"PATH=/usr/bin:/bin", "SHELL=/bin/bash", "HOME=" + directory, "TERMINAL_FUNCTIONS=" + filepath.Join(root, "scripts/testnet/include/terminal.sh"), "TESTNETDIR=" + directory, "TMUX_SOCKET=" + socket, "USETMUX=1", "NATIVE_CONFIG_PREFLIGHT=1", "LOCALNET_MAX_SECONDS=1"}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bounded terminal: %v: %s", err, output)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(directory, "started")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("selected process never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for {
		err = exec.Command("/usr/bin/tmux", "-f", "/dev/null", "-S", socket, "has-session", "-t", "sp2-runtime").Run()
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("package process survived its explicit lifetime without a controller")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
