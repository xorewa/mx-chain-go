package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestQualLocalnetNodeCommandsKeepWorkingDirectory(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"validator", "observer"} {
		for _, strict := range []string{"0", "1"} {
			t.Run(role+strict, func(t *testing.T) {
				directory := filepath.Join(t.TempDir(), "package with spaces")
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, "node"), []byte("#!/bin/sh\nprintf '%s\\0' \"$@\" > \"$CAPTURE\"\n"), 0700); err != nil {
					t.Fatal(err)
				}
				capture := filepath.Join(directory, "args")
				command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `
if [[ "$ROLE" == validator ]]; then
  source "$MULTIVERSXTESTNETSCRIPTSDIR/include/validators.sh"
  cmd=$(assembleCommand_startValidatorNode 0 validator 0) || exit
else
  source "$MULTIVERSXTESTNETSCRIPTSDIR/include/observers.sh"
  cmd=$(assembleCommand_startObserverNode 1 1) || exit
fi
eval "$cmd"
`)
				command.Dir = directory
				command.Env = []string{"PATH=/usr/bin:/bin", "ROLE=" + role, "CAPTURE=" + capture, "TESTNETDIR=" + directory, "MULTIVERSXTESTNETSCRIPTSDIR=" + filepath.Join(root, "scripts/testnet"), "NATIVE_CONFIG_PREFLIGHT=" + strict,
					"PORT_ORIGIN_VALIDATOR=21500", "PORT_ORIGIN_VALIDATOR_REST=9500", "PORT_ORIGIN_OBSERVER=21100", "PORT_ORIGIN_OBSERVER_REST=10000", "TOTAL_NODECOUNT=8", "MULTI_KEY_NODES=0", "LOGLEVEL=*:INFO", "NODE_NICENESS=", "EXTRA_OBSERVERS_FLAGS="}
				output, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("assembled node command: %v: %s", err, output)
				}
				raw, err := os.ReadFile(capture)
				if err != nil {
					t.Fatal(err)
				}
				args := strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
				name, port := "validator0", "9500"
				if role == "observer" {
					name, port = "observer1", "10001"
				}
				host := "localhost:"
				if strict == "1" {
					host = "127.0.0.1:"
				}
				for flag, want := range map[string]string{"-working-directory": filepath.Join(directory, "node_working_dirs", name), "-rest-api-interface": host + port, "-config": "./config/config_" + role + ".toml"} {
					found := false
					for index := 0; index+1 < len(args); index++ {
						if args[index] == flag && args[index+1] == want {
							found = true
						}
					}
					if !found {
						t.Fatalf("node did not receive %s=%q: %q", flag, want, args)
					}
				}
				for _, arg := range args {
					if arg == "--drwa-config" || arg == "--drwa-startup-record" {
						t.Fatalf("ordinary command carried configured startup: %q", args)
					}
				}
			})
		}
	}
}

func TestQualLocalnetNodeCommandsRefuseIncompleteProvenance(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "scripts", "testnet"))
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"validator", "observer"} {
		t.Run(role, func(t *testing.T) {
			command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/config.sh" || exit
if [[ "$ROLE" == validator ]]; then
  source "$MULTIVERSXTESTNETSCRIPTSDIR/include/validators.sh" || exit
  assembleCommand_startValidatorNode 0 validator 0
else
  source "$MULTIVERSXTESTNETSCRIPTSDIR/include/observers.sh" || exit
  assembleCommand_startObserverNode 1 1
fi
`)
			command.Env = []string{"PATH=/usr/bin:/bin", "ROLE=" + role, "MULTIVERSXTESTNETSCRIPTSDIR=" + root,
				"TESTNETDIR=" + t.TempDir(), "TOTAL_NODECOUNT=8", "MULTI_KEY_NODES=0", "NATIVE_DRWA_STARTUP_RECORD=fixture-record"}
			output, err := command.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || len(output) != 0 {
				t.Fatalf("incomplete provenance produced a command: %v: %q", err, output)
			}
		})
	}
}
