package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestQualLocalnetTermUITargetsShardOne(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, shards, observers, skipped, origin, wantPort string }{
		{"one observer per shard", "3", "1", "-1", "10000", "10001"},
		{"two observers per shard", "3", "2", "-1", "10000", "10002"},
		{"absent observers", "3", "0", "-1", "10000", ""},
		{"absent shard one", "1", "1", "-1", "10000", ""},
		{"skipped target", "3", "1", "1", "10000", ""},
		{"port overflow", "3", "1", "-1", "65535", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/tools.sh"
setTerminalSession() { printf '%s\n' "$1"; }
setTerminalLayout() { :; }
setWorkdirForNextCommands() { printf '%s\n' "$1"; }
runCommandInTerminal() { printf '%s\n' "$1"; }
startTermUI
`)
			command.Env = []string{"PATH=/usr/bin:/bin", "MULTIVERSXTESTNETSCRIPTSDIR=" + filepath.Join(root, "scripts/testnet"), "TESTNETDIR=/tmp/experimental localnet package",
				"SHARDCOUNT=" + tc.shards, "SHARD_OBSERVERCOUNT=" + tc.observers, "PORT_ORIGIN_OBSERVER_REST=" + tc.origin, "SKIP_OBSERVER_IDX=" + tc.skipped, "NATIVE_CONFIG_PREFLIGHT=1"}
			output, err := command.CombinedOutput()
			if tc.wantPort == "" {
				if err == nil || len(output) != 0 {
					t.Fatalf("absent shard-1 observer reached terminal creation: %v: %s", err, output)
				}
				return
			}
			want := "sp2-termui\n/tmp/experimental localnet package/node\n./termui --address 127.0.0.1:" + tc.wantPort + "\n"
			if err != nil || string(output) != want {
				t.Fatalf("TermUI does not target the shard-1 observer: %v: got %q want %q", err, output, want)
			}
		})
	}
}

func TestQualLocalnetActualTermUIReadsObserver(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("", "cu-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	if err := os.Mkdir(filepath.Join(directory, "node"), 0700); err != nil {
		t.Fatal(err)
	}
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin/go"), "build", "-o", filepath.Join(directory, "node/termui"), "../termui")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("native TermUI build: %v: %s", err, output)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/node/status" && r.URL.Path != "/node/bootstrapstatus" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		calls.Add(1)
		_, _ = w.Write([]byte(`{"code":"successful","error":"","data":{"metrics":{"erd_node_display_name":"","erd_node_type":"observer","erd_shard_id":1,"erd_nonce":7,"erd_current_round":2,"erd_synchronized_round":2,"erd_chain_id":"local-testnet","erd_probable_highest_nonce":7}}}`))
	}))
	defer server.Close()
	_, portString, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	env := []string{"PATH=/usr/bin:/bin", "SHELL=/bin/bash", "HOME=" + directory, "MULTIVERSXTESTNETSCRIPTSDIR=" + filepath.Join(root, "scripts/testnet"), "TESTNETDIR=" + directory, "TMUX_SOCKET=" + filepath.Join(directory, "tmux.sock"), "NATIVE_CONFIG_PREFLIGHT=1", "USETMUX=1", "LOCALNET_MAX_SECONDS=30", "SHARDCOUNT=3", "SHARD_OBSERVERCOUNT=1", "PORT_ORIGIN_OBSERVER_REST=" + strconv.Itoa(port-1), "SKIP_OBSERVER_IDX=-1"}
	t.Cleanup(func() {
		stop := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$MULTIVERSXTESTNETSCRIPTSDIR/include/tools.sh"; stopNativeLocalnet`)
		stop.Env = env
		if output, err := stop.CombinedOutput(); err != nil {
			t.Errorf("native TermUI shutdown: %v: %s", err, output)
		}
	})
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$MULTIVERSXTESTNETSCRIPTSDIR/include/tools.sh"; startTermUI || exit; nativeTermUIStatus`)
	command.Env = env
	output, err := command.CombinedOutput()
	if err != nil || calls.Load() == 0 {
		t.Fatalf("native TermUI did not read and display observer: %v, requests %d: %s", err, calls.Load(), output)
	}
}

func TestQualLocalnetStartsTermUIAfterNodes(t *testing.T) {
	start, err := os.ReadFile(filepath.Join("..", "..", "scripts", "testnet", "start.sh"))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "include"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, raw := range map[string][]byte{
		"start.sh":              start,
		"variables.sh":          []byte("NATIVE_CONFIG_PREFLIGHT=1\nUSE_PROXY=0\nUSE_TXGEN=0\nALWAYS_UPDATE_CONFIGS=0\nSEEDNODE_DELAY=0\nNODE_DELAY=0\n"),
		"include/build.sh":      []byte("prepareFolders() { :; }\nbuildSeednode() { :; }\nbuildNode() { :; }\nbuildTermUI() { echo stage-build-ui; }\n"),
		"include/config.sh":     []byte(qualLocalnetConfigWithOverrides(t, "validateNativeLocalnetOptions() { :; }\ncopySeednodeConfig() { :; }\nupdateSeednodeConfig() { :; }\nnativePackageIdentity() { :; }\npreflightConfig() { echo stage-preflight; }\n")),
		"include/tools.sh":      []byte("nativeRuntimeLimit() { :; }\nstartSeednode() { echo stage-seed; }\nshowTerminalSession() { :; }\nstartTermUI() { echo stage-start-ui; }\n"),
		"include/validators.sh": []byte("startValidators() { echo stage-validators; }\n"),
		"include/observers.sh":  []byte("startObservers() { echo stage-observers; }\n"),
	} {
		if err := os.WriteFile(filepath.Join(directory, path), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("/bin/bash", "--noprofile", "--norc", filepath.Join(directory, "start.sh"))
	command.Env = []string{"PATH=/usr/bin:/bin"}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("operator sequence: %v: %s", err, output)
	}
	previous := -1
	for _, stage := range []string{"stage-build-ui", "stage-preflight", "stage-seed", "stage-observers", "stage-validators", "stage-start-ui"} {
		index := strings.Index(string(output), stage)
		if index <= previous {
			t.Fatalf("missing or reordered stage %s: %s", stage, output)
		}
		previous = index
	}
}

func TestQualLocalnetTermUIVisibilityRequiresObservedShardOne(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"Node name: native (Shard 1 - observer)", "Node name: native (Shard 1 - observer - N/A)", "Node name: native (Shard 0 - observer)", "Node name: native (Shard 1 - validator)", "Node name: native (Shard 10 - observer)"} {
		command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/tools.sh"
sleep() { :; }
tmuxCommand() { [[ "$*" == 'capture-pane -p -t sp2-termui:0.0' ]] || return 23; printf '%s\n' "$PANE"; }
nativeTermUIStatus
`)
		command.Env = []string{"PATH=/usr/bin:/bin", "MULTIVERSXTESTNETSCRIPTSDIR=" + filepath.Join(root, "scripts/testnet"), "NATIVE_CONFIG_PREFLIGHT=1", "PANE=" + body}
		output, err := command.CombinedOutput()
		expected := strings.Contains(body, "(Shard 1 - observer)") || strings.Contains(body, "(Shard 1 - observer - N/A)")
		if (err == nil) != expected {
			t.Fatalf("TermUI visibility: %v: %s", err, output)
		}
		if expected && string(output) != body+"\n" {
			t.Fatalf("missing actual pane: %s", output)
		}
	}
}
