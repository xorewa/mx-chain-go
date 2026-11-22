package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestQualLocalnetNodeHealthUsesNativeStatus(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body string
		status     int
		accepted   bool
	}{
		{"progress", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":7,"erd_is_syncing":0}}}`, 200, true},
		{"exact nonce above float precision", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":9007199254740993,"erd_is_syncing":0}}}`, 200, true},
		{"maximum native nonce", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":18446744073709551615,"erd_is_syncing":0}}}`, 200, true},
		{"nonce exceeds native width", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":18446744073709551616,"erd_is_syncing":0}}}`, 200, false},
		{"fraction rounded by float", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":9007199254740992.5,"erd_is_syncing":0}}}`, 200, false},
		{"nonce exponent overflows float", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":1e1000,"erd_is_syncing":0}}}`, 200, false},
		{"integral exponential nonce", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":7e0,"erd_is_syncing":0}}}`, 200, true},
		{"integral decimal nonce", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":7.00,"erd_is_syncing":0}}}`, 200, true},
		{"fraction shifted to integer", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":1.2e2,"erd_is_syncing":0}}}`, 200, true},
		{"trailing zero shifted to integer", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":1.20e1,"erd_is_syncing":0}}}`, 200, true},
		{"negative exponent produces fraction", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":12e-1,"erd_is_syncing":0}}}`, 200, false},
		{"synchronizing with progress", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":7,"erd_is_syncing":1}}}`, 200, false},
		{"missing synchronization state", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":7}}}`, 200, false},
		{"string synchronization state", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":7,"erd_is_syncing":"0"}}}`, 200, false},
		{"wrong shard", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":2,"erd_nonce":7,"erd_is_syncing":0}}}`, 200, false},
		{"no progress", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":0,"erd_is_syncing":0}}}`, 200, false},
		{"string nonce", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":"7","erd_is_syncing":0}}}`, 200, false},
		{"missing metrics", `{"code":"successful","error":"","data":{}}`, 200, false},
		{"API error", `{"code":"internal_issue","error":"unavailable","data":{"metrics":{"erd_shard_id":1,"erd_nonce":7,"erd_is_syncing":0}}}`, 200, false},
		{"HTTP error", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":7,"erd_is_syncing":0}}}`, 503, false},
		{"redirect", `{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":1,"erd_nonce":7,"erd_is_syncing":0}}}`, 302, false},
		{"malformed", `{`, 200, false},
		{"oversize", strings.Repeat(" ", 1048577) + `{}`, 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "GET" || r.URL.Path != "/node/status" {
					t.Errorf("unexpected health request: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			_, port, err := net.SplitHostPort(server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", "source \"$MULTIVERSXTESTNETSCRIPTSDIR/include/tools.sh\"; nativeNodeStatus \"$PORT\" 1")
			command.Env = []string{"PATH=/usr/bin:/bin", "MULTIVERSXTESTNETSCRIPTSDIR=" + filepath.Join(root, "scripts/testnet"), "PORT=" + port}
			output, err := command.CombinedOutput()
			if (err == nil) != tc.accepted {
				t.Fatalf("native status %s: %v: %s", tc.name, err, output)
			}
			if calls.Load() != 1 {
				t.Fatalf("health did not reach its single native status consumer: %d: %s", calls.Load(), output)
			}
		})
	}
}

func TestQualLocalnetHealthChecksEveryShardAndProxy(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, validatorShards, observerShards, proxyShards string
		accepted                                           bool
	}{
		{"native assignment differs from launch order", "4294967295 0 1 2", "0 1 2 4294967295", "3", true},
		{"missing validator shard", "4294967295 0 0 2", "0 1 2 4294967295", "3", false},
		{"wrong observer destination", "4294967295 0 1 2", "0 2 1 4294967295", "3", false},
		{"wrong proxy topology", "4294967295 0 1 2", "0 1 2 4294967295", "2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/tools.sh"
nativeNodeStatus() {
  local -a shards
  if (( $1 >= 12000 )); then read -ra shards <<< "$OBSERVER_SHARDS"; index=$(($1-12000)); else read -ra shards <<< "$VALIDATOR_SHARDS"; index=$(($1-11000)); fi
  [[ -z "$2" || "$2" == "${shards[$index]}" ]] || return 1
  printf '{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":%s,"erd_nonce":7}}}\n' "${shards[$index]}"
}
nativeProxyConfig() { [[ "$1" == 13000 && "$PROXY_SHARDS" == 3 ]]; }
nativeLocalnetHealth
`)
			command.Env = []string{"PATH=/usr/bin:/bin", "MULTIVERSXTESTNETSCRIPTSDIR=" + filepath.Join(root, "scripts/testnet"), "NATIVE_CONFIG_PREFLIGHT=1", "SHARDCOUNT=3", "SHARD_VALIDATORCOUNT=1", "META_VALIDATORCOUNT=1", "SHARD_OBSERVERCOUNT=1", "META_OBSERVERCOUNT=1", "PORT_ORIGIN_VALIDATOR_REST=11000", "PORT_ORIGIN_OBSERVER_REST=12000", "PORT_PROXY=13000", "USE_PROXY=1", "VALIDATOR_SHARDS=" + tc.validatorShards, "OBSERVER_SHARDS=" + tc.observerShards, "PROXY_SHARDS=" + tc.proxyShards}
			output, err := command.CombinedOutput()
			if (err == nil) != tc.accepted {
				t.Fatalf("topology health: %v: %s", err, output)
			}
			if tc.accepted {
				for _, role := range []string{"validator", "observer"} {
					for i := 0; i < 4; i++ {
						port := 11000 + i
						if role == "observer" {
							port = 12000 + i
						}
						if !strings.Contains(string(output), fmt.Sprintf("%s %d ", role, port)) {
							t.Fatalf("missing actual %s %d status: %s", role, port, output)
						}
					}
				}
			}
		})
	}
}

func TestQualLocalnetNodeHealthRejectsInvalidTargetBeforeCurl(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ port, shard string }{{"0", "1"}, {"65536", "1"}, {"-1", "1"}, {"1;false", "1"}, {"12345", "999"}} {
		t.Run(tc.port+"_"+tc.shard, func(t *testing.T) {
			directory := t.TempDir()
			marker := filepath.Join(directory, "called")
			if err := os.WriteFile(filepath.Join(directory, "curl"), []byte("#!/bin/sh\ntouch \"$MARKER\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", "source \"$MULTIVERSXTESTNETSCRIPTSDIR/include/tools.sh\"; nativeNodeStatus \"$PORT\" \"$SHARD\"")
			command.Env = []string{"PATH=" + directory + ":/usr/bin:/bin", "MULTIVERSXTESTNETSCRIPTSDIR=" + filepath.Join(root, "scripts/testnet"), "PORT=" + tc.port, "SHARD=" + tc.shard, "MARKER=" + marker}
			if output, err := command.CombinedOutput(); err == nil {
				t.Fatalf("invalid health target accepted: %s", output)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("invalid target reached curl", err)
			}
		})
	}
}

func TestQualLocalnetHealthRefusesUnsynchronizedMember(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []string{"0", "11000", "12003"} {
		t.Run(port, func(t *testing.T) {
			command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/tools.sh"
nativeHTTPResponse() {
  if [[ "$2" == /network/config ]]; then
    printf '{"code":"successful","error":"","data":{"config":{"erd_num_shards_without_meta":3}}}\n'
    return
  fi
  [[ "$2" == /node/status ]] || return 23
  local shard syncing=0
  case "$1" in
    11000|12003) shard=4294967295 ;;
    11001|12000) shard=0 ;;
    11002|12001) shard=1 ;;
    11003|12002) shard=2 ;;
    *) return 24 ;;
  esac
  [[ "$1" != "$SYNCING_PORT" ]] || syncing=1
  printf '{"code":"successful","error":"","data":{"metrics":{"erd_shard_id":%s,"erd_nonce":7,"erd_is_syncing":%s}}}\n' "$shard" "$syncing"
}
nativeLocalnetHealth
`)
			command.Env = []string{"PATH=/usr/bin:/bin", "MULTIVERSXTESTNETSCRIPTSDIR=" + filepath.Join(root, "scripts/testnet"), "NATIVE_CONFIG_PREFLIGHT=1", "SHARDCOUNT=3", "SHARD_VALIDATORCOUNT=1", "META_VALIDATORCOUNT=1", "SHARD_OBSERVERCOUNT=1", "META_OBSERVERCOUNT=1", "PORT_ORIGIN_VALIDATOR_REST=11000", "PORT_ORIGIN_OBSERVER_REST=12000", "PORT_PROXY=13000", "USE_PROXY=1", "SYNCING_PORT=" + port}
			output, err := command.CombinedOutput()
			if port == "0" {
				if err != nil || strings.Count(string(output), `"erd_is_syncing":0`) != 8 || !strings.Contains(string(output), "proxy 13000 ") {
					t.Fatalf("synchronized positive control: %v: %s", err, output)
				}
			} else if err == nil || len(output) != 0 {
				t.Fatalf("synchronizing member %s accepted: %v: %s", port, err, output)
			}
		})
	}
}

func TestQualLocalnetProxyHealthUsesNativeConfig(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body string
		accepted   bool
	}{
		{"three execution shards", `{"code":"successful","error":"","data":{"config":{"erd_num_shards_without_meta":3}}}`, true},
		{"wrong topology", `{"code":"successful","error":"","data":{"config":{"erd_num_shards_without_meta":2}}}`, false},
		{"error", `{"code":"internal_issue","error":"failed","data":{"config":{"erd_num_shards_without_meta":3}}}`, false},
		{"missing config", `{"code":"successful","error":"","data":{}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "GET" || r.URL.Path != "/network/config" {
					t.Errorf("unexpected proxy request: %s %s", r.Method, r.URL.Path)
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			_, port, err := net.SplitHostPort(server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$MULTIVERSXTESTNETSCRIPTSDIR/include/tools.sh"; nativeProxyConfig "$PORT"`)
			command.Env = []string{"PATH=/usr/bin:/bin", "MULTIVERSXTESTNETSCRIPTSDIR=" + filepath.Join(root, "scripts/testnet"), "PORT=" + port}
			output, err := command.CombinedOutput()
			if (err == nil) != tc.accepted || calls.Load() != 1 {
				t.Fatalf("proxy health: %v, calls %d: %s", err, calls.Load(), output)
			}
		})
	}
}

func TestQualLocalnetHealthOperatorBoundsPolling(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/testnet/health.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, seconds, body string
		want                int
	}{
		{"positive", "1", "printf actual-health", 0},
		{"blocked check", "1", "sleep 60", 124},
		{"missing bound", "", "touch \"$MARKER\"", 1},
		{"excess bound", "121", "touch \"$MARKER\"", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Mkdir(filepath.Join(directory, "include"), 0700); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{
				"health.sh":        string(raw),
				"variables.sh":     "export NATIVE_CONFIG_PREFLIGHT=1\nexport LOCALNET_HEALTH_SECONDS=" + tc.seconds + "\n",
				"include/tools.sh": "nativeLocalnetHealth() { " + tc.body + "; }\nnativeLocalnetDiagnostics() { echo unaccepted-status; }\n",
			} {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			marker := filepath.Join(directory, "called")
			command := exec.Command("/usr/bin/timeout", "--kill-after=1s", "5s", "/bin/bash", "--noprofile", "--norc", filepath.Join(directory, "health.sh"))
			command.Env = []string{"PATH=/usr/bin:/bin", "MARKER=" + marker}
			start := time.Now()
			output, err := command.CombinedOutput()
			code := 0
			if err != nil {
				exit, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			if code != tc.want || time.Since(start) > 3*time.Second {
				t.Fatalf("health bound: exit %d elapsed %s: %s", code, time.Since(start), output)
			}
			if tc.want == 0 && string(output) != "actual-health" {
				t.Fatalf("missing positive control: %s", output)
			}
			if tc.want == 124 && !strings.Contains(string(output), "unaccepted-status") {
				t.Fatalf("health deadline discarded diagnostic status: %s", output)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("invalid bound reached checker", err)
			}
		})
	}
}

func TestQualLocalnetHealthDiagnosticsKeepZeroNonceUnaccepted(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/tools.sh"
nativeHTTPResponse() { if [[ "$2" == '/debug/pprof/goroutine?debug=2' ]]; then printf 'goroutine witness\n'; return; fi; [[ "$2" == /node/status ]] || return 23; printf '{"port":%d,"data":{"metrics":{"erd_nonce":0}}}\n' "$1"; }
nativeLocalnetDiagnostics
`)
	command.Env = []string{"PATH=/usr/bin:/bin", "MULTIVERSXTESTNETSCRIPTSDIR=" + filepath.Join(root, "scripts/testnet"), "NATIVE_CONFIG_PREFLIGHT=1", "SHARDCOUNT=3", "SHARD_VALIDATORCOUNT=1", "META_VALIDATORCOUNT=2", "SHARD_OBSERVERCOUNT=1", "META_OBSERVERCOUNT=1", "PORT_ORIGIN_VALIDATOR_REST=11000", "PORT_ORIGIN_OBSERVER_REST=12000"}
	output, err := command.CombinedOutput()
	if err != nil || strings.Count(string(output), "Unaccepted native status: validator") != 5 || strings.Count(string(output), "Unaccepted native status: observer") != 4 || strings.Count(string(output), `"erd_nonce":0`) != 9 {
		t.Fatalf("missing raw zero-nonce diagnostic: %v: %s", err, output)
	}
	if strings.Count(string(output), "goroutine witness") != 9 {
		t.Fatalf("missing zero-nonce goroutine consumer: %s", output)
	}
}
