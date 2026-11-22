package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/chainparametersnotifier"
	"github.com/multiversx/mx-chain-go/epochStart/notifier"
	"github.com/multiversx/mx-chain-go/sharding"
)

func TestQualLocalnetGeneratorUsesOwningConfigurations(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, strict  string
		missingEpoch  bool
		generatorExit string
	}{
		{name: "package", strict: "1"},
		{name: "package with spaces", strict: "1"},
		{name: "legacy", strict: "0"},
		{name: "missing epoch", strict: "1", missingEpoch: true},
		{name: "rejected configuration", strict: "1", generatorExit: "17"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), tc.name)
			if err := os.MkdirAll(filepath.Join(directory, "filegen"), 0700); err != nil {
				t.Fatal(err)
			}
			capture := filepath.Join(directory, "args")
			if err := os.WriteFile(filepath.Join(directory, "filegen", "filegen"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CAPTURE\"\nexit \"${GENERATOR_EXIT:-0}\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$CONFIG_FUNCTIONS"; generateConfig`)
			command.Env = []string{"PATH=/usr/bin:/bin", "CONFIG_FUNCTIONS=" + filepath.Join(root, "scripts/testnet/include/config.sh"),
				"CAPTURE=" + capture, "TESTNETDIR=" + directory, "CONFIGGENERATOROUTPUTDIR=output",
				"SHARDCOUNT=3", "SHARD_VALIDATORCOUNT=1", "SHARD_OBSERVERCOUNT=1", "SHARD_CONSENSUS_SIZE=1",
				"META_VALIDATORCOUNT=1", "META_OBSERVERCOUNT=1", "META_CONSENSUS_SIZE=1",
				"GENESIS_STAKE_TYPE=direct", "HYSTERESIS=0", "ROUND_DURATION_IN_MS=6000", "MULTI_KEY_NODES=0",
				"NATIVE_CONFIG_PREFLIGHT=" + tc.strict, "GENERATOR_EXIT=" + tc.generatorExit}
			if !tc.missingEpoch {
				command.Env = append(command.Env, "OUTPUT_ROLLBACK_EPOCH=2")
			}
			output, err := command.CombinedOutput()
			if tc.missingEpoch {
				if err == nil {
					t.Fatal("generation accepted an unbound expected epoch")
				}
				if _, err = os.Stat(capture); !os.IsNotExist(err) {
					t.Fatal("generator ran before required input admission", err)
				}
				return
			}
			if tc.generatorExit != "" {
				exit, isExit := err.(*exec.ExitError)
				if !isExit || exit.ExitCode() != 17 {
					t.Fatalf("generator rejection was not returned: %v: %s", err, output)
				}
				return
			}
			if err != nil {
				t.Fatalf("generator invocation: %v: %s", err, output)
			}
			raw, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			args := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
			if tc.strict == "0" {
				for _, arg := range args {
					if arg == "-node-config" || arg == "-epoch-config" || arg == "-output-rollback-epoch" {
						t.Fatalf("legacy invocation acquired a native binding: %q", args)
					}
				}
				return
			}
			for flag, value := range map[string]string{
				"-node-config":           filepath.Join(directory, "node/config/config_validator.toml"),
				"-epoch-config":          filepath.Join(directory, "node/config/enableEpochs.toml"),
				"-output-rollback-epoch": "2", "-num-of-shards": "3",
			} {
				found := false
				for i := 0; i+1 < len(args); i++ {
					if args[i] == flag && args[i+1] == value {
						found = true
					}
				}
				if !found {
					t.Fatalf("generator did not bind %s to %q: %q", flag, value, args)
				}
			}
		})
	}
}

func TestQualLocalnetConfigStopsOnRejectedGeneration(t *testing.T) {
	operator, err := os.ReadFile(filepath.Join("..", "..", "scripts", "testnet", "config.sh"))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err = os.Mkdir(filepath.Join(directory, "include"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{
		"config.sh":         operator,
		"variables.sh":      []byte("USE_PROXY=0\nUSE_TXGEN=0\nUSE_HARDFORK=0\nCOPY_BACK_CONFIGS=0\n"),
		"include/build.sh":  []byte("prepareFolders() { :; }\nbuildConfigGenerator() { :; }\n"),
		"include/config.sh": []byte("generateConfig() { return 17; }\ncopyConfig() { touch \"$MARKER\"; }\ncopySeednodeConfig() { :; }\nupdateSeednodeConfig() { :; }\ncopyNodeConfig() { :; }\nupdateNodeConfig() { :; }\n"),
	} {
		if err = os.WriteFile(filepath.Join(directory, path), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(directory, "copied-rejected-config")
	command := exec.Command("/bin/bash", "--noprofile", "--norc", filepath.Join(directory, "config.sh"))
	command.Env = []string{"PATH=/usr/bin:/bin", "MARKER=" + marker}
	output, err := command.CombinedOutput()
	exit, isExit := err.(*exec.ExitError)
	if !isExit || exit.ExitCode() != 17 {
		t.Fatalf("operator did not preserve generator refusal: %v: %s", err, output)
	}
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("operator copied rejected configuration", err)
	}
}

func TestQualLocalnetBuildsIntoPackage(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, function := range []string{"buildConfigGenerator", "buildNode", "buildSeednode", "buildProxy", "buildTxGen", "buildTermUI"} {
		for _, refused := range []bool{false, true} {
			t.Run(function+"/"+map[bool]string{false: "success", true: "refusal"}[refused], func(t *testing.T) {
				directory := filepath.Join(t.TempDir(), "package with spaces")
				source := filepath.Join(directory, "source")
				buildSource := source
				if function == "buildTermUI" {
					buildSource = filepath.Join(source, "cmd/termui")
				}
				bin := filepath.Join(directory, "bin")
				for _, path := range []string{buildSource, bin, filepath.Join(directory, "filegen"), filepath.Join(directory, "node"), filepath.Join(directory, "seednode"), filepath.Join(directory, "proxy"), filepath.Join(directory, "txgen")} {
					if err := os.MkdirAll(path, 0700); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(filepath.Join(bin, "go"), []byte("#!/bin/sh\nprintf '%s\\n' \"$PWD\" \"$@\" > \"$CAPTURE\"\nexit \"$GO_EXIT\"\n"), 0700); err != nil {
					t.Fatal(err)
				}
				capture := filepath.Join(directory, "args")
				command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$BUILD_FUNCTIONS"; "$BUILD_FUNCTION"`)
				code := "0"
				if refused {
					code = "17"
				}
				command.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "BUILD_FUNCTIONS=" + filepath.Join(root, "scripts/testnet/include/build.sh"), "BUILD_FUNCTION=" + function,
					"CAPTURE=" + capture, "GO_EXIT=" + code, "TESTNETDIR=" + directory, "CONFIGGENERATORDIR=" + source,
					"NODEDIR=" + source, "SEEDNODEDIR=" + source, "PROXYDIR=" + source, "TXGENDIR=" + source,
					"MULTIVERSXDIR=" + source, "ALWAYS_NEW_APP_VERSION=0"}
				output, err := command.CombinedOutput()
				if refused {
					exit, isExit := err.(*exec.ExitError)
					if !isExit || exit.ExitCode() != 17 {
						t.Fatalf("build refusal was not propagated: %v: %s", err, output)
					}
				} else if err != nil {
					t.Fatalf("build invocation: %v: %s", err, output)
				}
				raw, err := os.ReadFile(capture)
				if err != nil {
					t.Fatal(err)
				}
				args := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
				component := map[string]string{"buildConfigGenerator": "filegen", "buildNode": "node", "buildSeednode": "seednode", "buildProxy": "proxy", "buildTxGen": "txgen", "buildTermUI": "termui"}[function]
				wantOutput := filepath.Join(directory, component, component)
				if function == "buildTermUI" {
					wantOutput = filepath.Join(directory, "node/termui")
				}
				if len(args) < 4 || args[0] != buildSource || args[1] != "build" || args[2] != "-o" || args[3] != wantOutput || args[len(args)-1] != "." {
					t.Fatalf("build is not scoped to package output %q: %q", wantOutput, args)
				}
			})
		}
	}
}

func TestQualLocalnetConfigPreparesNativeInputsBeforeGeneration(t *testing.T) {
	operator, err := os.ReadFile(filepath.Join("..", "..", "scripts", "testnet", "config.sh"))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err = os.Mkdir(filepath.Join(directory, "include"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{
		"config.sh":        operator,
		"variables.sh":     []byte("USE_PROXY=0\nUSE_TXGEN=0\nUSE_HARDFORK=0\nCOPY_BACK_CONFIGS=0\nNATIVE_CONFIG_PREFLIGHT=1\n"),
		"include/build.sh": []byte("prepareFolders() { mkdir -p \"$TESTNETDIR/node/config\"; }\nbuildConfigGenerator() { :; }\n"),
		"include/config.sh": []byte(`
validateNativeLocalnetOptions() { :; }
copyNodeConfig() { echo copied >> "$TRACE"; }
updateChainParameters() { echo "$1" >> "$TRACE"; }
generateConfig() {
  expected=$(printf 'copied\nconfig_observer.toml\nconfig_validator.toml')
  [[ -f "$TRACE" && $(cat "$TRACE") == "$expected" ]] || return 17
  echo generated >> "$TRACE"
}

copyConfig() { echo distributed >> "$TRACE"; }
copySeednodeConfig() { :; }
updateSeednodeConfig() { :; }
updateNodeConfig() { echo updated >> "$TRACE"; }
`),
	} {
		if err = os.WriteFile(filepath.Join(directory, path), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	trace := filepath.Join(directory, "trace")
	command := exec.Command("/bin/bash", "--noprofile", "--norc", filepath.Join(directory, "config.sh"))
	command.Env = []string{"PATH=/usr/bin:/bin", "TRACE=" + trace, "TESTNETDIR=" + directory}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("generation did not receive prepared native configuration: %v: %s", err, output)
	}
	raw, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "copied\nconfig_observer.toml\nconfig_validator.toml\ngenerated\ndistributed\nupdated\n" {
		t.Fatalf("native configuration was replaced or reordered: %s", raw)
	}
}

func TestQualLocalnetConfigurationPaths(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "node source")
	packageDir := filepath.Join(directory, "localnet package")
	files := []string{"api.toml", "config.toml", "economics.toml", "ratings.toml", "prefs.toml", "external.toml", "p2p.toml", "fullArchiveP2P.toml", "enableEpochs.toml", "enableRounds.toml", "systemSmartContractsConfig.toml", "genesisSmartContracts.json", "genesisContracts/fixture.wasm", "gasSchedules/fixture.toml"}
	for _, name := range files {
		path := filepath.Join(source, "config", name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("experimental fixture: "+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	generated := filepath.Join(packageDir, "filegen", "output")
	if err := os.MkdirAll(generated, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"genesis.json", "nodesSetup.json", "fixture.pem"} {
		if err := os.WriteFile(filepath.Join(generated, name), []byte("experimental generated: "+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$BUILD_FUNCTIONS"; source "$CONFIG_FUNCTIONS"; prepareFolders && prepareFolders_Proxy && prepareFolders_TxGen && copyNodeConfig && copyConfig`)
	command.Env = []string{"PATH=/usr/bin:/bin", "BUILD_FUNCTIONS=" + filepath.Join(root, "scripts/testnet/include/build.sh"), "CONFIG_FUNCTIONS=" + filepath.Join(root, "scripts/testnet/include/config.sh"),
		"TESTNETDIR=" + packageDir, "NODEDIR=" + source, "CONFIGGENERATOROUTPUTDIR=output", "MULTI_KEY_NODES=0"}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("configuration copy: %v: %s", err, output)
	}
	for _, name := range []string{"seednode/config", "node_working_dirs", "proxy/config", "txgen/config/nodeConfig/config"} {
		info, err := os.Stat(filepath.Join(packageDir, name))
		if err != nil || !info.IsDir() {
			t.Fatalf("package directory %s: %v", name, err)
		}
	}
	for _, name := range files {
		if name == "config.toml" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(packageDir, "node", "config", name))
		if err != nil || string(raw) != "experimental fixture: "+name {
			t.Fatalf("copy %s: %v: %s", name, err, raw)
		}
	}
	for _, name := range []string{"config_validator.toml", "config_observer.toml"} {
		raw, err := os.ReadFile(filepath.Join(packageDir, "node", "config", name))
		if err != nil || string(raw) != "experimental fixture: config.toml" {
			t.Fatalf("role configuration %s: %v: %s", name, err, raw)
		}
	}
	for _, name := range []string{"genesis.json", "nodesSetup.json", "fixture.pem"} {
		raw, err := os.ReadFile(filepath.Join(packageDir, "node", "config", name))
		if err != nil || string(raw) != "experimental generated: "+name {
			t.Fatalf("generated configuration %s: %v: %s", name, err, raw)
		}
	}
	if err := os.Remove(filepath.Join(source, "config", "api.toml")); err != nil {
		t.Fatal(err)
	}
	refusal := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$CONFIG_FUNCTIONS"; copyNodeConfig`)
	refusal.Env = command.Env
	if output, err = refusal.CombinedOutput(); err == nil {
		t.Fatalf("missing native configuration was accepted: %s", output)
	}
	if err := os.Remove(filepath.Join(generated, "nodesSetup.json")); err != nil {
		t.Fatal(err)
	}
	refusal = exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$CONFIG_FUNCTIONS"; copyConfig`)
	refusal.Env = command.Env
	if output, err = refusal.CombinedOutput(); err == nil {
		t.Fatalf("missing generated topology was accepted: %s", output)
	}
}

func TestQualLocalnetChainParametersKeepValidatorCounts(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	// Experimental asymmetric geometry distinguishes validator counts from
	// consensus sizes; neither value is an admitted deployment profile.
	for _, tc := range []struct {
		filename, hysteresis string
		expected             float32
	}{
		{"config.toml", "0.0", 0}, {"config with spaces.toml", "0", 0}, {"fractional.toml", "0.125", 0.125},
	} {
		t.Run(tc.filename, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.filename)
			if err := os.WriteFile(path, []byte(`[GeneralSettings]
ChainParametersByEpoch = [
 { EnableEpoch = 0, RoundDuration = 6000, RoundsPerEpoch = 200, MinRoundsBetweenEpochs = 20, ShardConsensusGroupSize = 7, ShardMinNumNodes = 10, MetachainConsensusGroupSize = 10, MetachainMinNumNodes = 10, Hysteresis = 0.2, Adaptivity = false, Offset = 0 },
 { EnableEpoch = 1, RoundDuration = 6000, RoundsPerEpoch = 200, MinRoundsBetweenEpochs = 20, ShardConsensusGroupSize = 7, ShardMinNumNodes = 10, MetachainConsensusGroupSize = 10, MetachainMinNumNodes = 10, Hysteresis = 0.2, Adaptivity = false, Offset = 0 }
]
`), 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$CONFIG_FUNCTIONS"; updateChainParameters "$TARGET"`)
			command.Env = []string{"PATH=/usr/bin:/bin", "CONFIG_FUNCTIONS=" + filepath.Join(root, "scripts/testnet/include/config.sh"), "TARGET=" + path,
				"SHARD_CONSENSUS_SIZE=2", "SHARD_VALIDATORCOUNT=3", "META_CONSENSUS_SIZE=1", "META_VALIDATORCOUNT=2", "ROUND_DURATION_IN_MS=6000", "HYSTERESIS=" + tc.hysteresis, "ROUNDS_PER_EPOCH=0"}
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("chain parameter update: %v: %s", err, output)
			}
			cfg, err := common.LoadMainConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			holder, err := sharding.NewChainParametersHolder(sharding.ArgsChainParametersHolder{
				ChainParameters: cfg.GeneralSettings.ChainParametersByEpoch, EpochStartEventNotifier: notifier.NewEpochStartSubscriptionHandler(), ChainParametersNotifier: chainparametersnotifier.NewChainParametersNotifier(),
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, params := range holder.AllChainParameters() {
				if params.Hysteresis != tc.expected {
					t.Fatalf("native hysteresis changed: got %v want %v", params.Hysteresis, tc.expected)
				}
				if params.ShardMinNumNodes != 3 || params.ShardConsensusGroupSize != 2 || params.MetachainMinNumNodes != 2 || params.MetachainConsensusGroupSize != 1 {
					t.Fatalf("native parameters lost requested geometry: %+v", params)
				}
			}
		})
	}
}

func TestQualLocalnetSeedKeyIsPackageOwned(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "node source")
	packageDir := filepath.Join(directory, "localnet package")
	bin := filepath.Join(directory, "bin")
	for _, path := range []string{filepath.Join(source, "cmd/keygenerator"), filepath.Join(source, "cmd/seednode/config"), filepath.Join(packageDir, "seednode/config"), bin} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"config.toml", "p2p.toml"} {
		if err := os.WriteFile(filepath.Join(source, "cmd/seednode/config", name), []byte("experimental fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	keygen := filepath.Join(directory, "fixture-keygenerator")
	if err := os.WriteFile(keygen, []byte("#!/bin/sh\n[ \"$1\" = --key-type ] && [ \"$2\" = p2p ] || exit 91\nprintf '%s\\n' \"$PWD\" > \"$KEY_CAPTURE\"\nprintf '%s\\n' '-----BEGIN PRIVATE KEY for experimental-peer-----' > p2pKey.pem\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte("#!/bin/sh\nprintf '%s\\n' \"$PWD\" \"$@\" > \"$BUILD_CAPTURE\"\n[ \"$1\" = build ] && [ \"$2\" = -o ] || exit 92\ncp \"$FAKE_KEYGEN\" \"$3\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	buildCapture, keyCapture := filepath.Join(directory, "build-args"), filepath.Join(directory, "key-cwd")
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$CONFIG_FUNCTIONS"; copySeednodeConfig && printf '%s' "$P2P_SEEDNODE_ADDRESS"`)
	command.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "CONFIG_FUNCTIONS=" + filepath.Join(root, "scripts/testnet/include/config.sh"), "TESTNETDIR=" + packageDir,
		"MULTIVERSXDIR=" + source, "SEEDNODEDIR=" + filepath.Join(source, "cmd/seednode"), "SEEDNODE_IP=127.0.0.1", "PORT_SEEDNODE=9999", "FAKE_KEYGEN=" + keygen, "BUILD_CAPTURE=" + buildCapture, "KEY_CAPTURE=" + keyCapture}
	output, err := command.CombinedOutput()
	if err != nil || !strings.HasSuffix(string(output), "/ip4/127.0.0.1/tcp/9999/p2p/experimental-peer") {
		t.Fatalf("seed binding: %v: %s", err, output)
	}
	raw, err := os.ReadFile(keyCapture)
	if err != nil || strings.TrimSpace(string(raw)) != filepath.Join(packageDir, "seednode/config") {
		t.Fatalf("key generation escaped package: %v: %s", err, raw)
	}
	if _, err = os.Stat(filepath.Join(source, "cmd/keygenerator/p2pKey.pem")); !os.IsNotExist(err) {
		t.Fatal("seed key written to source", err)
	}
	info, err := os.Stat(filepath.Join(packageDir, "seednode/config/p2pKey.pem"))
	if err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatalf("seed key permissions: %v: %v", info, err)
	}
	if err := os.Remove(buildCapture); err != nil {
		t.Fatal(err)
	}
	reuse := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$CONFIG_FUNCTIONS"; copySeednodeConfig`)
	reuse.Env = command.Env
	if output, err = reuse.CombinedOutput(); err != nil {
		t.Fatalf("existing package key: %v: %s", err, output)
	}
	if _, err = os.Stat(buildCapture); !os.IsNotExist(err) {
		t.Fatal("existing package key triggered another build", err)
	}
}

func TestQualLocalnetSourcePathsWithSpaces(t *testing.T) {
	variables, err := os.ReadFile(filepath.Join("..", "..", "scripts", "testnet", "variables.sh"))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "node source")
	scripts := filepath.Join(source, "scripts", "testnet")
	if err := os.MkdirAll(scripts, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(scripts, "variables.sh")
	if err := os.WriteFile(path, variables, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$MULTIVERSXTESTNETSCRIPTSDIR/variables.sh"; printf '%s\n' "$MULTIVERSXDIR" "$CONFIGGENERATORDIR" "$NODEDIR" "$PROXYDIR" "$TXGENDIR"`)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + directory, "MULTIVERSXTESTNETSCRIPTSDIR=" + scripts}
	output, err := command.CombinedOutput()
	want := source + "\n" + filepath.Join(directory, "mx-chain-deploy-go", "cmd", "filegen") + "\n" + filepath.Join(source, "cmd", "node") + "\n" + filepath.Join(directory, "mx-chain-proxy-go", "cmd", "proxy") + "\n" + filepath.Join(directory, "mx-chain-txgen-go", "cmd", "txgen") + "\n"
	if err != nil || string(output) != want {
		t.Fatalf("source path resolution: %v: got %q want %q", err, output, want)
	}
}

func TestQualLocalnetSeedTransportIsLoopback(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	configDir := filepath.Join(directory, "seednode/config")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configDir, "p2p.toml")
	if err := os.WriteFile(path, []byte(`[Node]
Port = "10000"
[Node.Transports]
QUICAddress = "/ip4/0.0.0.0/udp/%d/quic-v1"
WebSocketAddress = "/ip4/0.0.0.0/tcp/%d/ws"
WebTransportAddress = "/ip4/0.0.0.0/udp/%d/quic-v1/webtransport"
[Node.Transports.TCP]
ListenAddress = "/ip4/0.0.0.0/tcp/%d"
[KadDhtPeerDiscovery]
InitialPeerList = []
`), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$CONFIG_FUNCTIONS"; updateSeednodeConfig`)
	command.Env = []string{"PATH=/usr/bin:/bin", "CONFIG_FUNCTIONS=" + filepath.Join(root, "scripts/testnet/include/config.sh"), "TESTNETDIR=" + directory, "PORT_SEEDNODE=9999", "NATIVE_CONFIG_PREFLIGHT=1", "SEEDNODE_IP=127.0.0.1"}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("seed update: %v: %s", err, output)
	}
	p2p, err := common.LoadP2PConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if p2p.Node.Port != "9999" || p2p.Node.Transports.TCP.ListenAddress != "/ip4/127.0.0.1/tcp/%d" || p2p.Node.Transports.QUICAddress != "" || p2p.Node.Transports.WebSocketAddress != "" || p2p.Node.Transports.WebTransportAddress != "" || len(p2p.KadDhtPeerDiscovery.InitialPeerList) != 0 {
		t.Fatalf("seed config is not loopback-only: %+v", p2p)
	}
	denial := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$CONFIG_FUNCTIONS"; updateSeednodeConfig`)
	denial.Env = append(command.Env, "SEEDNODE_IP=192.0.2.1")
	if output, err = denial.CombinedOutput(); err == nil {
		t.Fatalf("non-loopback seed accepted: %s", output)
	}
}

func TestQualLocalnetNodeTransportIsLoopback(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	configDir := filepath.Join(directory, "node/config")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"p2p.toml":              "[Node.Transports]\nQUICAddress = \"\"\nWebSocketAddress = \"\"\nWebTransportAddress = \"\"\n[Node.Transports.TCP]\nListenAddress = \"/ip4/0.0.0.0/tcp/%d\"\n[KadDhtPeerDiscovery]\nInitialPeerList = []\n",
		"nodesSetup.json":       "{\n\"startTime\": 0,\n\"minTransactionVersion\": 1,\n\"initialNodes\": []\n}\n",
		"enableEpochs.toml":     "[EnableEpochs]\nStakingV4Step3EnableEpoch = 10\nMaxNodesChangeEnableEpoch = []\n",
		"config_validator.toml": "[GeneralSettings]\nChainID = \"undefined\"\n[NTPConfig]\nHosts = [\"time.google.com\"]\n[SoftwareVersionConfig]\nStableTagLocation = \"https://example.invalid/releases\"\n[GatewayMetricsConfig]\nURL = \"https://example.invalid/metrics\"\n",
		"config_observer.toml":  "[GeneralSettings]\nChainID = \"undefined\"\n[NTPConfig]\nHosts = [\"time.google.com\"]\n[SoftwareVersionConfig]\nStableTagLocation = \"https://example.invalid/releases\"\n[GatewayMetricsConfig]\nURL = \"https://example.invalid/metrics\"\n",
	} {
		if err := os.WriteFile(filepath.Join(configDir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	peer := "/ip4/127.0.0.1/tcp/9999/p2p/experimental-peer"
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$CONFIG_FUNCTIONS"; updateNodeConfig`)
	command.Env = []string{"PATH=/usr/bin:/bin", "CONFIG_FUNCTIONS=" + filepath.Join(root, "scripts/testnet/include/config.sh"), "TESTNETDIR=" + directory,
		"NATIVE_CONFIG_PREFLIGHT=1", "P2P_SEEDNODE_ADDRESS=" + peer, "SEEDNODE_IP=127.0.0.1", "GENESIS_DELAY=60", "ALWAYS_NEW_CHAINID=1", "OBSERVERS_ANTIFLOOD_DISABLE=0", "ROUNDS_PER_EPOCH=0",
		"SHARD_CONSENSUS_SIZE=1", "SHARD_VALIDATORCOUNT=1", "META_CONSENSUS_SIZE=1", "META_VALIDATORCOUNT=1", "ROUND_DURATION_IN_MS=6000", "HYSTERESIS=0.0"}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("node update: %v: %s", err, output)
	}
	p2p, err := common.LoadP2PConfig(filepath.Join(configDir, "p2p.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if p2p.Node.Transports.TCP.ListenAddress != "/ip4/127.0.0.1/tcp/%d" || len(p2p.KadDhtPeerDiscovery.InitialPeerList) != 1 || p2p.KadDhtPeerDiscovery.InitialPeerList[0] != peer {
		t.Fatalf("node config is not loopback-only: %+v", p2p)
	}
	for _, name := range []string{"config_validator.toml", "config_observer.toml"} {
		cfg, err := common.LoadMainConfig(filepath.Join(configDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.SoftwareVersionConfig.StableTagLocation != "" || cfg.GatewayMetricsConfig.URL != "" {
			t.Fatalf("nonlocal polling targets retained in %s", name)
		}
		if len(cfg.NTPConfig.Hosts) != 0 {
			t.Fatalf("public NTP hosts retained in %s: %q", name, cfg.NTPConfig.Hosts)
		}
	}
	denial := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `source "$CONFIG_FUNCTIONS"; updateNodeConfig`)
	denial.Env = append(command.Env, "P2P_SEEDNODE_ADDRESS=/ip4/192.0.2.1/tcp/9999/p2p/experimental-peer")
	if output, err = denial.CombinedOutput(); err == nil {
		t.Fatalf("non-loopback peer accepted: %s", output)
	}
}

func TestQualLocalnetProxyOperatorBindsLoopback(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, strict := range []string{"0", "1"} {
		t.Run(strict, func(t *testing.T) {
			command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", `
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/tools.sh"
setTerminalSession() { :; }
setTerminalLayout() { :; }
setWorkdirForNextCommands() { printf '%s\n' "$1"; }
runCommandInTerminal() { printf '%s\n' "$1"; }
startProxy
`)
			command.Env = []string{"PATH=/usr/bin:/bin", "MULTIVERSXTESTNETSCRIPTSDIR=" + filepath.Join(root, "scripts/testnet"), "TESTNETDIR=/tmp/experimental localnet package", "PORT_PROXY=7950", "NATIVE_CONFIG_PREFLIGHT=" + strict}
			output, err := command.CombinedOutput()
			want := "/tmp/experimental localnet package/proxy\n./proxy"
			if strict == "1" {
				want += " --rest-api-interface 127.0.0.1:7950"
			}
			want += "\n"
			if err != nil || string(output) != want {
				t.Fatalf("operator proxy binding: %v: got %q want %q", err, output, want)
			}
		})
	}
}
