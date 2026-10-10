package processProxy

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/stretchr/testify/require"
)

// These are upstream adoption diagnostics, not admitted DRWA processor modes.
// The loader, flags, notifier, proxy and both processors are real. Other
// constructor dependencies use the existing upstream mock helper; no VM output,
// protected operation, native account effect or canonical outcome is executed.
func qualDRWAProcessorEpochFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enableEpochs.toml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
	return path
}

func qualDRWAProcessorLoadedConfig(t *testing.T, path string) *config.EpochConfig {
	t.Helper()
	cfg, err := common.LoadEpochConfig(path)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	return cfg
}

func qualDRWAProcessorAssertSelection(t *testing.T, proxy *scProcessorProxy, v2 bool) {
	t.Helper()
	version, name := procV1, "*smartContract.scProcessor"
	if v2 {
		version, name = procV2, "*processorV2.scProcessor"
	}
	selected := proxy.getProcessor()
	require.NotNil(t, selected)
	require.Equal(t, name, fmt.Sprintf("%T", selected))
	require.Equal(t, configuredProcessor(version), proxy.configuredProcessor)
	require.Same(t, proxy.processorsCache[configuredProcessor(version)], selected)
}

func TestQualDRWAProcessorLoadedActivation(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		activation uint32
		epochs     []uint32
		v2         []bool
	}{
		{"boundary_and_diagnostic_revisit", "[EnableEpochs]\nSCProcessorV2EnableEpoch = 3\n", 3,
			[]uint32{0, 2, 3, 4, 3, 2, 3}, []bool{false, false, true, true, true, false, true}},
		{"zero", "[EnableEpochs]\nSCProcessorV2EnableEpoch = 0\n", 0,
			[]uint32{0, 1, 4294967295}, []bool{true, true, true}},
		{"max_uint32", "[EnableEpochs]\nSCProcessorV2EnableEpoch = 4294967295\n", 4294967295,
			[]uint32{0, 4294967294, 4294967295}, []bool{false, false, true}},
		{"omitted_is_native_zero_not_admission", "[EnableEpochs]\n", 0,
			[]uint32{0, 1}, []bool{true, true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := qualDRWAProcessorLoadedConfig(t, qualDRWAProcessorEpochFile(t, tc.body))
			require.Equal(t, tc.activation, cfg.EnableEpochs.SCProcessorV2EnableEpoch)
			notifier := forking.NewGenericEpochNotifier()
			t.Cleanup(notifier.UnRegisterAll)
			handler, err := enablers.NewEnableEpochsHandler(cfg.EnableEpochs, notifier)
			require.NoError(t, err)
			args := createMockSmartContractProcessorArguments()
			args.EnableEpochs, args.EnableEpochsHandler = cfg.EnableEpochs, handler
			proxy, err := NewSmartContractProcessorProxy(args, notifier)
			require.NoError(t, err)
			require.Len(t, proxy.processorsCache, 2)
			v1, v2 := proxy.processorsCache[procV1], proxy.processorsCache[procV2]
			require.Equal(t, "*smartContract.scProcessor", fmt.Sprintf("%T", v1))
			require.Equal(t, "*processorV2.scProcessor", fmt.Sprintf("%T", v2))
			for i, epoch := range tc.epochs {
				t.Run(fmt.Sprintf("step_%d_epoch_%d", i, epoch), func(t *testing.T) {
					notifier.CheckEpoch(&block.Header{Epoch: epoch})
					require.Equal(t, tc.v2[i], handler.IsFlagEnabledInEpoch(common.SCProcessorV2Flag, epoch))
					qualDRWAProcessorAssertSelection(t, proxy, tc.v2[i])
					notifier.CheckEpoch(&block.Header{Epoch: epoch})
					qualDRWAProcessorAssertSelection(t, proxy, tc.v2[i])
					require.Same(t, v1, proxy.processorsCache[procV1])
					require.Same(t, v2, proxy.processorsCache[procV2])
				})
			}
		})
	}
}

func TestQualDRWAProcessorCurrentEpochRegistration(t *testing.T) {
	for _, tc := range []struct {
		epoch uint32
		v2    bool
	}{{2, false}, {3, true}} {
		t.Run(fmt.Sprintf("epoch_%d", tc.epoch), func(t *testing.T) {
			cfg := qualDRWAProcessorLoadedConfig(t, qualDRWAProcessorEpochFile(t, "[EnableEpochs]\nSCProcessorV2EnableEpoch = 3\n"))
			notifier := forking.NewGenericEpochNotifier()
			t.Cleanup(notifier.UnRegisterAll)
			notifier.CheckEpoch(&block.Header{Epoch: tc.epoch})
			handler, err := enablers.NewEnableEpochsHandler(cfg.EnableEpochs, notifier)
			require.NoError(t, err)
			args := createMockSmartContractProcessorArguments()
			args.EnableEpochs, args.EnableEpochsHandler = cfg.EnableEpochs, handler
			proxy, err := NewSmartContractProcessorProxy(args, notifier)
			require.NoError(t, err)
			require.Len(t, proxy.processorsCache, 2)
			qualDRWAProcessorAssertSelection(t, proxy, tc.v2)
		})
	}
}

func TestQualDRWAProcessorProposedCandidate(t *testing.T) {
	// Immutable public qualification fixture, not a selected release default.
	path := filepath.Join(qualDRWACandidateFixtureDir(t), "enableEpochs.toml")
	cfg := qualDRWAProcessorLoadedConfig(t, path)
	require.Equal(t, uint32(1), cfg.EnableEpochs.SCProcessorV2EnableEpoch)
	notifier := forking.NewGenericEpochNotifier()
	t.Cleanup(notifier.UnRegisterAll)
	handler, err := enablers.NewEnableEpochsHandler(cfg.EnableEpochs, notifier)
	require.NoError(t, err)
	args := createMockSmartContractProcessorArguments()
	args.EnableEpochs, args.EnableEpochsHandler = cfg.EnableEpochs, handler
	proxy, err := NewSmartContractProcessorProxy(args, notifier)
	require.NoError(t, err)
	for _, tc := range []struct {
		epoch uint32
		v2    bool
	}{{0, false}, {1, true}, {2, true}, {3, true}} {
		t.Run(fmt.Sprintf("epoch_%d", tc.epoch), func(t *testing.T) {
			notifier.CheckEpoch(&block.Header{Epoch: tc.epoch})
			qualDRWAProcessorAssertSelection(t, proxy, tc.v2)
		})
	}
	t.Logf("PROPOSED candidate SCProcessorV2EnableEpoch=%d; no configuration admission or protected effect exercised", cfg.EnableEpochs.SCProcessorV2EnableEpoch)
}

func TestQualDRWAProcessorMalformedActivation(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"negative", "[EnableEpochs]\nSCProcessorV2EnableEpoch = -1\n"},
		{"overflow", "[EnableEpochs]\nSCProcessorV2EnableEpoch = 4294967296\n"},
		{"wrong_type", "[EnableEpochs]\nSCProcessorV2EnableEpoch = \"three\"\n"},
		{"broken_toml", "[EnableEpochs\nSCProcessorV2EnableEpoch = 3\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := common.LoadEpochConfig(qualDRWAProcessorEpochFile(t, tc.body))
			require.Error(t, err)
			require.Nil(t, cfg)
		})
	}
}

func TestQualDRWAProcessorConcurrentSelectionReads(t *testing.T) {
	cfg := qualDRWAProcessorLoadedConfig(t, qualDRWAProcessorEpochFile(t, "[EnableEpochs]\nSCProcessorV2EnableEpoch = 3\n"))
	notifier := forking.NewGenericEpochNotifier()
	t.Cleanup(notifier.UnRegisterAll)
	handler, err := enablers.NewEnableEpochsHandler(cfg.EnableEpochs, notifier)
	require.NoError(t, err)
	args := createMockSmartContractProcessorArguments()
	args.EnableEpochs, args.EnableEpochsHandler = cfg.EnableEpochs, handler
	proxy, err := NewSmartContractProcessorProxy(args, notifier)
	require.NoError(t, err)
	v1, v2 := proxy.processorsCache[procV1], proxy.processorsCache[procV2]
	errors := make(chan process.SmartContractProcessorFacade, 4)
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 1000; j++ {
				selected := proxy.getProcessor()
				if selected != v1 && selected != v2 {
					errors <- selected
					return
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		notifier.CheckEpoch(&block.Header{Epoch: 2})
		notifier.CheckEpoch(&block.Header{Epoch: 3})
	}
	readers.Wait()
	close(errors)
	for selected := range errors {
		t.Errorf("unexpected native processor identity %T", selected)
	}
	qualDRWAProcessorAssertSelection(t, proxy, true)
}
