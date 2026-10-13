package processProxy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/config"
	coreFactory "github.com/multiversx/mx-chain-go/factory/core"
	"github.com/stretchr/testify/require"
)

// N02/M5: experimental candidate03 support is V2 at DRWA epoch>=3, native
// relay-v3 and its four selected prerequisites active before enforcement.
// Native V1 before epoch1 remains ordinary behavior, not a dropped route.
// Runtime upgrade/relay/finality qualification is not inferred from this matrix.
func qualDRWADevelopmentScheduleConfig(t *testing.T) *config.Configs {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "testscommon", "testdata", "drwa", "t09", "candidate03"))
	require.NoError(t, err)
	body, err := os.ReadFile(filepath.Join(dir, "CANDIDATE.json"))
	require.NoError(t, err)
	require.Equal(t, "e3921e16c3f442caed9678513e8f32b66012c9b80f02f28490eab7cebe4c178c", fmt.Sprintf("%x", sha256.Sum256(body)))
	var inventory struct {
		Files []struct{ Path, SHA256 string }
	}
	require.NoError(t, json.Unmarshal(body, &inventory))
	for _, name := range []string{"config.toml", "enableEpochs.toml", "enableRounds.toml", "economics.toml", "ratings.toml"} {
		bound := false
		for _, item := range inventory.Files {
			if item.Path != name {
				continue
			}
			raw, readErr := os.ReadFile(filepath.Join(dir, name))
			require.NoError(t, readErr)
			require.Equal(t, item.SHA256, fmt.Sprintf("%x", sha256.Sum256(raw)))
			bound = true
		}
		require.True(t, bound, name)
	}
	main, err := common.LoadMainConfig(filepath.Join(dir, "config.toml"))
	require.NoError(t, err)
	epochs, err := common.LoadEpochConfig(filepath.Join(dir, "enableEpochs.toml"))
	require.NoError(t, err)
	rounds, err := common.LoadRoundConfig(filepath.Join(dir, "enableRounds.toml"))
	require.NoError(t, err)
	economics, err := common.LoadEconomicsConfig(filepath.Join(dir, "economics.toml"))
	require.NoError(t, err)
	ratings, err := common.LoadRatingsConfig(filepath.Join(dir, "ratings.toml"))
	require.NoError(t, err)
	return &config.Configs{GeneralConfig: main, EpochConfig: epochs, RoundConfig: rounds, EconomicsConfig: economics, RatingsConfig: ratings}
}

func TestQualDRWADevelopmentSupportedSchedule(t *testing.T) {
	cfg := qualDRWADevelopmentScheduleConfig(t)
	candidate, err := coreFactory.NewDRWAConfigurationCandidate(cfg, 3, coreFactory.DRWAConfigurationSupport{RelayedV3: true})
	require.NoError(t, err)
	notifier := forking.NewGenericEpochNotifier()
	t.Cleanup(notifier.UnRegisterAll)
	epochs, err := enablers.NewEnableEpochsHandler(cfg.EpochConfig.EnableEpochs, notifier)
	require.NoError(t, err)
	args := createMockSmartContractProcessorArguments()
	args.EnableEpochs, args.EnableEpochsHandler = cfg.EpochConfig.EnableEpochs, epochs
	proxy, err := NewSmartContractProcessorProxy(args, notifier)
	require.NoError(t, err)
	for _, row := range []struct {
		epoch           uint32
		v2, relay, drwa bool
	}{
		{0, false, false, false}, {1, true, true, false}, {2, true, true, false}, {3, true, true, true}, {4, true, true, true}, {4294967295, true, true, true},
	} {
		t.Run(fmt.Sprintf("epoch_%d", row.epoch), func(t *testing.T) {
			notifier.CheckEpoch(&block.Header{Epoch: row.epoch, Round: 440})
			qualDRWAProcessorAssertSelection(t, proxy, row.v2)
			require.Equal(t, row.relay, epochs.IsFlagEnabledInEpoch(common.RelayedTransactionsV3Flag, row.epoch))
			require.Equal(t, row.relay, epochs.IsFlagEnabledInEpoch(common.RelayedTransactionsV3FixESDTTransferFlag, row.epoch))
			require.Equal(t, row.relay, epochs.IsFlagEnabledInEpoch(common.FixRelayedBaseCostFlag, row.epoch))
			require.Equal(t, row.relay, epochs.IsFlagEnabledInEpoch(common.FixRelayedMoveBalanceToNonPayableSCFlag, row.epoch))
			require.Equal(t, row.drwa, candidate.Enabled(row.epoch, 440))
			require.False(t, candidate.Enabled(row.epoch, 439))
			if row.drwa {
				require.NoError(t, candidate.CheckEnforcedBlock(row.epoch, 440))
			} else {
				require.Error(t, candidate.CheckEnforcedBlock(row.epoch, 440))
			}
		})
	}
	require.Len(t, proxy.processorsCache, 2, "DRWA support selection does not delete either upstream processor")
}

func TestQualDRWADevelopmentUnsupportedPrerequisiteSchedule(t *testing.T) {
	for _, field := range []string{"processor", "relay_v3", "relay_esdt_fix", "relay_base_fee_fix", "relay_nonpayable_fix"} {
		t.Run(field, func(t *testing.T) {
			cfg := qualDRWADevelopmentScheduleConfig(t)
			var want string
			switch field {
			case "processor":
				cfg.EpochConfig.EnableEpochs.SCProcessorV2EnableEpoch = 4
				want = string(common.SCProcessorV2Flag)
			case "relay_v3":
				cfg.EpochConfig.EnableEpochs.RelayedTransactionsV3EnableEpoch = 4
				want = string(common.RelayedTransactionsV3Flag)
			case "relay_esdt_fix":
				cfg.EpochConfig.EnableEpochs.RelayedTransactionsV3FixESDTTransferEnableEpoch = 4
				want = string(common.RelayedTransactionsV3FixESDTTransferFlag)
			case "relay_base_fee_fix":
				cfg.EpochConfig.EnableEpochs.FixRelayedBaseCostEnableEpoch = 4
				want = string(common.FixRelayedBaseCostFlag)
			case "relay_nonpayable_fix":
				cfg.EpochConfig.EnableEpochs.FixRelayedMoveBalanceToNonPayableSCEnableEpoch = 4
				want = string(common.FixRelayedMoveBalanceToNonPayableSCFlag)
			}
			candidate, err := coreFactory.NewDRWAConfigurationCandidate(cfg, 3, coreFactory.DRWAConfigurationSupport{RelayedV3: true})
			require.ErrorContains(t, err, want)
			require.Nil(t, candidate)
		})
	}
}
