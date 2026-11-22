package enablers_test

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	"github.com/stretchr/testify/require"
)

// These SP1 observations exercise Part A v4.2.8 section 2.3 E05 against
// real upstream TOML loaders and flag handlers. They do not implement a DRWA
// admission validator or select deployment settings. Thresholds are synthetic
// boundary fixtures; route completeness and effective node configuration remain open.
func TestQualDRWAEpochPrerequisiteLoaderBoundaries(t *testing.T) {
	cases := []struct {
		field            string
		flag             core.EnableEpochFlag
		activeAtBoundary bool
	}{
		{"SupernovaEnableEpoch", common.SupernovaFlag, true},
		{"DynamicESDTEnableEpoch", common.DynamicESDTFlag, true},
		{"ESDTEnableEpoch", common.ESDTFlag, true},
		{"MetaESDTSetEnableEpoch", common.MetaESDTSetFlag, true},
		{"GlobalMintBurnDisableEpoch", common.GlobalMintBurnFlag, false},
		{"NFTStopCreateEnableEpoch", common.NFTStopCreateFlag, true},
		{"SetGuardianEnableEpoch", common.SetGuardianFlag, true},
		{"EGLDInMultiTransferEnableEpoch", common.EGLDInESDTMultiTransferFlag, true},
		{"ESDTMetadataContinuousCleanupEnableEpoch", common.ESDTMetadataContinuousCleanupFlag, true},
		{"SCProcessorV2EnableEpoch", common.SCProcessorV2Flag, true},
		{"RelayedTransactionsV3EnableEpoch", common.RelayedTransactionsV3Flag, true},
		{"RelayedTransactionsV3FixESDTTransferEnableEpoch", common.RelayedTransactionsV3FixESDTTransferFlag, true},
		{"FixRelayedBaseCostEnableEpoch", common.FixRelayedBaseCostFlag, true},
		{"FixRelayedMoveBalanceToNonPayableSCEnableEpoch", common.FixRelayedMoveBalanceToNonPayableSCFlag, true},
	}
	for _, c := range cases {
		t.Run(c.field, func(t *testing.T) {
			for _, boundary := range []uint32{0, 10, math.MaxUint32} {
				t.Run(fmt.Sprint(boundary), func(t *testing.T) {
					p := filepath.Join(t.TempDir(), "epochs.toml")
					require.NoError(t, os.WriteFile(p, []byte(fmt.Sprintf("[EnableEpochs]\n%s = %d\n", c.field, boundary)), 0600))
					cfg, err := common.LoadEpochConfig(p)
					require.NoError(t, err)
					handler, err := enablers.NewEnableEpochsHandler(cfg.EnableEpochs, &epochNotifier.EpochNotifierStub{})
					require.NoError(t, err)
					require.True(t, handler.IsFlagDefined(c.flag))
					require.Equal(t, boundary, handler.GetActivationEpoch(c.flag), "TOML field must bind to this flag")
					require.Equal(t, c.activeAtBoundary, handler.IsFlagEnabledInEpoch(c.flag, boundary), "inclusive boundary / negative disable polarity")
					if boundary > 0 {
						require.Equal(t, !c.activeAtBoundary, handler.IsFlagEnabledInEpoch(c.flag, boundary-1))
					}
					if boundary < math.MaxUint32 {
						require.Equal(t, c.activeAtBoundary, handler.IsFlagEnabledInEpoch(c.flag, boundary+1))
					}
				})
			}
		})
	}
}

func TestQualDRWASupernovaLoadedEpochRoundComposition(t *testing.T) {
	dir := t.TempDir()
	ep := filepath.Join(dir, "epochs.toml")
	rp := filepath.Join(dir, "rounds.toml")
	require.NoError(t, os.WriteFile(ep, []byte("[EnableEpochs]\nSupernovaEnableEpoch = 10\n"), 0600))
	require.NoError(t, os.WriteFile(rp, []byte("[RoundActivations.DisableAsyncCallV1]\nRound = \"100\"\n[RoundActivations.SupernovaEnableRound]\nRound = \"100\"\n"), 0600))
	ec, err := common.LoadEpochConfig(ep)
	require.NoError(t, err)
	rc, err := common.LoadRoundConfig(rp)
	require.NoError(t, err)
	eh, err := enablers.NewEnableEpochsHandler(ec.EnableEpochs, &epochNotifier.EpochNotifierStub{})
	require.NoError(t, err)
	rh, err := enablers.NewEnableRoundsHandler(*rc, &epochNotifier.RoundNotifierStub{})
	require.NoError(t, err)
	cases := []struct {
		name           string
		epoch          uint32
		round          uint64
		enabled, drain bool
	}{
		{"neither", 9, 99, false, false}, {"round_only", 9, 100, false, false},
		{"epoch_only_drain", 10, 99, false, true}, {"both_at_boundary", 10, 100, true, false},
		{"later_epoch_drain", 11, 99, false, true}, {"later_round_only", 9, 101, false, false},
		{"both_later", 11, 101, true, false}, {"max_coordinates", math.MaxUint32, math.MaxUint64, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Contradictory current notifications must not replace evaluated coordinates.
			for _, current := range []struct {
				epoch uint32
				round uint64
			}{{0, 0}, {math.MaxUint32, math.MaxUint64}} {
				eh.EpochConfirmed(current.epoch, 0)
				rh.RoundConfirmed(current.round, 0)
				require.Equal(t, c.enabled, common.IsAsyncExecutionEnabledForEpochAndRound(eh, rh, c.epoch, c.round))
				require.Equal(t, c.drain, common.IsInSupernovaDrainWindowForEpochAndRound(eh, rh, c.epoch, c.round))
			}
		})
	}
}

func TestQualDRWARoundConfigurationRejectsMissingAndMalformed(t *testing.T) {
	for _, entry := range []string{"", "[RoundActivations.SupernovaEnableRound]\nRound = \"invalid\"\n", "[RoundActivations.SupernovaEnableRound]\nRound = \"-1\"\n", "[RoundActivations.SupernovaEnableRound]\nRound = \"18446744073709551616\"\n"} {
		t.Run(fmt.Sprintf("case_%d", len(entry)), func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "rounds.toml")
			require.NoError(t, os.WriteFile(p, []byte("[RoundActivations.DisableAsyncCallV1]\nRound = \"0\"\n"+entry), 0600))
			cfg, err := common.LoadRoundConfig(p)
			require.NoError(t, err)
			handler, err := enablers.NewEnableRoundsHandler(*cfg, &epochNotifier.RoundNotifierStub{})
			require.Error(t, err)
			require.Nil(t, handler)
		})
	}
}
