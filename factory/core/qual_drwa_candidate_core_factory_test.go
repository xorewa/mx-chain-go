package core

import (
	"fmt"
	"testing"
	"time"

	nativeCore "github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/endProcess"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
)

func qualDRWACandidateCoreArgs(t *testing.T) CoreComponentsFactoryArgs {
	t.Helper()
	cfg, err := common.LoadMainConfig(qualDRWACandidateGenesisPath(t, "config.toml"))
	require.NoError(t, err)
	epochs, err := common.LoadEpochConfig(qualDRWACandidateGenesisPath(t, "enableEpochs.toml"))
	require.NoError(t, err)
	rounds, err := common.LoadRoundConfig(qualDRWACandidateGenesisPath(t, "enableRounds.toml"))
	require.NoError(t, err)
	economics, err := common.LoadEconomicsConfig(qualDRWACandidateGenesisPath(t, "economics.toml"))
	require.NoError(t, err)
	ratings, err := common.LoadRatingsConfig(qualDRWACandidateGenesisPath(t, "ratings.toml"))
	require.NoError(t, err)
	var nodes config.NodesConfig
	require.NoError(t, nativeCore.LoadJsonFile(&nodes, qualDRWACandidateGenesisPath(t, "nodesSetup.json")))
	require.Zero(t, nodes.StartTime)
	// Only this field differs from the loaded candidate. Empty Hosts makes
	// native ntp.sync enumerate zero hosts, so it never invokes its query.
	cfg.NTPConfig.Hosts = nil
	require.Positive(t, cfg.NTPConfig.SyncPeriodSeconds)
	return CoreComponentsFactoryArgs{
		Config: *cfg, EpochConfig: *epochs, RoundConfig: *rounds,
		EconomicsConfig: *economics, RatingsConfig: *ratings, NodesConfig: nodes,
		WorkingDirectory: t.TempDir(), ChanStopNodeProcess: make(chan endProcess.ArgEndProcess, 1),
	}
}

// T09-M25: actual native core assembly, with NTP queries explicitly excluded.
// Native NTP/alarm loops start and Close cancels them. This is not node startup,
// deployment admission, authenticated header execution or network evidence.
func TestQualDRWACandidateCoreFactoryNativeAssembly(t *testing.T) {
	factory, err := NewCoreComponentsFactory(qualDRWACandidateCoreArgs(t))
	require.NoError(t, err)
	components, err := factory.Create()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, components.Close()) })
	require.Equal(t, "undefined", components.chainID)
	require.Equal(t, uint32(3), components.nodesSetupHandler.NumberOfShards())
	require.Len(t, components.nodesSetupHandler.AllInitialNodes(), 36)
	require.Equal(t, uint64(6000), components.nodesSetupHandler.GetRoundDuration())
	require.Equal(t, 440*6*time.Second, components.supernovaGenesisTime.Sub(components.genesisTime))
	t.Logf("native local-clock genesis=%s; NTP hosts empty; no admitted deployment genesis", components.genesisTime.UTC().Format(time.RFC3339Nano))

	// Both notifier inputs below are synthetic. Exercise the factory's actual
	// subscriptions; this does not prove any canonical epoch/round context.
	for _, tc := range []struct {
		epoch          uint32
		round          uint64
		async          bool
		duration       uint64
		roundsPerEpoch int64
	}{
		{0, 439, false, 6000, 200},
		{1, 439, false, 6000, 200},
		{1, 440, false, 6000, 200},
		{2, 439, false, 600, 2000},
		{2, 440, true, 600, 2000},
		{3, 440, true, 600, 2000},
	} {
		t.Run(fmt.Sprintf("epoch_%d_round_%d", tc.epoch, tc.round), func(t *testing.T) {
			hdr := &block.Header{Epoch: tc.epoch, Round: tc.round}
			components.epochStartNotifierWithConfirm.NotifyAll(hdr)
			components.epochNotifier.CheckEpoch(hdr)
			components.roundNotifier.CheckRound(hdr)
			params := components.chainParametersHandler.CurrentChainParameters()
			require.Equal(t, tc.duration, params.RoundDuration)
			require.Equal(t, tc.roundsPerEpoch, params.RoundsPerEpoch)
			require.Equal(t, tc.async, common.IsAsyncExecutionEnabledForEpochAndRound(
				components.enableEpochsHandler, components.enableRoundsHandler, tc.epoch, tc.round))
		})
	}
	for _, tc := range []struct {
		round    uint64
		duration time.Duration
		boundary uint64
	}{
		{439, 6 * time.Second, 0},
		{440, 600 * time.Millisecond, 440},
		{441, 600 * time.Millisecond, 440},
	} {
		t.Run(fmt.Sprintf("chronology_%d", tc.round), func(t *testing.T) {
			stamp := components.supernovaGenesisTime
			if tc.round < 440 {
				stamp = stamp.Add(-6 * time.Second)
			} else {
				stamp = stamp.Add(time.Duration(tc.round-440) * 600 * time.Millisecond)
			}
			components.roundHandler.UpdateRound(components.genesisTime, stamp)
			require.Equal(t, int64(tc.round), components.roundHandler.Index())
			require.Equal(t, tc.duration, components.roundHandler.TimeDuration())
			require.Equal(t, uint64(stamp.UnixMilli()), components.roundHandler.GetTimeStampForRound(tc.round))
			components.roundNotifier.CheckRound(&block.Header{Round: tc.round})
			require.Equal(t, tc.boundary, components.antifloodConfigsHandler.GetCurrentConfig().Round)
		})
	}
}
