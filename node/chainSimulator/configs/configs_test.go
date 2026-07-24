package configs

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/integrationTests/realcomponents"
	"github.com/multiversx/mx-chain-go/testscommon"

	"github.com/stretchr/testify/require"
)

func TestNewProcessorRunnerChainArguments(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	outputConfig, err := CreateChainSimulatorConfigs(ArgsChainSimulatorConfigs{
		NumOfShards:                    3,
		OriginalConfigsPath:            "../../../cmd/node/config",
		RoundDurationInMillis:          6000,
		SupernovaRoundDurationInMillis: 600,
		TempDir:                        t.TempDir(),
		MetaChainMinNodes:              1,
		MinNodesPerShard:               1,
		ConsensusGroupSize:             1,
		MetaChainConsensusGroupSize:    1,
	})
	require.Nil(t, err)

	pr := realcomponents.NewProcessorRunner(t, outputConfig.Configs)
	pr.Close(t)
}

func TestUpdateSupernovaConfigs(t *testing.T) {
	t.Parallel()

	configs, err := testscommon.CreateTestConfigs(t.TempDir(), "../../../cmd/node/config")
	require.Nil(t, err)

	chainSimulatorCfg := ArgsChainSimulatorConfigs{
		RoundsPerEpoch: core.OptionalUint64{
			Value:    20,
			HasValue: true,
		},
		SupernovaRoundsPerEpoch: core.OptionalUint64{
			Value:    200,
			HasValue: true,
		},
		SupernovaRoundDurationInMillis: 600,
	}

	updateSupernovaConfigs(configs, chainSimulatorCfg)
	require.Equal(t, uint64(600), configs.GeneralConfig.GeneralSettings.ChainParametersByEpoch[2].RoundDuration)
	require.Equal(t, configs.EpochConfig.EnableEpochs.SupernovaEnableEpoch, configs.GeneralConfig.GeneralSettings.ChainParametersByEpoch[2].EnableEpoch)
	require.Equal(t, "45", configs.RoundConfig.RoundActivations[string(common.SupernovaRoundFlag)].Round)
}

func TestUpdateSupernovaConfigsFromGenesisPromotesPostSupernovaSchedules(t *testing.T) {
	t.Parallel()

	configs, err := testscommon.CreateTestConfigs(t.TempDir(), "../../../cmd/node/config")
	require.NoError(t, err)
	configs.EpochConfig.EnableEpochs.AndromedaEnableEpoch = 0
	configs.EpochConfig.EnableEpochs.SupernovaEnableEpoch = 0

	updateSupernovaConfigs(configs, ArgsChainSimulatorConfigs{
		RoundsPerEpoch: core.OptionalUint64{
			Value:    2000,
			HasValue: true,
		},
		SupernovaRoundsPerEpoch: core.OptionalUint64{
			Value:    2000,
			HasValue: true,
		},
		SupernovaRoundDurationInMillis: 600,
	})

	generalSettings := configs.GeneralConfig.GeneralSettings
	require.Len(t, generalSettings.ChainParametersByEpoch, 1)
	require.Equal(t, uint32(0), generalSettings.ChainParametersByEpoch[0].EnableEpoch)
	require.Equal(t, uint64(600), generalSettings.ChainParametersByEpoch[0].RoundDuration)
	require.Equal(t, int64(2000), generalSettings.ChainParametersByEpoch[0].RoundsPerEpoch)

	require.Len(t, generalSettings.EpochChangeGracePeriodByEpoch, 1)
	require.Equal(t, uint32(0), generalSettings.EpochChangeGracePeriodByEpoch[0].EnableEpoch)
	require.Equal(t, uint32(100), generalSettings.EpochChangeGracePeriodByEpoch[0].GracePeriodInRounds)

	require.Len(t, generalSettings.ProcessConfigsByEpoch, 1)
	require.Equal(t, uint32(0), generalSettings.ProcessConfigsByEpoch[0].EnableEpoch)
	require.Equal(t, uint32(75), generalSettings.ProcessConfigsByEpoch[0].MaxMetaNoncesBehind)
	require.Len(t, generalSettings.ProcessConfigsByRound, 1)
	require.Equal(t, uint64(0), generalSettings.ProcessConfigsByRound[0].EnableRound)
	require.Equal(t, uint32(100), generalSettings.ProcessConfigsByRound[0].MaxRoundsWithoutNewBlockReceived)

	require.Len(t, generalSettings.EpochStartConfigsByEpoch, 1)
	require.Equal(t, uint32(0), generalSettings.EpochStartConfigsByEpoch[0].EnableEpoch)
	require.Equal(t, uint32(250), generalSettings.EpochStartConfigsByEpoch[0].GracePeriodRounds)
	require.Len(t, generalSettings.EpochStartConfigsByRound, 1)
	require.Equal(t, uint64(0), generalSettings.EpochStartConfigsByRound[0].EnableRound)
	require.Equal(t, uint32(500), generalSettings.EpochStartConfigsByRound[0].MaxRoundsWithoutCommittedStartInEpochBlock)

	require.Len(t, generalSettings.ConsensusConfigsByEpoch, 1)
	require.Equal(t, uint32(0), generalSettings.ConsensusConfigsByEpoch[0].EnableEpoch)
	require.Equal(t, uint32(100), generalSettings.ConsensusConfigsByEpoch[0].NumRoundsToWaitBeforeSignalingChronologyStuck)
	require.Len(t, generalSettings.ConsensusConfigsByRound, 1)
	require.Equal(t, uint64(0), generalSettings.ConsensusConfigsByRound[0].EnableRound)
	require.Equal(t, float64(0.35), generalSettings.ConsensusConfigsByRound[0].SubroundsTiming[1].EndTime)

	require.Len(t, configs.GeneralConfig.Antiflood.ConfigsByRound, 1)
	require.Equal(t, uint64(0), configs.GeneralConfig.Antiflood.ConfigsByRound[0].Round)
	require.Equal(t, uint32(100), configs.GeneralConfig.Antiflood.ConfigsByRound[0].FastReacting.BlackList.NumFloodingRounds)

	require.Len(t, configs.GeneralConfig.Versions.VersionsByEpochs, 1)
	require.Equal(t, uint32(0), configs.GeneralConfig.Versions.VersionsByEpochs[0].StartEpoch)
	require.Equal(t, uint64(0), configs.GeneralConfig.Versions.VersionsByEpochs[0].StartRound)
	require.Equal(t, "3", configs.GeneralConfig.Versions.VersionsByEpochs[0].Version)
	require.Equal(t, "0", configs.RoundConfig.RoundActivations[string(common.SupernovaRoundFlag)].Round)
}
