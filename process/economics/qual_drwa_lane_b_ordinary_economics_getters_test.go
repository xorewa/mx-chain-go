package economics_test

import (
	"testing"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/economics"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAOrdinaryRewardsConfigGetters(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name               string
		epoch              uint32
		percentage, factor float64
		gradient           string
	}{
		{"before", 1, 0.1, 0.25, "300000000000000000000"},
		{"at_boundary", 2, 0.1, 0.25, "300000000000000000000"},
		{"after", 3, 0.2, 0.5, "200000000000000000000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := createArgsForEconomicsData(1)
			first := args.Economics.RewardsSettings.RewardsConfigByEpoch[0]
			second := first
			second.EpochEnable = 2
			second.LeaderPercentage = 0.2
			second.DeveloperPercentage = 0.2
			second.ProtocolSustainabilityPercentage = 0.2
			second.TopUpGradientPoint = "200000000000000000000"
			second.TopUpFactor = 0.5
			args.Economics.RewardsSettings.RewardsConfigByEpoch = []config.EpochRewardSettings{second, first}
			args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).GetCurrentEpochCalled = func() uint32 { return tc.epoch }
			ed, err := economics.NewEconomicsData(args)
			require.NoError(t, err)

			require.Equal(t, tc.percentage, ed.LeaderPercentage())
			require.Equal(t, tc.percentage, ed.LeaderPercentageInEpoch(tc.epoch))
			require.Equal(t, tc.percentage, ed.DeveloperPercentage())
			require.Equal(t, tc.percentage, ed.DeveloperPercentageInEpoch(tc.epoch))
			require.Equal(t, tc.percentage, ed.ProtocolSustainabilityPercentage())
			require.Equal(t, tc.percentage, ed.ProtocolSustainabilityPercentageInEpoch(tc.epoch))
			require.Equal(t, tc.factor, ed.RewardsTopUpFactor())
			require.Equal(t, tc.factor, ed.RewardsTopUpFactorInEpoch(tc.epoch))
			require.Equal(t, tc.gradient, ed.RewardsTopUpGradientPoint().String())
			require.Equal(t, tc.gradient, ed.RewardsTopUpGradientPointInEpoch(tc.epoch).String())
			require.Equal(t, "2000000000000000000000", ed.GenesisTotalSupply().String())
		})
	}
}
