package economics_test

import (
	"testing"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/economics"
	"github.com/multiversx/mx-chain-go/testscommon/chainParameters"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAOrdinaryInflationSettingsGetters(t *testing.T) {
	t.Parallel()

	args := createArgsForEconomicsData(1)
	args.Economics.GlobalSettings.MinimumInflation = 0.01
	args.Economics.GlobalSettings.YearSettings = []*config.YearSetting{{Year: 1, MaximumInflation: 0.1}}
	args.Economics.GlobalSettings.TailInflation = config.TailInflationSettings{
		EnableEpoch: 100, StartYearInflation: 0.08757, MinimumInflation: 0.01,
	}
	params := config.ChainParametersByEpochConfig{RoundsPerEpoch: 14400, RoundDuration: 6000}
	args.ChainParamsHandler = &chainParameters.ChainParametersHandlerStub{
		AllChainParametersCalled: func() []config.ChainParametersByEpochConfig {
			return []config.ChainParametersByEpochConfig{params}
		},
	}
	ed, err := economics.NewEconomicsData(args)
	require.NoError(t, err)

	for _, tc := range []struct {
		name  string
		epoch uint32
		tail  bool
		rate  float64
	}{
		{"before", 99, false, 0.1},
		{"at_boundary", 100, false, 0.1},
		{"after", 101, true, 0.08395550376084304},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.tail, ed.IsTailInflationEnabled(tc.epoch))
			require.InDelta(t, tc.rate, ed.MaxInflationRate(1, tc.epoch), 1e-12)
		})
	}
}
