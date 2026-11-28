package economics

import (
	"testing"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/testscommon/chainParameters"
	"github.com/stretchr/testify/require"
)

// A detached inflation calculator needs a schedule from which to derive a rate.
func TestQualSP218OrdinaryEmptyInflationSchedule(t *testing.T) {
	t.Parallel()

	cfg := &config.EconomicsConfig{
		GlobalSettings: config.GlobalSettings{
			MinimumInflation: 0.01,
			TailInflation:    config.TailInflationSettings{StartYearInflation: 0.1},
		},
	}
	for _, tc := range []struct {
		name     string
		schedule []config.ChainParametersByEpochConfig
	}{
		{"absent", nil},
		{"empty", []config.ChainParametersByEpochConfig{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := &chainParameters.ChainParametersHandlerStub{
				AllChainParametersCalled: func() []config.ChainParametersByEpochConfig {
					return tc.schedule
				},
			}
			calculator, err := newGlobalSettingsHandler(cfg, params)
			require.ErrorIs(t, err, process.ErrEmptyChainParametersConfiguration)
			require.Nil(t, calculator)
		})
	}
}
