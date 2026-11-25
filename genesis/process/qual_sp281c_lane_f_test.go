package process

import (
	"testing"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CLaneFOriginalGenesisCoordinate(t *testing.T) {
	for _, tt := range []struct {
		name                                string
		configured, evidence, afterHardFork bool
		start                               uint32
		want                                error
	}{
		{"ordinary restart", false, false, false, 18, nil},
		{"missing evidence", true, false, false, 17, drwa.ErrInitialProgrammeLimits},
		{"original genesis", true, true, false, 17, nil},
		{"later startup", true, true, false, 18, drwa.ErrDeploymentIdentity},
		{"hardfork at same epoch", true, true, true, 17, drwa.ErrDeploymentIdentity},
	} {
		t.Run(tt.name, func(t *testing.T) {
			arg := ArgsGenesisBlockCreator{GenesisEpoch: 17, StartEpochNum: tt.start}
			if tt.configured {
				arg.DRWAMinimumGenesis = &config.DRWAMinimumGenesis{}
			}
			if tt.evidence {
				// Only the presence check is under test. No state or codec consumes this value.
				arg.DRWAInitialProgrammes = []drwa.InitialProgrammeEvidence{{}}
			}
			arg.HardForkConfig.AfterHardFork = tt.afterHardFork
			arg.HardForkConfig.StartEpoch = 17
			require.ErrorIs(t, checkDRWAOriginalGenesis(arg), tt.want)
		})
	}
}
