package core

import (
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

// SP2-22, Part A 5.1 (before-first-effect): the registry member of a new token
// reaches each shard as the first result of its registration only while
// created results keep their execution order. DRWA enforcement therefore does
// not start, and no block is admitted as enforced, unless
// KeepExecOrderOnCreatedSCRsFlag is active at that epoch.
func TestQualSP222EnforcementRequiresCreatedResultOrder(t *testing.T) {
	for _, activation := range []uint32{0, 1, 3, 4, ^uint32(0)} {
		t.Run(fmt.Sprintf("activation_%d", activation), func(t *testing.T) {
			paths, overlay := qualDRWALoadedFiles(t)
			qualDRWAReplaceLoaded(t, paths.Epoch, "\n    KeepExecOrderOnCreatedSCRsEnableEpoch = 1",
				fmt.Sprintf("\n    KeepExecOrderOnCreatedSCRsEnableEpoch = %d", activation))
			candidate, err := LoadDRWAConfigurationCandidate(paths, overlay,
				DRWAConfigurationSupport{RelayedV3: true, RegisterMetaESDTPath: true})
			if activation > 3 {
				require.ErrorContains(t, err, string(common.KeepExecOrderOnCreatedSCRsFlag))
				require.Nil(t, candidate, "enforcement does not start")
				return
			}
			require.NoError(t, err)
			require.NoError(t, candidate.CheckEnforcedBlock(3, 440))
			require.True(t, candidate.epochs.IsFlagEnabledInEpoch(common.KeepExecOrderOnCreatedSCRsFlag, 3))
		})
	}
}
