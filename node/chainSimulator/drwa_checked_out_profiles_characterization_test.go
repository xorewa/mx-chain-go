package chainSimulator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/node/chainSimulator/components/api"
	"github.com/stretchr/testify/require"
)

// Characterizes the node-construction boundary with the actual checked-out
// Ldevnet configuration and genesis material. The first run proves that the
// current disabled profile starts. The second changes only DRWA.Enabled through
// the same in-memory configuration hook used by the simulator command and must
// reproduce the production genesis failure.
func TestCharacterization_CheckedOutLdevnetAtConcreteChainSimulatorStartup(t *testing.T) {
	profileRoot, err := filepath.Abs(filepath.Join("..", "..", "..", "mx-chain-ldevnet-config"))
	require.NoError(t, err)
	if _, statErr := os.Stat(profileRoot); os.IsNotExist(statErr) {
		t.Skip("mx-chain-ldevnet-config is not present in this checkout")
	}

	newSimulator := func(t *testing.T, alter func(*config.Configs)) (*simulator, error) {
		t.Helper()
		return NewChainSimulator(ArgsChainSimulator{
			BypassTxSignatureCheck:         true,
			BypassCreateBlockTimeCheck:     true,
			TempDir:                        t.TempDir(),
			PathToInitialConfig:            profileRoot,
			NumOfShards:                    2,
			RoundDurationInMillis:          defaultRoundDurationInMillis,
			SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
			RoundsPerEpoch:                 defaultRoundsPerEpoch,
			SupernovaRoundsPerEpoch:        defaultSupernovaRoundsPerEpoch,
			ApiInterface:                   api.NewNoApiInterface(),
			MinNodesPerShard:               defaultMinNodesPerShard,
			MetaChainMinNodes:              defaultMetaChainMinNodes,
			AlterConfigsFunction:           alter,
		})
	}

	t.Run("current-disabled-profile-starts", func(t *testing.T) {
		chain, startupErr := newSimulator(t, nil)
		require.NoError(t, startupErr)
		require.NotNil(t, chain)
		chain.Close()
	})

	t.Run("enabled-only-reproduces-genesis-failure", func(t *testing.T) {
		chain, startupErr := newSimulator(t, func(configs *config.Configs) {
			configs.GeneralConfig.DRWA.Enabled = true
		})
		if chain != nil {
			chain.Close()
		}
		require.ErrorContains(t, startupErr,
			`invalid DRWA key management model "": expected "multisig_3of5_contract"`)
		require.ErrorContains(t, startupErr, "while provisioning DRWA authorized callers")
	})
}
