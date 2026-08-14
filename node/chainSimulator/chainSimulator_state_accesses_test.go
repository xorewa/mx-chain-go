package chainSimulator

// Full-node qualification of the state-access collector changes on this
// baseline: real multi-shard chain simulator nodes (3 shards + metachain)
// produce blocks through the Supernova activation and multiple epoch changes
// with state-access collection ENABLED, so the collector code sits live on
// the block-processing hot path (collection, merge, commit, reset and revert
// flows) of every node. Block production must be completely unaffected.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/node/chainSimulator/components/api"
)

func TestChainSimulatorSupernovaWithStateAccessCollectionEnabled(t *testing.T) {
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 defaultRoundsPerEpoch,
		SupernovaRoundsPerEpoch:        defaultSupernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               3,
		MetaChainMinNodes:              3,
		AlterConfigsFunction: func(cfg *config.Configs) {
			cfg.GeneralConfig.StateAccessesCollectorConfig.TypesToCollect = []string{"write"}
			cfg.GeneralConfig.StateAccessesCollectorConfig.SaveToStorage = false
		},
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	err = chainSimulator.GenerateBlocksUntilEpochIsReached(2)
	require.Nil(t, err)

	err = chainSimulator.GenerateBlocks(2)
	require.Nil(t, err)

	err = chainSimulator.GenerateBlocks(1) // supernova round activation
	require.Nil(t, err)

	err = chainSimulator.GenerateBlocks(50)
	require.Nil(t, err)

	time.Sleep(time.Second)

	chainSimulator.Close()
}
