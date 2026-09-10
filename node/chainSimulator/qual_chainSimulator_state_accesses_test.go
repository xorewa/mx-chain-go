package chainSimulator

// Full-node qualification of the state-access collector changes on this
// baseline: real multi-shard chain simulator nodes (3 shards + metachain)
// receive the configured collector through the same state-component holder
// used by block processing, then produce blocks through Supernova activation
// and multiple epoch changes. The explicit lifecycle probe below proves that
// the simulator did not substitute a disabled collector; focused outport tests
// separately prove delivery of retained header-scoped accesses.

import (
	"testing"
	"time"

	data "github.com/multiversx/mx-chain-core-go/data/stateChange"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/node/chainSimulator/components/api"
)

func TestQualChainSimulatorSupernovaWithStateAccessCollectionEnabled(t *testing.T) {
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
	t.Cleanup(chainSimulator.Close)

	collector := chainSimulator.GetNodeHandler(0).GetStateComponents().StateAccessesCollector()
	require.NotNil(t, collector)
	headerHash := []byte("chain-simulator-header")
	rootHash := []byte("chain-simulator-root")
	collector.BeginExecution(headerHash)
	collector.AddStateAccess(&data.StateAccess{
		Type:   data.Write,
		TxHash: []byte("chain-simulator-tx"),
	})
	require.NoError(t, collector.CommitCollectedAccesses(rootHash))
	collector.EndExecution(headerHash)
	retained, err := collector.TakeStateAccessesForHeader(headerHash, rootHash)
	require.NoError(t, err)
	require.Contains(t, retained, "chain-simulator-tx")

	err = chainSimulator.GenerateBlocksUntilEpochIsReached(2)
	require.Nil(t, err)

	err = chainSimulator.GenerateBlocks(2)
	require.Nil(t, err)

	err = chainSimulator.GenerateBlocks(1) // supernova round activation
	require.Nil(t, err)

	err = chainSimulator.GenerateBlocks(50)
	require.Nil(t, err)

	time.Sleep(time.Second)
}
