package components

import (
	"testing"

	data "github.com/multiversx/mx-chain-core-go/data/stateChange"
	"github.com/stretchr/testify/require"
)

func TestStateComponentsHolder_PropagatesConfiguredStateAccessesCollector(t *testing.T) {
	t.Parallel()

	args := createArgsStateComponents()
	args.Config.StateAccessesCollectorConfig.TypesToCollect = []string{"write"}
	comp, err := CreateStateComponents(args)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, comp.Close()) })

	collector := comp.StateAccessesCollector()
	require.NotNil(t, collector)

	headerHash := []byte("simulator-header")
	rootHash := []byte("simulator-root")
	collector.BeginExecution(headerHash)
	collector.AddStateAccess(&data.StateAccess{
		Type:   data.Write,
		TxHash: []byte("simulator-tx"),
	})
	require.NoError(t, collector.CommitCollectedAccesses(rootHash))
	collector.EndExecution(headerHash)

	retained, err := collector.TakeStateAccessesForHeader(headerHash, rootHash)
	require.NoError(t, err)
	require.Contains(t, retained, "simulator-tx")
}
