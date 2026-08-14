package process

// Guard for the core #7961 defect on the #7962 base: two distinct execution
// results sharing one state root must each keep their own state-access batch
// all the way through the outport provider.

import (
	"encoding/hex"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/stateChange"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/stateAccesses"
)

func TestGetStateAccesses_V3DistinctExecutionsWithSameRootAreBothDelivered(t *testing.T) {
	t.Parallel()

	collector, err := stateAccesses.NewCollector(
		disabled.NewDisabledStateAccessesStorer(),
		stateAccesses.WithCollectRead(),
	)
	require.NoError(t, err)

	sharedRoot := []byte("shared-root-hash")
	executionA := []byte("execution-a-header-hash")
	executionB := []byte("execution-b-header-hash")

	generation := collector.BeginExecution(executionA)
	collector.AddStateAccess(&stateChange.StateAccess{Type: stateChange.Read, TxHash: []byte("tx-a")})
	require.NoError(t, collector.CommitCollectedAccesses(sharedRoot))
	collector.EndExecution(generation)

	generation = collector.BeginExecution(executionB)
	collector.AddStateAccess(&stateChange.StateAccess{Type: stateChange.Read, TxHash: []byte("tx-b")})
	require.NoError(t, collector.CommitCollectedAccesses(sharedRoot))
	collector.EndExecution(generation)

	arg := createArgOutportDataProvider()
	arg.StateAccessesCollector = collector
	provider, err := NewOutportDataProvider(arg)
	require.NoError(t, err)

	header := &block.HeaderV3{
		ExecutionResults: []*block.ExecutionResult{
			{BaseExecutionResult: &block.BaseExecutionResult{HeaderHash: executionA, RootHash: sharedRoot}},
			{BaseExecutionResult: &block.BaseExecutionResult{HeaderHash: executionB, RootHash: sharedRoot}},
		},
	}

	accessesByExecution, _ := provider.getStateAccesses(header, []byte("v3-block-hash"), nil)

	require.Contains(t,
		accessesByExecution[hex.EncodeToString(executionA)].StateAccesses, "tx-a",
		"execution A must keep its own batch")
	require.Contains(t,
		accessesByExecution[hex.EncodeToString(executionB)].StateAccesses, "tx-b",
		"execution B must not lose its batch merely because its root equals A's root")
}
