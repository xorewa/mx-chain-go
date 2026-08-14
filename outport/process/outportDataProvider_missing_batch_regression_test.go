package process

// Differential regression guard. This file compiles on both this tree and
// the base commit 80afef363f (PR #7961 head): it uses only APIs that exist
// unchanged in both, so the asserted delivery contract can be checked against
// either version.
//
// Scenario: the state-access collector holds NO batch for the block being
// indexed. This is the normal collector state right after a node restart
// (the collector is purely in-memory), and it is also reachable through any
// root/identity mismatch.
//
// Required behavior (base commit and fixed tree): the missing batch is logged
// as a warning and the block is still prepared and delivered to the outport
// drivers without state accesses. The execution-keyed rework must never turn
// a missing side-channel batch into a whole block silently disappearing from
// the indexer.

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/stateAccesses"
	"github.com/multiversx/mx-chain-go/testscommon/shardingMocks"
)

func TestPrepareOutportSaveBlockData_BlockMustStillBeDeliveredWhenAccessesBatchIsMissing(t *testing.T) {
	t.Parallel()

	// a real, enabled collector that holds no batch - the state every node is
	// in immediately after a restart
	collector, err := stateAccesses.NewCollector(
		disabled.NewDisabledStateAccessesStorer(),
		stateAccesses.WithCollectRead(),
	)
	require.NoError(t, err)

	arg := createArgOutportDataProvider()
	arg.StateAccessesCollector = collector
	arg.NodesCoordinator = &shardingMocks.NodesCoordinatorMock{
		GetValidatorsPublicKeysCalled: func(randomness []byte, round uint64, shardId uint32, epoch uint32) (string, []string, error) {
			return "", nil, nil
		},
		GetValidatorsIndexesCalled: func(publicKeys []string, epoch uint32) ([]uint64, error) {
			return []uint64{0, 1}, nil
		},
	}
	provider, err := NewOutportDataProvider(arg)
	require.NoError(t, err)

	res, err := provider.PrepareOutportSaveBlockData(ArgPrepareOutportSaveBlockData{
		Header:     &block.Header{Nonce: 7, RootHash: []byte("block-root-hash")},
		Body:       &block.Body{},
		HeaderHash: []byte("block-header-hash"),
	})

	require.NoError(t, err,
		"a missing state-access batch must degrade to a block without accesses, not suppress delivery of the whole block")
	require.NotNil(t, res)
	require.NotNil(t, res.HeaderDataWithBody.Body,
		"the block body must still reach the outport drivers")
}
