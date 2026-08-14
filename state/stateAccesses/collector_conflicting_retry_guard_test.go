package stateAccesses

// Guard for retry semantics on the #7962 base. A commit that reuses an
// execution identity must be:
//   - idempotent when the root and the payload are identical;
//   - rejected with a typed conflict error when the payload differs, because
//     silently keeping the first payload hides non-deterministic re-execution
//     or corruption from every downstream consumer (storage, outport, DRWA
//     audit evidence).

import (
	"testing"

	data "github.com/multiversx/mx-chain-core-go/data/stateChange"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/disabled"
)

func TestCollector_IdenticalRetryIsIdempotent(t *testing.T) {
	t.Parallel()

	c, err := NewCollector(disabled.NewDisabledStateAccessesStorer(), WithCollectWrite())
	require.NoError(t, err)

	headerHash := []byte("execution-header-hash")
	rootHash := []byte("root-hash")

	generation := c.BeginExecution(headerHash)
	c.AddStateAccess(&data.StateAccess{Type: data.Write, TxHash: []byte("tx-1"), MainTrieKey: []byte("acc-1")})
	require.NoError(t, c.CommitCollectedAccesses(rootHash))
	c.EndExecution(generation)

	generation = c.BeginExecution(headerHash)
	c.AddStateAccess(&data.StateAccess{Type: data.Write, TxHash: []byte("tx-1"), MainTrieKey: []byte("acc-1")})
	require.NoError(t, c.CommitCollectedAccesses(rootHash),
		"an identical retry must succeed idempotently")
	c.EndExecution(generation)

	retained, err := c.TakeStateAccessesForHeader(headerHash, rootHash)
	require.NoError(t, err)
	require.Contains(t, retained, "tx-1")
}

func TestCollector_ConflictingRetryMustBeRejected(t *testing.T) {
	t.Parallel()

	c, err := NewCollector(disabled.NewDisabledStateAccessesStorer(), WithCollectWrite())
	require.NoError(t, err)

	headerHash := []byte("execution-header-hash")
	rootHash := []byte("root-hash")

	generation := c.BeginExecution(headerHash)
	c.AddStateAccess(&data.StateAccess{Type: data.Write, TxHash: []byte("tx-1"), MainTrieKey: []byte("acc-1")})
	require.NoError(t, c.CommitCollectedAccesses(rootHash))
	c.EndExecution(generation)

	generation = c.BeginExecution(headerHash)
	c.AddStateAccess(&data.StateAccess{Type: data.Write, TxHash: []byte("tx-2"), MainTrieKey: []byte("acc-2")})
	err = c.CommitCollectedAccesses(rootHash)
	c.EndExecution(generation)

	require.ErrorIs(t, err, state.ErrStateAccessesExecutionConflict,
		"a same-identity retry with a different payload must fail loudly, not silently keep the first payload")

	// the first (accepted) payload must remain retained and consumable
	retained, takeErr := c.TakeStateAccessesForHeader(headerHash, rootHash)
	require.NoError(t, takeErr)
	require.Contains(t, retained, "tx-1")
	require.NotContains(t, retained, "tx-2")
}
