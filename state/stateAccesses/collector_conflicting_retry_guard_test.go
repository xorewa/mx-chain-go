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

type countingStateAccessesStorer struct {
	stores int
}

func (s *countingStateAccessesStorer) Store(_ map[string]*data.StateAccesses) error {
	s.stores++
	return nil
}

func (s *countingStateAccessesStorer) IsInterfaceNil() bool {
	return s == nil
}

func TestCollector_IdenticalRetryIsIdempotent(t *testing.T) {
	t.Parallel()

	storer := &countingStateAccessesStorer{}
	c, err := NewCollector(storer, WithCollectWrite())
	require.NoError(t, err)

	headerHash := []byte("execution-header-hash")
	rootHash := []byte("root-hash")

	c.BeginExecution(headerHash)
	c.AddStateAccess(&data.StateAccess{Type: data.Write, TxHash: []byte("tx-1"), MainTrieKey: []byte("acc-1")})
	require.NoError(t, c.CommitCollectedAccesses(rootHash))
	c.EndExecution(headerHash)

	c.BeginExecution(headerHash)
	c.AddStateAccess(&data.StateAccess{Type: data.Write, TxHash: []byte("tx-1"), MainTrieKey: []byte("acc-1")})
	require.NoError(t, c.CommitCollectedAccesses(rootHash),
		"an identical retry must succeed idempotently")
	c.EndExecution(headerHash)
	require.Equal(t, 1, storer.stores,
		"an identical retry must not write the retained payload again")

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

	c.BeginExecution(headerHash)
	c.AddStateAccess(&data.StateAccess{Type: data.Write, TxHash: []byte("tx-1"), MainTrieKey: []byte("acc-1")})
	require.NoError(t, c.CommitCollectedAccesses(rootHash))
	c.EndExecution(headerHash)

	c.BeginExecution(headerHash)
	c.AddStateAccess(&data.StateAccess{Type: data.Write, TxHash: []byte("tx-2"), MainTrieKey: []byte("acc-2")})
	err = c.CommitCollectedAccesses(rootHash)
	c.EndExecution(headerHash)

	require.ErrorIs(t, err, state.ErrStateAccessesExecutionConflict,
		"a same-identity retry with a different payload must fail loudly, not silently keep the first payload")

	// the first (accepted) payload must remain retained and consumable
	retained, takeErr := c.TakeStateAccessesForHeader(headerHash, rootHash)
	require.NoError(t, takeErr)
	require.Contains(t, retained, "tx-1")
	require.NotContains(t, retained, "tx-2")

	// A conflict must not destroy the rejected working payload. Prove it can
	// still be committed under a new execution identity after the caller
	// handles the conflict.
	retryHeaderHash := []byte("retry-header-hash")
	retryRootHash := []byte("retry-root-hash")
	c.BeginExecution(retryHeaderHash)
	require.NoError(t, c.CommitCollectedAccesses(retryRootHash))
	c.EndExecution(retryHeaderHash)

	restored, restoreErr := c.TakeStateAccessesForHeader(retryHeaderHash, retryRootHash)
	require.NoError(t, restoreErr)
	require.Contains(t, restored, "tx-2")
}
