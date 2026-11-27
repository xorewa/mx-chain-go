package node

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core/keyValStorage"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryLeafBudgetAccounting(t *testing.T) {
	leaf := keyValStorage.NewKeyValStorage([]byte("key"), []byte("value"))
	budget := trieCollectionBudget{bytesRemaining: 144, leavesRemaining: 1}
	require.NoError(t, budget.chargeLeaf(leaf))
	require.Zero(t, budget.bytesRemaining)
	require.Zero(t, budget.leavesRemaining)

	budget = trieCollectionBudget{bytesRemaining: 132, leavesRemaining: 1}
	require.ErrorIs(t, budget.chargeLeaf(leaf), ErrTrieOperationsLimit)
}
