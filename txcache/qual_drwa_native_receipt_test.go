package txcache

import (
	"encoding/json"
	"math/big"
	"testing"

	nativeTransaction "github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/stretchr/testify/require"
)

func TestQualD19ReceiptDoesNotChangeNativeJSONOrPriority(t *testing.T) {
	tx := &nativeTransaction.Transaction{Nonce: 7, Value: big.NewInt(1), GasLimit: 100, SndAddr: []byte("synthetic-sender")}
	ordinary := &WrappedTransaction{Tx: tx, TxHash: []byte("synthetic-hash"), Size: 111,
		Fee: big.NewInt(2), PricePerUnit: 3, TransferredValue: big.NewInt(1), FeePayer: tx.SndAddr}
	withMetadata := *ordinary
	// Deliberately not an authority or a native validation receipt. The cache
	// field is opaque storage; no test grants meaning to its presence.
	withMetadata.DRWAValidationReceipt = struct{ Label string }{"synthetic-non-authority"}
	a, err := json.Marshal(ordinary)
	require.NoError(t, err)
	b, err := json.Marshal(&withMetadata)
	require.NoError(t, err)
	require.Equal(t, a, b)
	require.Same(t, tx, withMetadata.Tx)
	for _, price := range []uint64{2, 3, 4} {
		other := &WrappedTransaction{Tx: tx, TxHash: []byte("other-synthetic-hash"), PricePerUnit: price}
		require.Equal(t, ordinary.isTransactionMoreValuableForNetwork(other), withMetadata.isTransactionMoreValuableForNetwork(other))
		require.Equal(t, other.isTransactionMoreValuableForNetwork(ordinary), other.isTransactionMoreValuableForNetwork(&withMetadata))
	}
	require.Equal(t, ordinary.decideFeePayer(), withMetadata.decideFeePayer())
	require.Equal(t, ordinary.isFeePayerSameAsSender(), withMetadata.isFeePayerSameAsSender())
}

// INV-0: node 9e22a9f8a362 txcache/txByHashMap.go clear removes entries
// and resets the item counter, but does not reset its approximate byte counter.
// Receipt transport must not silently repair this ordinary native behavior.
func TestQualD20ClearPreservesUntouchedNativeAccounting(t *testing.T) {
	cache := newUnconstrainedCacheToTest(createMockTxBoundsConfig())
	first := createTx([]byte("synthetic-clear-first"), "alice", 1)
	first.Size = 17
	_, added := cache.AddTx(first)
	require.True(t, added)
	require.Equal(t, 17, cache.NumBytes())
	cache.Clear()
	require.Zero(t, cache.Len())
	require.False(t, cache.Has(first.TxHash))
	require.Equal(t, 17, cache.NumBytes(), "untouched clear leaves its approximate byte counter unchanged")
	second := createTx([]byte("synthetic-clear-second"), "alice", 2)
	second.Size = 23
	_, added = cache.AddTx(second)
	require.True(t, added)
	require.Equal(t, 40, cache.NumBytes())
	require.True(t, cache.RemoveTxByHash(second.TxHash))
	require.Zero(t, cache.Len())
	require.Equal(t, 17, cache.NumBytes())
}
