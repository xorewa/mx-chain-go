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
	// An inert value exercises opaque cache storage without producing authority.
	marker := struct{ Label string }{"synthetic-non-authority"}
	cache := newTxByHashMap(1)
	copyForCache := *ordinary
	require.True(t, cache.addTxWithValidationReceipt(&copyForCache, marker))
	withMetadata, retained, found := cache.getTxWithValidationReceipt(string(ordinary.TxHash))
	require.True(t, found)
	require.Equal(t, marker, retained)
	a, err := json.Marshal(ordinary)
	require.NoError(t, err)
	b, err := json.Marshal(withMetadata)
	require.NoError(t, err)
	require.Equal(t, a, b)
	require.Same(t, tx, withMetadata.Tx)
	for _, price := range []uint64{2, 3, 4} {
		other := &WrappedTransaction{Tx: tx, TxHash: []byte("other-synthetic-hash"), PricePerUnit: price}
		require.Equal(t, ordinary.isTransactionMoreValuableForNetwork(other), withMetadata.isTransactionMoreValuableForNetwork(other))
		require.Equal(t, other.isTransactionMoreValuableForNetwork(ordinary), other.isTransactionMoreValuableForNetwork(withMetadata))
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

func TestQualValidationReceiptFollowsNativeCacheEntry(t *testing.T) {
	type receiptCache interface {
		AddTx(*WrappedTransaction) (bool, bool)
		AddTxWithValidationReceipt(*WrappedTransaction, interface{}) (bool, bool)
		GetByTxHash([]byte) (*WrappedTransaction, bool)
		GetByTxHashWithValidationReceipt([]byte) (*WrappedTransaction, interface{}, bool)
		ForEachTransactionWithValidationReceipt(ForEachTransactionWithValidationReceipt)
		RemoveTxByHash([]byte) bool
		NumBytes() int
		Clear()
	}
	caches := []struct {
		name  string
		cache receiptCache
	}{
		{"sender", newUnconstrainedCacheToTest(createMockTxBoundsConfig())},
		{"destination", newCrossTxCacheToTest(1, 16, 4096)},
	}
	for _, fixture := range caches {
		t.Run(fixture.name, func(t *testing.T) {
			cache := fixture.cache
			key := []byte("synthetic-paired-cache-entry")
			original := createTx(key, "alice", 1)
			original.Size = 71
			marker := struct{ Label string }{"synthetic-non-authority"}
			_, added := cache.AddTxWithValidationReceipt(original, marker)
			require.True(t, added)
			require.Equal(t, 71, cache.NumBytes())
			_, added = cache.AddTx(original)
			require.False(t, added)
			wrapped, found := cache.GetByTxHash(key)
			require.True(t, found)
			require.Same(t, original, wrapped)
			wrapped, retained, found := cache.GetByTxHashWithValidationReceipt(key)
			require.True(t, found)
			require.Same(t, original, wrapped)
			require.Equal(t, marker, retained)

			pairs := 0
			cache.ForEachTransactionWithValidationReceipt(func(hash []byte, tx *WrappedTransaction, receipt interface{}) {
				pairs++
				require.Equal(t, key, hash)
				require.Same(t, original, tx)
				require.Equal(t, marker, receipt)
			})
			require.Equal(t, 1, pairs)

			require.True(t, cache.RemoveTxByHash(key))
			require.Zero(t, cache.NumBytes())
			wrapped, retained, found = cache.GetByTxHashWithValidationReceipt(key)
			require.False(t, found)
			require.Nil(t, wrapped)
			require.Nil(t, retained)

			ordinary := createTx(key, "alice", 2)
			_, added = cache.AddTx(ordinary)
			require.True(t, added)
			wrapped, retained, found = cache.GetByTxHashWithValidationReceipt(key)
			require.True(t, found)
			require.Same(t, ordinary, wrapped)
			require.Nil(t, retained)
			require.True(t, cache.RemoveTxByHash(key))
			_, added = cache.AddTxWithValidationReceipt(original, marker)
			require.True(t, added)
			cache.Clear()
			wrapped, retained, found = cache.GetByTxHashWithValidationReceipt(key)
			require.False(t, found)
			require.Nil(t, wrapped)
			require.Nil(t, retained)
		})
	}
}
