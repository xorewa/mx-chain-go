package txcache

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP223OrdinaryCrossCacheLifecycle(t *testing.T) {
	cache := newCrossTxCacheToTest(1, 8, 65535)
	first := createTx([]byte("ordinary-first"), "alice", 1)
	second := createTx([]byte("ordinary-second"), "bob", 2)
	_, added := cache.AddTx(first)
	require.True(t, added)
	_, added = cache.AddTx(second)
	require.True(t, added)

	expected := map[string]*WrappedTransaction{
		string(first.TxHash):  first,
		string(second.TxHash): second,
	}
	seenItems := make(map[string]*WrappedTransaction)
	cache.ForEachItem(func(key []byte, item interface{}) {
		tx, ok := item.(*WrappedTransaction)
		require.True(t, ok)
		require.NotContains(t, seenItems, string(key))
		seenItems[string(key)] = tx
	})
	require.Len(t, seenItems, len(expected))
	for key, tx := range expected {
		require.Same(t, tx, seenItems[key])
		found, ok := cache.GetByTxHash([]byte(key))
		require.True(t, ok)
		require.Same(t, tx, found)
	}
	require.True(t, cache.RemoveTxByHash(first.TxHash))
	seenRemaining := make(map[string]*WrappedTransaction)
	cache.ForEachTransaction(func(key []byte, tx *WrappedTransaction) {
		require.NotContains(t, seenRemaining, string(key))
		seenRemaining[string(key)] = tx
	})
	require.Len(t, seenRemaining, 1)
	require.Same(t, second, seenRemaining[string(second.TxHash)])
	cache.Clear()
	require.Zero(t, cache.Len())
	cache.ForEachItem(func(_ []byte, _ interface{}) {
		t.Fatal("ordinary cache iteration after clear returned an item")
	})
}

func TestQualSP223OrdinaryHashMapBulkLifecycle(t *testing.T) {
	txMap := newTxByHashMap(1)
	first := createTx([]byte("ordinary-first"), "alice", 1)
	second := createTx([]byte("ordinary-second"), "bob", 2)
	first.Size = 17
	second.Size = 23
	require.True(t, txMap.addTx(first))
	require.True(t, txMap.addTx(second))
	require.False(t, txMap.addTx(first))
	require.Equal(t, int64(2), txMap.counter.Get())
	require.Equal(t, int64(40), txMap.numBytes.Get())

	found := txMap.GetTxsBulk([][]byte{second.TxHash, first.TxHash})
	require.Len(t, found, 2)
	require.Same(t, second, found[0])
	require.Same(t, first, found[1])
	require.Equal(t, uint32(1), txMap.RemoveTxsBulk([][]byte{first.TxHash}))
	require.Equal(t, int64(1), txMap.counter.Get())
	require.Equal(t, int64(23), txMap.numBytes.Get())
	remaining := txMap.GetTxsBulk([][]byte{second.TxHash})
	require.Len(t, remaining, 1)
	require.Same(t, second, remaining[0])
	require.True(t, txMap.addTx(first))
	require.Equal(t, int64(2), txMap.counter.Get())
	require.Equal(t, int64(40), txMap.numBytes.Get())
}

func TestQualSP223OrdinaryCacheViewPreservesIdentity(t *testing.T) {
	cache := newUnconstrainedCacheToTest(createMockTxBoundsConfig())
	tx := createTx([]byte("ordinary-view"), "alice", 1)
	ok, added := cache.AddTx(tx)
	require.True(t, ok)
	require.True(t, added)

	found, observation, ok := cache.GetByTxHashWithValidationReceipt(tx.TxHash)
	require.True(t, ok)
	require.Same(t, tx, found)
	require.Nil(t, observation)

	visits := 0
	cache.ForEachTransactionWithValidationReceipt(func(key []byte, item *WrappedTransaction, observation interface{}) {
		visits++
		require.Equal(t, tx.TxHash, key)
		require.Same(t, tx, item)
		require.Nil(t, observation)
	})
	require.Equal(t, 1, visits)
	require.Equal(t, 1, cache.Len())
}

func TestQualSP223OrdinaryDisabledCacheRemainsEmpty(t *testing.T) {
	cache := NewDisabledCache()
	tx := createTx([]byte("ordinary-disabled"), "alice", 1)
	ok, added := cache.AddTxWithValidationReceipt(tx, nil)
	require.False(t, ok)
	require.False(t, added)

	item, observation, ok := cache.GetByTxHashWithValidationReceipt(tx.TxHash)
	require.False(t, ok)
	require.Nil(t, item)
	require.Nil(t, observation)
	require.Zero(t, cache.Len())
	require.Zero(t, cache.NumBytes())
	cache.ForEachTransactionWithValidationReceipt(func(_ []byte, _ *WrappedTransaction, _ interface{}) {
		t.Fatal("disabled cache returned an item")
	})
}
