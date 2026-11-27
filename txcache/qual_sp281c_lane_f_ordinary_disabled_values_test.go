package txcache

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryDisabledCacheReturnValues(t *testing.T) {
	cache := NewDisabledCache()
	key := []byte("display-key")
	wrapped := &WrappedTransaction{TxHash: key}
	value := "display-value"

	ok, added := cache.AddTx(wrapped)
	require.False(t, ok)
	require.False(t, added)
	gotTx, ok := cache.GetByTxHash(key)
	require.Nil(t, gotTx)
	require.False(t, ok)
	require.False(t, cache.RemoveTxByHash(key))
	selected, count := cache.SelectTransactions(1, 1)
	require.Equal(t, []*WrappedTransaction{}, selected)
	require.Zero(t, count)
	require.Equal(t, []*WrappedTransaction{}, cache.GetTransactionsPoolForSender("display-label"))

	require.False(t, cache.Put(key, value, len(value)))
	got, ok := cache.Get(key)
	require.Nil(t, got)
	require.False(t, ok)
	got, ok = cache.Peek(key)
	require.Nil(t, got)
	require.False(t, ok)
	require.False(t, cache.Has(key))
	has, added := cache.HasOrAdd(key, value, len(value))
	require.False(t, has)
	require.False(t, added)
	cache.Remove(key)
	cache.Clear()
	require.Equal(t, [][]byte{}, cache.Keys())
	require.Zero(t, cache.Len())
	require.Zero(t, cache.SizeInBytesContained())
	require.Zero(t, cache.NumBytes())
	require.Zero(t, cache.MaxSize())

	called := false
	cache.ForEachTransaction(func([]byte, *WrappedTransaction) { called = true })
	cache.RegisterHandler(func([]byte, interface{}) { called = true }, "display-handler")
	cache.UnRegisterHandler("display-handler")
	require.False(t, called)
	require.False(t, cache.IsInterfaceNil())
	require.NoError(t, cache.Close())
}
