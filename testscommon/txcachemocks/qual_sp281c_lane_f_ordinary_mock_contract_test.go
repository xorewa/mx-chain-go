package txcachemocks

import (
	"testing"

	"github.com/multiversx/mx-chain-go/txcache"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryCacheMockDefaults(t *testing.T) {
	cache := NewTxCacheStub()
	key := []byte("display-key")
	value := "display-value"
	wrapped := &txcache.WrappedTransaction{TxHash: key}
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
	require.Zero(t, cache.MaxSize())
	ok, added = cache.AddTx(wrapped)
	require.False(t, ok)
	require.False(t, added)
	gotTx, ok := cache.GetByTxHash(key)
	require.Nil(t, gotTx)
	require.False(t, ok)
	require.False(t, cache.RemoveTxByHash(key))
	require.Zero(t, cache.NumBytes())
	require.Nil(t, cache.GetTransactionsPoolForSender("display-label"))
	called := false
	cache.RegisterHandler(func([]byte, interface{}) { called = true }, "display-handler")
	cache.UnRegisterHandler("display-handler")
	require.False(t, called)
	require.False(t, cache.IsInterfaceNil())
	require.NoError(t, cache.Close())
}

func TestQualSP281COrdinaryCacheMockForwarding(t *testing.T) {
	key := []byte("display-key")
	value := "display-value"
	wrapped := &txcache.WrappedTransaction{TxHash: key}
	calls := make(map[string]int)
	checkKey := func(name string, got []byte) { require.Equal(t, key, got); calls[name]++ }
	checkValue := func(name string, gotKey []byte, gotValue interface{}, size int) {
		checkKey(name, gotKey)
		require.Equal(t, value, gotValue)
		require.Equal(t, len(value), size)
	}
	cache := NewTxCacheStub()
	cache.PutCalled = func(k []byte, v interface{}, size int) bool { checkValue("put", k, v, size); return true }
	cache.GetCalled = func(k []byte) (interface{}, bool) { checkKey("get", k); return value, true }
	cache.PeekCalled = func(k []byte) (interface{}, bool) { checkKey("peek", k); return value, true }
	cache.HasCalled = func(k []byte) bool { checkKey("has", k); return true }
	cache.HasOrAddCalled = func(k []byte, v interface{}, size int) (bool, bool) {
		checkValue("hasOrAdd", k, v, size)
		return true, false
	}
	cache.RemoveCalled = func(k []byte) { checkKey("remove", k) }
	cache.ClearCalled = func() { calls["clear"]++ }
	cache.KeysCalled = func() [][]byte { calls["keys"]++; return [][]byte{key} }
	cache.LenCalled = func() int { calls["len"]++; return 1 }
	cache.MaxSizeCalled = func() int { calls["max"]++; return 2 }
	cache.AddTxCalled = func(tx *txcache.WrappedTransaction) (bool, bool) {
		require.Same(t, wrapped, tx)
		calls["add"]++
		return true, true
	}
	cache.GetByTxHashCalled = func(k []byte) (*txcache.WrappedTransaction, bool) { checkKey("getTx", k); return wrapped, true }
	cache.RemoveTxByHashCalled = func(k []byte) bool { checkKey("removeTx", k); return true }
	cache.NumBytesCalled = func() int { calls["bytes"]++; return len(value) }
	cache.GetTransactionsPoolForSenderCalled = func(s string) []*txcache.WrappedTransaction {
		require.Equal(t, "display-label", s)
		calls["sender"]++
		return []*txcache.WrappedTransaction{wrapped}
	}
	cache.RegisterHandlerCalled = func(handler func([]byte, interface{})) { calls["register"]++; handler(key, value) }
	cache.UnRegisterHandlerCalled = func(s string) { require.Equal(t, "display-handler", s); calls["unregister"]++ }
	cache.CloseCalled = func() error { calls["close"]++; return nil }

	require.True(t, cache.Put(key, value, len(value)))
	got, ok := cache.Get(key)
	require.Equal(t, value, got)
	require.True(t, ok)
	got, ok = cache.Peek(key)
	require.Equal(t, value, got)
	require.True(t, ok)
	require.True(t, cache.Has(key))
	has, added := cache.HasOrAdd(key, value, len(value))
	require.True(t, has)
	require.False(t, added)
	cache.Remove(key)
	cache.Clear()
	require.Equal(t, [][]byte{key}, cache.Keys())
	require.Equal(t, 1, cache.Len())
	require.Equal(t, 2, cache.MaxSize())
	ok, added = cache.AddTx(wrapped)
	require.True(t, ok)
	require.True(t, added)
	gotTx, ok := cache.GetByTxHash(key)
	require.Same(t, wrapped, gotTx)
	require.True(t, ok)
	require.True(t, cache.RemoveTxByHash(key))
	require.Equal(t, len(value), cache.NumBytes())
	require.Equal(t, []*txcache.WrappedTransaction{wrapped}, cache.GetTransactionsPoolForSender("display-label"))
	cache.RegisterHandler(func(k []byte, v interface{}) { checkKey("handler", k); require.Equal(t, value, v) }, "display-handler")
	cache.UnRegisterHandler("display-handler")
	require.NoError(t, cache.Close())
	want := []string{"put", "get", "peek", "has", "hasOrAdd", "remove", "clear", "keys", "len", "max", "add", "getTx", "removeTx", "bytes", "sender", "register", "handler", "unregister", "close"}
	require.Len(t, calls, len(want))
	for _, name := range want {
		require.Equal(t, 1, calls[name], name)
	}
}
