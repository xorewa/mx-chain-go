package txpool

import (
	"testing"

	"github.com/multiversx/mx-chain-go/txcache"
	"github.com/stretchr/testify/require"
)

// This subset is only the shared ordinary bookkeeping interface.
type ordinaryCacheBookkeepingContract interface {
	GetByTxHash([]byte) (*txcache.WrappedTransaction, bool)
	RemoveTxByHash([]byte) bool
	GetTransactionsPoolForSender(string) []*txcache.WrappedTransaction
	NumBytes() int
	Get([]byte) (interface{}, bool)
	Has([]byte) bool
	Len() int
	Keys() [][]byte
}

var _ ordinaryCacheBookkeepingContract = (txCache)(nil)

func TestQualSP281COrdinaryCacheInterfaceContract(t *testing.T) {
	var cache txCache = txcache.NewDisabledCache()
	var ordinary ordinaryCacheBookkeepingContract = cache
	key := []byte("display-key")
	got, ok := ordinary.Get(key)
	require.Nil(t, got)
	require.False(t, ok)
	require.False(t, ordinary.Has(key))
	tx, ok := ordinary.GetByTxHash(key)
	require.Nil(t, tx)
	require.False(t, ok)
	require.False(t, ordinary.RemoveTxByHash(key))
	require.Equal(t, []*txcache.WrappedTransaction{}, ordinary.GetTransactionsPoolForSender("display-label"))
	require.Zero(t, ordinary.NumBytes())
	require.Zero(t, ordinary.Len())
	require.Equal(t, [][]byte{}, ordinary.Keys())
}
