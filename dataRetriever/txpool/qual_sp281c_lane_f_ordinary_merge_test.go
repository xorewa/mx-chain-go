package txpool

import (
	"testing"

	"github.com/multiversx/mx-chain-go/txcache"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CLaneFMergeOrdinaryShardStores(t *testing.T) {
	for _, test := range []struct {
		name            string
		destination     string
		destinationRead string
	}{
		{name: "cross shard destination", destination: "2_0", destinationRead: "2_0"},
		{name: "local shard union destination", destination: "0_2", destinationRead: "0_3"},
	} {
		t.Run(test.name, func(t *testing.T) {
			const source = "1_0"
			movedKey, residentKey := []byte("moved-key"), []byte("resident-key")
			moved, resident := createTx("alice", 42), createTx("bob", 17)

			pool, err := newTxPoolToTest()
			require.NoError(t, err)
			p := pool.(*shardedTxPool)
			t.Cleanup(p.Clear)
			p.AddData(movedKey, moved, 41, source)
			p.AddData(residentKey, resident, 29, test.destinationRead)
			movedBefore, found := p.getTxCache(source).GetByTxHash(movedKey)
			require.True(t, found)
			destination := p.getTxCache(test.destinationRead)

			var notifications int
			p.RegisterOnAdded(func(key []byte, value interface{}) {
				notifications++
				require.Equal(t, movedKey, key)
				require.Same(t, movedBefore, value.(*txcache.WrappedTransaction))
			})

			p.MergeShardStores(source, test.destination)

			require.NotContains(t, p.backingMap, source)
			require.ElementsMatch(t, [][]byte{movedKey, residentKey}, destination.Keys())
			require.Equal(t, 70, destination.NumBytes())
			require.Equal(t, 1, notifications)

			entry, receipt, found := destination.GetByTxHashWithValidationReceipt(movedKey)
			require.True(t, found)
			require.Nil(t, receipt)
			require.Same(t, movedBefore, entry)
			require.Same(t, moved, entry.Tx)
			require.Equal(t, movedKey, entry.TxHash)
			require.Equal(t, uint32(1), entry.SenderShardID)
			require.Zero(t, entry.ReceiverShardID)
			require.Equal(t, int64(41), entry.Size)

			entry, receipt, found = destination.GetByTxHashWithValidationReceipt(residentKey)
			require.True(t, found)
			require.Nil(t, receipt)
			require.Same(t, resident, entry.Tx)
			require.Equal(t, int64(29), entry.Size)
		})
	}
}
