package txpool

import (
	"testing"

	native "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/stretchr/testify/require"
)

// Compare ordinary cache bookkeeping on the native insertion API and the
// receipt-aware API. The fixture has no signed receipt or regulated request.
func TestQualCoverageItem17NominalOrdinaryInsertionParity(t *testing.T) {
	for _, route := range []string{"0", "1_0"} {
		t.Run(route, func(t *testing.T) {
			baselinePool, err := newTxPoolToTest()
			require.NoError(t, err)
			baseline := baselinePool.(*shardedTxPool)
			t.Cleanup(baseline.Clear)
			ordinaryPool, err := newTxPoolToTest()
			require.NoError(t, err)
			ordinary := ordinaryPool.(*shardedTxPool)
			t.Cleanup(ordinary.Clear)
			require.NoError(t, ordinary.ConfigureNativeValidationSource(&native.NativeValidationSource{
				EnableEpochsHandler: &enableEpochsHandlerMock.EnableEpochsHandlerStub{},
			}))
			key := []byte("ordinary-fixture-key")
			tx := createTx("alice", 42)
			const fixtureSize = 41
			baseline.AddData(key, tx, fixtureSize, route)
			ordinary.AddDataWithNativeValidationReceipt(key, tx, fixtureSize, route, nil)
			want := baseline.getTxCache(route)
			got := ordinary.getTxCache(route)
			wantEntry, found := want.GetByTxHash(key)
			require.True(t, found)
			gotEntry, found := got.GetByTxHash(key)
			require.True(t, found)
			require.Equal(t, wantEntry.Size, gotEntry.Size)
			require.Equal(t, int64(fixtureSize), gotEntry.Size)
			require.Equal(t, wantEntry.TxHash, gotEntry.TxHash)
			require.Equal(t, wantEntry.SenderShardID, gotEntry.SenderShardID)
			require.Equal(t, wantEntry.ReceiverShardID, gotEntry.ReceiverShardID)
			require.Same(t, wantEntry.Tx, gotEntry.Tx)
			require.Equal(t, want.NumBytes(), got.NumBytes())
			require.Equal(t, want.Len(), got.Len())
			require.Equal(t, 1, got.Len())
		})
	}
}
