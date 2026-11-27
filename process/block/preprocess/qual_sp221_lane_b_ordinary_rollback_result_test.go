package preprocess

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/testscommon"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/txcache"
	"github.com/stretchr/testify/require"
)

// The native cleanup has no result; its bookkeeping is the same whether or not
// the rollback fails. The returned error and the rollback status are checked in
// qual_sp221_rollback_status_test.go.
func TestQualSP221OrdinaryBadTransactionRollbackResult(t *testing.T) {
	original := errors.New("local original error")
	rollback := errors.New("local rollback error")
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "successful cleanup"},
		{name: "cleanup error", err: rollback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			label := []byte("local-label")
			txs := &transactions{basePreProcess: &basePreProcess{
				accounts: &stateMock.AccountsStub{
					RevertToSnapshotCalled: func(snapshot int) error {
						require.Equal(t, 7, snapshot)
						calls = append(calls, "restore")
						return tc.err
					},
				},
			}}
			record := func(name string) func([][]byte) {
				return func(labels [][]byte) {
					require.Equal(t, [][]byte{label}, labels)
					calls = append(calls, name)
				}
			}
			previous := gasConsumedInfo{totalGasConsumedInSelfShard: 3}
			builder := &miniBlocksBuilder{
				gasTracker: gasTracker{gasHandler: &testscommon.GasHandlerStub{
					RemoveGasProvidedCalled:  record("provided"),
					RemoveGasRefundedCalled:  record("refunded"),
					RemoveGasPenalizedCalled: record("penalized"),
				}},
				gasConsumedInReceiverShard: map[uint32]uint64{1: 10},
				gasInfo:                    gasConsumedInfo{prevGasConsumedInReceiverShard: 4},
				prevGasInfo:                previous,
			}
			wrapped := &txcache.WrappedTransaction{TxHash: label, ReceiverShardID: 1}

			txs.handleBadTransaction(original, wrapped, nil, builder, 7)

			require.Equal(t, []string{"restore", "provided", "refunded", "penalized"}, calls)
			require.Equal(t, uint64(4), builder.gasConsumedInReceiverShard[1])
			require.Equal(t, previous, builder.gasInfo)
			require.EqualValues(t, 1, builder.stats.numTxsBad)
		})
	}
}
