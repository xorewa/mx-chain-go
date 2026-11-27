package coordinator

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/testscommon"
	commonMock "github.com/multiversx/mx-chain-go/testscommon/common"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/stretchr/testify/require"
)

// The native cleanup has no result; its bookkeeping is the same whether or not
// the rollback fails. The returned error and the rollback status are checked in
// qual_sp221_rollback_status_test.go.
func TestQualSP221OrdinaryCoordinatorCleanupResult(t *testing.T) {
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
			coordinator := &transactionCoordinator{
				accounts: &stateMock.AccountsStub{
					RevertToSnapshotCalled: func(snapshot int) error {
						require.Equal(t, 7, snapshot)
						calls = append(calls, "restore")
						return tc.err
					},
				},
				gasHandler: &testscommon.GasHandlerStub{
					RestoreGasSinceLastResetCalled: func(key []byte) {
						require.Equal(t, label, key)
						calls = append(calls, "gas")
					},
				},
				txExecutionOrderHandler: &commonMock.TxExecutionOrderHandlerStub{
					RemoveMultipleCalled: func(hashes [][]byte) {
						require.Empty(t, hashes)
						calls = append(calls, "order")
					},
				},
			}
			coordinator.handleProcessTransactionError(7, label, nil)
			require.Equal(t, []string{"gas", "restore", "order"}, calls)
		})
	}
}

func TestQualSP221OrdinaryCoordinatorCleanupBookkeeping(t *testing.T) {
	label := []byte("local-label")
	items := [][]byte{[]byte("one"), []byte("two")}
	var calls []string
	coordinator := &transactionCoordinator{
		accounts: &stateMock.AccountsStub{
			RevertToSnapshotCalled: func(snapshot int) error {
				require.Equal(t, 7, snapshot)
				calls = append(calls, "restore")
				return nil
			},
		},
		gasHandler: &testscommon.GasHandlerStub{
			RestoreGasSinceLastResetCalled: func(key []byte) {
				require.Equal(t, label, key)
				calls = append(calls, "gas")
			},
		},
		feeHandler: &mock.FeeAccumulatorStub{
			RevertFeesCalled: func(labels [][]byte) {
				require.Equal(t, items, labels)
				calls = append(calls, "fees")
			},
		},
		txExecutionOrderHandler: &commonMock.TxExecutionOrderHandlerStub{
			RemoveMultipleCalled: func(labels [][]byte) {
				require.Equal(t, items, labels)
				calls = append(calls, "order")
			},
		},
	}

	coordinator.handleProcessTransactionError(7, label, items)

	require.Equal(t, []string{"gas", "restore", "fees", "order", "order"}, calls)
}
