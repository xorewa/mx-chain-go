package preprocess

import (
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/testscommon"
	commonMock "github.com/multiversx/mx-chain-go/testscommon/common"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/stretchr/testify/require"
	"testing"
)

// Observes P-05's native cleanup boundary. Its void return does not convey a
// rollback failure. This is not a claim about outer block commit or recovery.
func TestQualDRWARollbackPreprocessCleanup(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{{"success", nil}, {"failure", errors.New("rollback failed")}, {"closing", core.ErrDBIsClosed}} {
		t.Run(tc.name, func(t *testing.T) {
			events := []string{}
			txHash := []byte("tx")
			mbHash := []byte("mb")
			bpp := &basePreProcess{
				gasTracker: gasTracker{gasHandler: &testscommon.GasHandlerStub{RestoreGasSinceLastResetCalled: func(key []byte) { require.Equal(t, txHash, key); events = append(events, "gas") }}},
				accounts: &stateMock.AccountsStub{
					JournalLenCalled: func() int { events = append(events, "snapshot"); return 7 },
					RevertToSnapshotCalled: func(snapshot int) error {
						require.Equal(t, 7, snapshot)
						events = append(events, "revert")
						return tc.err
					},
				},
				txExecutionOrderHandler: &commonMock.TxExecutionOrderHandlerStub{RemoveCalled: func(key []byte) { require.Equal(t, txHash, key); events = append(events, "order") }},
			}
			info := &testscommon.PreProcessorExecutionInfoHandlerMock{
				InitProcessedTxsResultsCalled: func(key, parent []byte) {
					require.Equal(t, txHash, key)
					require.Equal(t, mbHash, parent)
					events = append(events, "init")
				},
				RevertProcessedTxsResultsCalled: func(hashes [][]byte, key []byte) {
					require.Equal(t, [][]byte{txHash}, hashes)
					require.Equal(t, txHash, key)
					events = append(events, "results")
				},
			}
			snapshot := bpp.handleProcessTransactionInit(info, txHash, mbHash)
			require.Equal(t, 7, snapshot)
			bpp.handleProcessTransactionError(info, snapshot, txHash)
			require.Equal(t, []string{"snapshot", "init", "gas", "revert", "results", "order"}, events, "native cleanup continues after rollback error")
		})
	}
}
