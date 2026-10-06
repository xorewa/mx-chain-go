package preprocess

import (
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/testscommon"
	commonMock "github.com/multiversx/mx-chain-go/testscommon/common"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/txcache"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

// Observes P-05's native cleanup boundary. Its void return does not convey a
// rollback failure upstream; the descendant returns it after preserving cleanup.
// This is not a claim about outer block commit or recovery.
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
			cleanupErr := bpp.handleProcessTransactionError(info, snapshot, txHash)
			if tc.err == nil {
				require.NoError(t, cleanupErr)
			} else {
				require.ErrorIs(t, cleanupErr, tc.err)
			}
			require.Equal(t, []string{"snapshot", "init", "gas", "revert", "results", "order"}, events, "native cleanup continues after rollback error")
		})
	}
}

// The AccountsDB latch is separately exercised with a native trie in state.
// These caller probes show why that latch alone cannot stop the outer loops:
// builders otherwise swallow the error, and partial execution suppresses undo.
func TestQualDRWARollbackOuterTransactionProbes(t *testing.T) {
	for _, path := range []string{"builder_v1", "builder_v2", "partial_miniblock"} {
		t.Run(path, func(t *testing.T) {
			primary, rollback := errors.New("transaction failed"), errors.New("rollback failed")
			txs := createTransactionPreprocessor()
			txs.gasHandler = &mock.GasHandlerMock{
				ComputeGasProvidedByTxCalled:        func(uint32, uint32, data.TransactionHandler) (uint64, uint64, error) { return 0, 0, nil },
				TotalGasProvidedCalled:              func() uint64 { return 0 },
				TotalGasProvidedAsScheduledCalled:   func() uint64 { return 0 },
				TotalGasProvidedWithScheduledCalled: func() uint64 { return 0 },
				TotalGasRefundedCalled:              func() uint64 { return 0 },
				TotalGasPenalizedCalled:             func() uint64 { return 0 },
				SetGasProvidedCalled:                func(uint64, []byte) {},
				RemoveGasProvidedCalled:             func([][]byte) {},
				RemoveGasRefundedCalled:             func([][]byte) {},
				RemoveGasPenalizedCalled:            func([][]byte) {},
				RestoreGasSinceLastResetCalled:      func([]byte) {},
			}
			txs.txExecutionOrderHandler = &commonMock.TxExecutionOrderHandlerStub{AddCalled: func([]byte) {}, RemoveCalled: func([]byte) {}}
			txs.balanceComputation = &testscommon.BalanceComputationStub{
				IsAddressSetCalled:            func([]byte) bool { return true },
				AddressHasEnoughBalanceCalled: func([]byte, *big.Int) bool { return true },
				SetBalanceToAddressCalled:     func([]byte, *big.Int) {},
			}
			txs.blockSizeComputation = &testscommon.BlockSizeComputationStub{
				IsMaxBlockSizeReachedCalled:                func(int, int) bool { return false },
				IsMaxBlockSizeWithoutThrottleReachedCalled: func(int, int) bool { return false },
				AddNumMiniBlocksCalled:                     func(int) {}, AddNumTxsCalled: func(int) {},
			}
			txs.enableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).IsFlagEnabledCalled = func(core.EnableEpochFlag) bool { return false }
			txs.enableRoundsHandler.(*testscommon.EnableRoundsHandlerStub).IsFlagEnabledCalled = func(common.EnableRoundFlag) bool { return false }
			txs.accounts = &stateMock.AccountsStub{
				JournalLenCalled:       func() int { return 1 },
				RevertToSnapshotCalled: func(int) error { return rollback },
				RootHashCalled:         func() ([]byte, error) { return nil, rollback },
				GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
					return stateMock.NewAccountWrapMock(address), nil
				},
			}
			calls := 0
			txs.txProcessor = &testscommon.TxProcessorMock{ProcessTransactionCalled: func(*transaction.Transaction) (vmcommon.ReturnCode, error) {
				calls++
				return vmcommon.ExecutionFailed, primary
			}}
			var err error
			if path == "partial_miniblock" {
				info := &testscommon.PreProcessorExecutionInfoHandlerMock{
					GetNumOfCrossInterMbsAndTxsCalled: func() (int, int) { return 0, 0 },
					InitProcessedTxsResultsCalled:     func([]byte, []byte) {},
					RevertProcessedTxsResultsCalled:   func([][]byte, []byte) {},
				}
				var shouldRevert bool
				_, _, shouldRevert, err = txs.ProcessMiniBlock(&block.MiniBlock{Type: block.TxBlock, TxHashes: [][]byte{[]byte("tx2_hash")}}, haveTimeTrue, haveAdditionalTimeFalse, false, true, -1, info, process.GasProcessingPolicy{})
				require.True(t, shouldRevert, "a failed undo cannot become a partial-success continuation")
			} else {
				txsToProcess := []*txcache.WrappedTransaction{
					{Tx: &transaction.Transaction{Nonce: 1}, TxHash: []byte("first")},
					{Tx: &transaction.Transaction{Nonce: 2}, TxHash: []byte("later")},
				}
				if path == "builder_v1" {
					_, _, err = txs.createAndProcessMiniBlocksFromMeV1(haveTimeTrue, func(uint32) bool { return false }, func(int, int) bool { return false }, txsToProcess)
				} else {
					_, _, _, err = txs.createAndProcessMiniBlocksFromMeV2(haveTimeTrue, func(uint32) bool { return false }, func(int, int) bool { return false }, txsToProcess)
				}
			}
			require.ErrorIs(t, err, primary)
			require.ErrorIs(t, err, rollback)
			require.Equal(t, 1, calls, "no later transaction is executed after failed undo")
		})
	}
}
