package preprocess

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/testscommon/txcachemocks"
	"github.com/multiversx/mx-chain-go/testscommon/txcachestubs"
	"github.com/multiversx/mx-chain-go/txcache"
	"github.com/multiversx/mx-chain-go/vm"
)

// Qualification-only composition of existing cache stubs, not a product seam.
type qualDRWAOutgoingCache struct {
	*txcachemocks.TxCacheMock
	*txcachestubs.TxCacheStub
}

func (c *qualDRWAOutgoingCache) IsInterfaceNil() bool { return c == nil }

// DS02-M6/M7, Part A P-05: an internal fatal error must escape before native
// bad-transaction recovery or another transaction. This exercises propagation,
// not canonical restoration, liveness or authenticated classifier admission.
// All dependency defaults and synthetic coordinates below are experimental
// component fixtures; replace or confirm before testnet admission (R7).
func TestQualDRWAOutgoingPreprocessorError(t *testing.T) {
	rollback := errors.New("experimental rollback failure")
	for _, route := range []string{"selection", "publicV1", "publicV2", "builderV1", "builderV2", "scheduled", "scheduledWrapper", "transactionV1", "transactionV2", "verification"} {
		for _, shape := range []struct {
			name  string
			err   error
			fatal bool
		}{
			{"marker", vm.ErrDRWAExecution, true},
			{"wrapped", fmt.Errorf("experimental context: %w", vm.ErrDRWAExecution), true},
			{"joined", errors.Join(vm.ErrDRWAExecution, rollback, process.ErrFailedTransaction, process.ErrTransactionNotExecutable), true},
			{"ordinarySameMessage", errors.New(vm.ErrDRWAExecution.Error()), false},
			{"success", nil, false},
		} {
			t.Run(route+"/"+shape.name, func(t *testing.T) {
				p := createTransactionPreprocessor()
				p.balanceComputation = &testscommon.BalanceComputationStub{}
				p.enableEpochsHandler = &enableEpochsHandlerMock.EnableEpochsHandlerStub{
					IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
						return flag == common.ScheduledMiniBlocksFlag && route != "publicV1"
					},
				}
				calls, reverts, removals := 0, 0, 0
				p.accounts = &stateMock.AccountsStub{RevertToSnapshotCalled: func(int) error { reverts++; return rollback }}
				p.gasHandler = &mock.GasHandlerMock{
					RemoveGasProvidedCalled:            func([][]byte) { removals++ },
					RemoveGasProvidedAsScheduledCalled: func([][]byte) { removals++ },
				}
				p.txProcessor = &testscommon.TxProcessorMock{
					ProcessTransactionCalled: func(*transaction.Transaction) (vmcommon.ReturnCode, error) {
						calls++
						return vmcommon.UserError, shape.err
					},
					VerifyTransactionCalled: func(*transaction.Transaction) error { calls++; return shape.err },
				}
				p.txTypeHandler = &testscommon.TxTypeHandlerMock{ComputeTransactionTypeCalled: func(_ data.TransactionHandler) (process.TransactionType, process.TransactionType, bool) {
					return process.MoveBalance, process.SCInvoking, false
				}}
				sorted := []*txcache.WrappedTransaction{
					{Tx: &transaction.Transaction{SndAddr: []byte("experimental sender A"), Value: big.NewInt(0)}, TxHash: []byte("experimental hash A")},
					{Tx: &transaction.Transaction{SndAddr: []byte("experimental sender B"), Value: big.NewInt(0)}, TxHash: []byte("experimental hash B")},
				}
				cache := &qualDRWAOutgoingCache{TxCacheMock: &txcachemocks.TxCacheMock{}, TxCacheStub: &txcachestubs.TxCacheStub{
					SelectTransactionsCalled: func(txcache.SelectionSession, common.TxSelectionOptions, uint64) ([]*txcache.WrappedTransaction, uint64, error) {
						if route == "selection" {
							return sorted, 0, shape.err
						}
						return sorted, 0, nil
					},
				}}
				p.txPool = &testscommon.ShardedDataStub{ShardDataStoreCalled: func(string) storage.Cacher { return cache }, RemoveDataCalled: func([]byte, string) { removals++ }}
				var mbs block.MiniBlockSlice
				var remaining []*txcache.WrappedTransaction
				var scs map[string]struct{}
				var err error
				switch route {
				case "selection", "publicV1", "publicV2":
					mbs, err = p.CreateAndProcessMiniBlocks(haveTimeTrue, []byte("experimental randomness"))
				case "builderV1":
					mbs, remaining, err = p.createAndProcessMiniBlocksFromMeV1(haveTimeTrue, func(uint32) bool { return false }, func(int, int) bool { return false }, sorted)
				case "builderV2":
					mbs, remaining, scs, err = p.createAndProcessMiniBlocksFromMeV2(haveTimeTrue, func(uint32) bool { return false }, func(int, int) bool { return false }, sorted)
				case "scheduled":
					mbs, err = p.createScheduledMiniBlocks(haveTimeTrue, haveAdditionalTimeFalse, func(uint32) bool { return false }, func(int, int) bool { return false }, sorted, make(map[string]struct{}))
				case "scheduledWrapper":
					mbs, err = p.createAndProcessScheduledMiniBlocksFromMeAsProposer(haveTimeTrue, haveAdditionalTimeFalse, sorted, make(map[string]struct{}))
				case "transactionV1":
					mb := &miniBlocksBuilder{accounts: p.accounts, gasTracker: p.gasTracker, gasConsumedInReceiverShard: make(map[uint32]uint64), blockSizeComputation: p.blockSizeComputation, enableEpochsHandler: p.enableEpochsHandler, enableRoundsHandler: p.enableRoundsHandler}
					err = p.processMiniBlockBuilderTx(mb, sorted[0], sorted[0].Tx.(*transaction.Transaction))
				case "transactionV2":
					_, err = p.processTransaction(sorted[0].Tx.(*transaction.Transaction), sorted[0].TxHash, 0, 0, p.initCreateAndProcessMiniBlocks())
				case "verification":
					err = p.verifyTransaction(sorted[0].Tx.(*transaction.Transaction), sorted[0].TxHash, 0, 0, p.initCreateScheduledMiniBlocks())
				}
				if shape.fatal {
					require.Same(t, shape.err, err)
					require.ErrorIs(t, err, vm.ErrDRWAExecution)
					if shape.name == "joined" {
						require.ErrorIs(t, err, rollback)
					}
					require.Nil(t, mbs)
					require.Nil(t, remaining)
					require.Nil(t, scs)
					require.Zero(t, reverts, "ordinary per-transaction revert cannot contain fatal candidate failure")
					require.Zero(t, removals, "do not reclassify fatal candidate as an ordinary bad transaction")
					if route == "selection" {
						require.Zero(t, calls)
					} else {
						require.Equal(t, 1, calls)
					}
				} else if route == "transactionV1" || route == "transactionV2" || route == "verification" {
					require.Equal(t, shape.err, err)
					require.Equal(t, 1, calls)
					if shape.err != nil && route != "verification" {
						require.Equal(t, 1, reverts)
					}
				} else {
					require.NoError(t, err)
					if route == "selection" && shape.err != nil {
						require.Zero(t, calls)
					} else {
						require.Equal(t, 2, calls)
					}
				}
			})
		}
	}
}
