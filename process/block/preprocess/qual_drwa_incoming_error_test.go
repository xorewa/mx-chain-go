package preprocess

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/cache"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
)

// DS02-M6/M7, P-05 propagation only. These synthetic coordinates and inherited
// constructor defaults are experimental fixtures, replace before testnet admission.
// Canonical account/result/gas reconstruction and admission are not exercised.
func TestQualDRWAIncomingPreprocessorError(t *testing.T) {
	for _, kind := range []string{"transaction", "SCR"} {
		for _, partial := range []bool{false, true} {
			for _, resume := range []int{-1, 0} {
				for _, position := range []int{1, 2} {
					for _, shape := range []string{"marker", "wrapped", "joined", "ordinary", "success"} {
						t.Run(fmt.Sprintf("%s/partial_%t/resume_%d/position_%d/%s", kind, partial, resume, position, shape), func(t *testing.T) {
							failure := vm.ErrDRWAExecution
							rollback := errors.New("experimental rollback failure")
							switch shape {
							case "wrapped":
								failure = fmt.Errorf("experimental context: %w", failure)
							case "joined":
								failure = errors.Join(failure, rollback, process.ErrFailedTransaction)
							case "ordinary":
								failure = errors.New(failure.Error())
							case "success":
								failure = nil
							}
							fatal := shape != "ordinary" && shape != "success"
							args, mb, entries := qualDRWASCRReceiverArgs(t)
							fault, calls, effects := false, 0, 0
							observe := func() {
								if fault {
									effects++
								}
							}
							accounts := &stateMock.AccountsStub{RevertToSnapshotCalled: func(int) error { observe(); return rollback }}
							gas := &testscommon.GasHandlerStub{RestoreGasSinceLastResetCalled: func([]byte) { observe() }, SetGasProvidedCalled: func(uint64, []byte) { observe() }}
							info := &testscommon.PreProcessorExecutionInfoHandlerMock{RevertProcessedTxsResultsCalled: func([][]byte, []byte) { observe() }}
							size := &testscommon.BlockSizeComputationStub{AddNumTxsCalled: func(int) { observe() }, AddNumMiniBlocksCalled: func(int) { observe() }}
							execute := func() (vmcommon.ReturnCode, error) {
								calls++
								if calls == position && failure != nil {
									fault = true
									return vmcommon.UserError, failure
								}
								return vmcommon.Ok, nil
							}
							var receiver process.PreProcessor
							var err error
							if kind == "SCR" {
								args.Accounts, args.GasHandler, args.BlockSizeComputation = accounts, gas, size
								args.ScrProcessor = &testscommon.TxProcessorMock{ProcessSmartContractResultCalled: func(*smartContractResult.SmartContractResult) (vmcommon.ReturnCode, error) { return execute() }}
								receiver, err = NewSmartContractResultPreprocessor(args)
							} else {
								mb.Type = block.TxBlock
								mb.SenderShardID = 0
								for _, hash := range mb.TxHashes {
									entries[string(hash)] = &transaction.Transaction{Value: big.NewInt(0)}
								}
								ta := createDefaultTransactionsProcessorArgs()
								ta.Accounts, ta.GasHandler, ta.BlockSizeComputation = accounts, gas, size
								ta.DataPool = &testscommon.ShardedDataStub{ShardDataStoreCalled: func(string) storage.Cacher {
									return &cache.CacherStub{PeekCalled: func(hash []byte) (interface{}, bool) { v, ok := entries[string(hash)]; return v, ok }}
								}}
								ta.TxProcessor = &testscommon.TxProcessorMock{ProcessTransactionCalled: func(*transaction.Transaction) (vmcommon.ReturnCode, error) { return execute() }}
								receiver, err = NewTransactionPreprocessor(ta)
							}
							require.NoError(t, err)
							undo, last, revert, err := receiver.ProcessMiniBlock(mb, haveTimeTrue, haveAdditionalTimeFalse, false, partial, resume, info, process.GasProcessingPolicy{})
							if fatal {
								require.Same(t, failure, err)
								require.ErrorIs(t, err, vm.ErrDRWAExecution)
								if shape == "joined" {
									require.ErrorIs(t, err, rollback)
								}
								require.Equal(t, position, calls)
								require.Zero(t, effects, "no ordinary revert/result/gas/size continuation after fatal fault")
								require.Equal(t, resume, last, "withhold tentative prefix progress")
								require.False(t, revert, "whole candidate recovery belongs to outer owner")
								require.Nil(t, undo)
								require.Empty(t, receiver.GetAllCurrentUsedTxs(), "do not cache failed/unattempted suffix")
							} else if failure != nil {
								require.Same(t, failure, err)
								require.Equal(t, position, calls)
								require.Equal(t, resume+position-1, last)
								require.Equal(t, !partial, revert)
								require.Positive(t, effects)
								if partial {
									require.Len(t, receiver.GetAllCurrentUsedTxs(), 3)
								} else {
									require.Empty(t, receiver.GetAllCurrentUsedTxs())
								}
							} else {
								require.NoError(t, err)
								require.Equal(t, len(mb.TxHashes)-resume-1, calls)
								require.Equal(t, 2, last)
								require.False(t, revert)
								require.Len(t, receiver.GetAllCurrentUsedTxs(), 3)
							}
						})
					}
				}
			}
		}
	}
}
