package coordinator

import (
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/block/processedMb"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/testscommon"
	commonMock "github.com/multiversx/mx-chain-go/testscommon/common"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/preprocMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

// The real coordinator is exercised with a faulting preprocessor/account store.
// No final block commit, persistent trie restoration or network is exercised.
func TestQualDRWARollbackMiniBlockErrorIdentity(t *testing.T) {
	for _, tc := range []struct {
		name              string
		initial, rollback error
		revert            bool
	}{
		{"success", nil, nil, false},
		{"initial_failure", errors.New("transaction failed"), nil, true},
		{"both_fail", errors.New("transaction failed"), errors.New("rollback failed"), true},
		{"partial_execution", errors.New("time exhausted"), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := []string{}
			hash := []byte("mb")
			txHash := []byte("tx")
			c := &transactionCoordinator{
				accounts: &stateMock.AccountsStub{
					JournalLenCalled: func() int { events = append(events, "snapshot"); return 7 },
					RevertToSnapshotCalled: func(snapshot int) error {
						require.Equal(t, 7, snapshot)
						events = append(events, "revert")
						return tc.rollback
					},
				},
				gasHandler: &testscommon.GasHandlerStub{
					TotalGasProvidedCalled:            func() uint64 { return 0 },
					TotalGasProvidedAsScheduledCalled: func() uint64 { return 0 },
					TotalGasRefundedCalled:            func() uint64 { return 0 },
					TotalGasPenalizedCalled:           func() uint64 { return 0 },
					ResetCalled:                       func(key []byte) { require.Equal(t, hash, key); events = append(events, "reset") },
					RestoreGasSinceLastResetCalled:    func(key []byte) { require.Equal(t, hash, key); events = append(events, "gas") },
				},
				feeHandler:              &mock.FeeAccumulatorStub{GetAccumulatedFeesCalled: func() *big.Int { return big.NewInt(0) }, RevertFeesCalled: func(hashes [][]byte) { require.Equal(t, [][]byte{txHash}, hashes); events = append(events, "fees") }},
				txExecutionOrderHandler: &commonMock.TxExecutionOrderHandlerStub{RemoveMultipleCalled: func(hashes [][]byte) { require.Equal(t, [][]byte{txHash}, hashes); events = append(events, "order") }},
			}
			mb := &block.MiniBlock{TxHashes: [][]byte{txHash}}
			pp := &preprocMocks.PreProcessorMock{ProcessMiniBlockCalled: func(got *block.MiniBlock, haveTime, additional func() bool, scheduled, partial bool, index int, info process.PreProcessorExecutionInfoHandler) ([][]byte, int, bool, error) {
				require.Same(t, mb, got)
				require.True(t, haveTime())
				require.False(t, additional())
				require.False(t, scheduled)
				require.True(t, partial)
				require.Equal(t, -1, index)
				require.Same(t, c, info)
				events = append(events, "process")
				return [][]byte{txHash}, 0, tc.revert, tc.initial
			}}
			info := &processedMb.ProcessedMiniBlockInfo{IndexOfLastTxProcessed: -1}
			err := c.processCompleteMiniBlock(pp, mb, hash, func() bool { return true }, func() bool { return false }, false, true, info, []byte("header"), process.GasProcessingPolicy{})
			expected := []string{"snapshot", "reset", "process"}
			if tc.initial == nil {
				require.NoError(t, err)
				require.Equal(t, int32(0), info.IndexOfLastTxProcessed)
				require.True(t, info.FullyProcessed)
			} else {
				require.ErrorIs(t, err, tc.initial, "original error survives failed rollback")
				if tc.rollback != nil {
					require.ErrorIs(t, err, tc.rollback)
				} else {
					require.Same(t, tc.initial, err)
				}
				require.False(t, info.FullyProcessed)
				if tc.revert {
					expected = append(expected, "gas", "revert", "fees", "order", "order")
					require.Equal(t, int32(-1), info.IndexOfLastTxProcessed)
				} else {
					require.Equal(t, int32(0), info.IndexOfLastTxProcessed)
				}
			}
			require.Equal(t, expected, events, "native miniblock error path")
		})
	}
}

// Native per-sender skipping would execute a later sender after failed undo.
func TestQualDRWARollbackOuterCoordinatorProbe(t *testing.T) {
	rollback := errors.New("rollback failed")

	args := createMockTransactionCoordinatorArguments()
	numAccountReverts := 0
	args.Accounts = &stateMock.AccountsStub{
		RootHashCalled: func() ([]byte, error) { return nil, rollback },
		JournalLenCalled: func() int {
			return 1
		},
		RevertToSnapshotCalled: func(snapshot int) error {
			numAccountReverts++
			require.Equal(t, 1, snapshot)
			return rollback
		},
	}
	numGasRestores := 0
	args.GasHandler = &testscommon.GasHandlerStub{
		ResetCalled:                       func([]byte) {},
		TotalGasProvidedCalled:            func() uint64 { return 0 },
		TotalGasProvidedAsScheduledCalled: func() uint64 { return 0 },
		TotalGasRefundedCalled:            func() uint64 { return 0 },
		TotalGasPenalizedCalled:           func() uint64 { return 0 },
		RestoreGasSinceLastResetCalled: func(key []byte) {
			numGasRestores++
			require.Equal(t, []byte("fresh"), key)
		},
	}
	removedResultsForKeys := make([]string, 0, 1)
	args.InterProcessors = &mock.InterimProcessorContainerMock{
		KeysCalled: func() []block.Type {
			return []block.Type{block.SmartContractResultBlock}
		},
		GetCalled: func(key block.Type) (process.IntermediateTransactionHandler, error) {
			require.Equal(t, block.SmartContractResultBlock, key)
			return &mock.IntermediateTransactionHandlerMock{
				InitProcessedResultsCalled: func([]byte, []byte) {},
				RemoveProcessedResultsCalled: func(key []byte) [][]byte {
					removedResultsForKeys = append(removedResultsForKeys, string(key))
					return [][]byte{[]byte("result")}
				},
			}, nil
		},
	}
	feeReverts := make([][][]byte, 0, 2)
	args.FeeHandler = &mock.FeeAccumulatorStub{
		GetAccumulatedFeesCalled: func() *big.Int { return big.NewInt(0) },
		RevertFeesCalled: func(txHashes [][]byte) {
			feeReverts = append(feeReverts, txHashes)
		},
	}
	executionOrderRemovals := make([][][]byte, 0, 3)
	args.TxExecutionOrderHandler = &commonMock.TxExecutionOrderHandlerStub{
		RemoveMultipleCalled: func(txHashes [][]byte) {
			executionOrderRemovals = append(executionOrderRemovals, txHashes)
		},
	}
	args.EnableEpochsHandler = &enableEpochsHandlerMock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			return flag == common.MiniBlockPartialExecutionFlag
		},
	}
	args.BlockDataRequester = &preprocMocks.BlockDataRequesterStub{
		GetFinalCrossMiniBlockInfoAndRequestMissingCalled: func(header data.HeaderHandler) []*data.MiniBlockInfo {
			return []*data.MiniBlockInfo{
				{Hash: []byte("fresh"), SenderShardID: 1},
				{Hash: []byte("same-sender"), SenderShardID: 1},
				{Hash: []byte("continuation"), SenderShardID: 2},
			}
		},
	}

	for _, miniBlock := range []*block.MiniBlock{
		{SenderShardID: 1, ReceiverShardID: args.ShardCoordinator.SelfId(), Type: block.TxBlock, TxHashes: [][]byte{[]byte("fresh")}},
		{SenderShardID: 1, ReceiverShardID: args.ShardCoordinator.SelfId(), Type: block.TxBlock, TxHashes: [][]byte{[]byte("same-sender")}},
		{SenderShardID: 2, ReceiverShardID: args.ShardCoordinator.SelfId(), Type: block.TxBlock, TxHashes: [][]byte{[]byte("old"), []byte("continuation")}},
	} {
		args.DataPool.MiniBlocks().Put(miniBlock.TxHashes[len(miniBlock.TxHashes)-1], miniBlock, miniBlock.Size())
	}

	tc, err := NewTransactionCoordinator(args)
	require.NoError(t, err)
	processedHashes := make([]string, 0, 2)
	tc.preProcExecution.txPreProcessors[block.TxBlock] = &preprocMocks.PreProcessorMock{
		GetTransactionsAndRequestMissingForMiniBlockCalled: func(miniBlock *block.MiniBlock) ([]data.TransactionHandler, int) {
			return nil, 0
		},
		ProcessMiniBlockCalled: func(
			miniBlock *block.MiniBlock,
			haveTime func() bool,
			haveAdditionalTime func() bool,
			scheduledMode bool,
			partialMbExecutionMode bool,
			indexOfLastTxProcessed int,
			preProcessorExecutionInfoHandler process.PreProcessorExecutionInfoHandler,
		) ([][]byte, int, bool, error) {
			hash := string(miniBlock.TxHashes[len(miniBlock.TxHashes)-1])
			processedHashes = append(processedHashes, hash)
			if hash == "fresh" {
				require.False(t, partialMbExecutionMode)
				return [][]byte{[]byte("fresh")}, 0, true, process.ErrTimeIsOut
			}

			require.Equal(t, "continuation", hash)
			require.True(t, partialMbExecutionMode)
			return nil, 1, false, nil
		},
	}

	processedMiniBlocksInfo := map[string]*processedMb.ProcessedMiniBlockInfo{
		"continuation": {
			FullyProcessed:         false,
			IndexOfLastTxProcessed: 0,
		},
	}
	_, _, allProcessed, err := tc.CreateMbsAndProcessCrossShardTransactionsDstMe(
		&block.MetaBlock{},
		processedMiniBlocksInfo,
		func() bool { return true },
		func() bool { return false },
		false,
		false,
		process.GasProcessingPolicy{},
	)

	require.ErrorIs(t, err, rollback)
	require.ErrorIs(t, err, process.ErrTimeIsOut)
	require.False(t, allProcessed)
	require.Equal(t, []string{"fresh"}, processedHashes)
	require.False(t, processedMiniBlocksInfo["continuation"].FullyProcessed)
	require.Equal(t, 1, numAccountReverts)
	require.Equal(t, 1, numGasRestores)
	require.Equal(t, []string{"fresh"}, removedResultsForKeys)
	require.Equal(t, [][][]byte{{[]byte("result")}, {[]byte("fresh")}}, feeReverts)
	require.Equal(t, [][][]byte{{[]byte("result")}, {[]byte("fresh")}, {[]byte("fresh")}}, executionOrderRemovals)
}
