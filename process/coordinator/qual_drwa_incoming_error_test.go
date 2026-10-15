package coordinator

import (
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/block/processedMb"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/cache"
	dataRetrieverMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/preprocMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
)

// DS02-M6/M7 propagation at the real incoming coordinator entrypoint, including
// a misbehaving stub returning an error with partial progress. No candidate restoration or admission claim.
// Synthetic and inherited constructor coordinates are experimental; replace or
// confirm before testnet admission (R7).
func TestQualDRWAIncomingCoordinatorError(t *testing.T) {
	for _, scheduled := range []bool{false, true} {
		for _, revert := range []bool{false, true} {
			for _, shape := range []string{"marker", "wrapped", "joined", "ordinary", "success"} {
				t.Run(fmt.Sprintf("scheduled_%t/revert_%t/%s", scheduled, revert, shape), func(t *testing.T) {
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
					args := createMockTransactionCoordinatorArguments()
					c, err := NewTransactionCoordinator(args)
					require.NoError(t, err)
					dependencyReturnedError, effects, calls := false, 0, 0
					c.accounts = &stateMock.AccountsStub{RevertToSnapshotCalled: func(int) error {
						if dependencyReturnedError {
							effects++
						}
						return rollback
					}}
					c.gasHandler = &testscommon.GasHandlerStub{RestoreGasSinceLastResetCalled: func([]byte) {
						if dependencyReturnedError {
							effects++
						}
					}}
					c.enableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.MiniBlockPartialExecutionFlag)
					mbs := []*block.MiniBlock{
						{Type: block.TxBlock, SenderShardID: 1, TxHashes: [][]byte{[]byte("experimental tx A")}},
						{Type: block.TxBlock, SenderShardID: 2, TxHashes: [][]byte{[]byte("experimental tx B")}},
					}
					infos := []*data.MiniBlockInfo{{Hash: []byte("experimental mb A"), SenderShardID: 1}, {Hash: []byte("experimental mb B"), SenderShardID: 2}}
					c.dataPool = &dataRetrieverMock.PoolsHolderStub{MiniBlocksCalled: func() storage.Cacher {
						return &cache.CacherStub{PeekCalled: func(hash []byte) (interface{}, bool) {
							if string(hash) == string(infos[0].Hash) {
								return mbs[0], true
							}
							return mbs[1], true
						}}
					}}
					c.blockDataRequester = &preprocMocks.BlockDataRequesterStub{GetFinalCrossMiniBlockInfoAndRequestMissingCalled: func(data.HeaderHandler) []*data.MiniBlockInfo { return infos }}
					pp := &preprocMocks.PreProcessorMock{ProcessMiniBlockCalled: func(mb *block.MiniBlock, _, _ func() bool, _, _ bool, _ int, _ process.PreProcessorExecutionInfoHandler) ([][]byte, int, bool, error) {
						calls++
						if calls == 1 && failure != nil {
							dependencyReturnedError = true
							return mb.TxHashes, 0, revert, failure
						}
						return nil, 0, false, nil
					}}
					c.preProcExecution = &preProcData{keysTxPreProcs: []block.Type{block.TxBlock}, txPreProcessors: map[block.Type]process.PreProcessor{block.TxBlock: pp}}
					progress := map[string]*processedMb.ProcessedMiniBlockInfo{string(infos[0].Hash): {IndexOfLastTxProcessed: -1}, string(infos[1].Hash): {IndexOfLastTxProcessed: -1}}
					got, count, finished, err := c.CreateMbsAndProcessCrossShardTransactionsDstMe(&block.MetaBlock{}, progress, func() bool { return true }, func() bool { return false }, scheduled, true, process.GasProcessingPolicy{})
					if shape != "ordinary" && shape != "success" {
						require.Same(t, failure, err)
						require.ErrorIs(t, err, vm.ErrDRWAExecution)
						if shape == "joined" {
							require.ErrorIs(t, err, rollback)
						}
						require.Nil(t, got)
						require.Zero(t, count)
						require.False(t, finished)
						require.Equal(t, 1, calls, "no next miniblock")
						require.Zero(t, effects, "no ordinary gas/account recovery after fatal error")
						for _, p := range progress {
							require.Equal(t, int32(-1), p.IndexOfLastTxProcessed)
							require.False(t, p.FullyProcessed)
						}
					} else {
						require.NoError(t, err)
						require.Equal(t, 2, calls)
						if failure == nil {
							require.True(t, finished)
							require.Len(t, got, 2)
							require.Equal(t, uint32(2), count)
						} else {
							require.False(t, finished)
						}
					}
				})
			}
		}
	}
}
