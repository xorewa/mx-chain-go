package coordinator

import (
	"errors"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/block/processedMb"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/testscommon"
	commonMock "github.com/multiversx/mx-chain-go/testscommon/common"
	"github.com/multiversx/mx-chain-go/testscommon/preprocMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/stretchr/testify/require"
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
					ResetCalled:                    func(key []byte) { require.Equal(t, hash, key); events = append(events, "reset") },
					RestoreGasSinceLastResetCalled: func(key []byte) { require.Equal(t, hash, key); events = append(events, "gas") },
				},
				feeHandler:              &mock.FeeAccumulatorStub{RevertFeesCalled: func(hashes [][]byte) { require.Equal(t, [][]byte{txHash}, hashes); events = append(events, "fees") }},
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
				require.Same(t, tc.initial, err, "original error survives failed rollback")
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
