package coordinator

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/preprocMocks"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DS02-M6/M7 consumer contract only: native candidate recovery and the source
// of the injected preprocessor fault remain separate qualification obligations.
// Synthetic dependency fixtures are experimental; replace before testnet admission.
func TestQualDRWAOutgoingCoordinatorError(t *testing.T) {
	for _, shape := range []string{"marker", "wrapped", "joined", "ordinary_same_message", "success"} {
		t.Run(shape, func(t *testing.T) {
			initial := errors.New("native operation failed")
			rollback := errors.New("native rollback failed")
			injected := vm.ErrDRWAExecution
			switch shape {
			case "wrapped":
				injected = fmt.Errorf("context: %w", injected)
			case "joined":
				injected = errors.Join(injected, initial, rollback)
			case "ordinary_same_message":
				injected = errors.New(injected.Error())
			case "success":
				injected = nil
			}
			before := &block.MiniBlock{Type: block.TxBlock, TxHashes: [][]byte{[]byte("prior")}}
			partial := &block.MiniBlock{Type: block.SmartContractResultBlock, TxHashes: [][]byte{[]byte("partial")}}
			after := &block.MiniBlock{Type: block.RewardsBlock, TxHashes: [][]byte{[]byte("post")}}
			events := []string{}
			tc := &transactionCoordinator{
				gasHandler: &testscommon.GasHandlerStub{},
				preProcExecution: &preProcData{keysTxPreProcs: []block.Type{block.TxBlock, block.SmartContractResultBlock, block.RewardsBlock}, txPreProcessors: map[block.Type]process.PreProcessor{
					block.TxBlock: &preprocMocks.PreProcessorMock{CreateAndProcessMiniBlocksCalled: func(func() bool) (block.MiniBlockSlice, error) {
						events = append(events, "before")
						return block.MiniBlockSlice{before}, nil
					}},
					block.SmartContractResultBlock: &preprocMocks.PreProcessorMock{CreateAndProcessMiniBlocksCalled: func(func() bool) (block.MiniBlockSlice, error) {
						events = append(events, "fault")
						return block.MiniBlockSlice{partial}, injected
					}},
					block.RewardsBlock: &preprocMocks.PreProcessorMock{CreateAndProcessMiniBlocksCalled: func(func() bool) (block.MiniBlockSlice, error) {
						events = append(events, "after")
						return block.MiniBlockSlice{after}, nil
					}},
				}},
				keysInterimProcs: []block.Type{block.TxBlock}, interimProcessors: map[block.Type]process.IntermediateTransactionHandler{block.TxBlock: &mock.IntermediateTransactionHandlerMock{CreateAllInterMiniBlocksCalled: func() []*block.MiniBlock { events = append(events, "postprocess"); return nil }}},
			}
			// Reflection is confined to this qualifier: the pre-change native API has
			// no error result. Invoke it before checking the expected error contract.
			results := reflect.ValueOf(tc.CreateMbsAndProcessTransactionsFromMe).Call([]reflect.Value{reflect.ValueOf(func() bool { return true }), reflect.ValueOf([]byte("randomness"))})
			got := results[0].Interface().(block.MiniBlockSlice)
			fatal := shape != "ordinary_same_message" && shape != "success"
			t.Logf("shape=%s returned_miniblocks=%d result_arity=%d events=%v", shape, len(got), len(results), events)
			if fatal {
				assert.Nil(t, got, "withhold earlier and partial miniblocks")
				assert.Equal(t, []string{"before", "fault"}, events, "do not execute later processors")
			} else {
				assert.Equal(t, block.MiniBlockSlice{before, partial, after}, got)
				assert.Equal(t, []string{"before", "fault", "after", "postprocess"}, events)
			}
			if !fatal && len(results) == 1 {
				return
			} // unchanged native API ordinary control
			require.Len(t, results, 2, "coordinator needs a native error channel")
			var err error
			if !results[1].IsNil() {
				err = results[1].Interface().(error)
			}
			if !fatal {
				require.NoError(t, err)
				return
			}
			require.Same(t, injected, err)
			require.ErrorIs(t, err, vm.ErrDRWAExecution)
			if shape == "joined" {
				require.ErrorIs(t, err, initial)
				require.ErrorIs(t, err, rollback)
			}
		})
	}
}
