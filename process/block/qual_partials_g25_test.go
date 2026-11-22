package block

import (
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/process/mock"
	outportMock "github.com/multiversx/mx-chain-go/testscommon/outport"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"testing"
)

// Isolate retained inner barriers from the already-qualified outer entry guards.
// Unused dependencies deliberately remain absent: poison must precede them.
func TestQualPartialsG25InnerBarrierPrecedence(t *testing.T) {
	for _, route := range []string{"start", "commit_header"} {
		t.Run(route, func(t *testing.T) {
			queries := 0
			bp := &baseProcessor{vmContainer: &mock.VMContainerMock{GetCalled: func([]byte) (vmcommon.VMExecutionHandler, error) {
				return &qualFA01PoisonVM{VMExecutionHandlerStub: &mock.VMExecutionHandlerStub{}}, nil
			}}, outportHandler: &outportMock.OutportStub{HasDriversCalled: func() bool { queries++; return false }}}
			require.NotPanics(t, func() {
				if route == "start" {
					require.ErrorIs(t, bp.createBlockStarted(), vm.ErrDRWAExecution)
				} else {
					require.ErrorIs(t, bp.commitStateForHeader(&block.MetaBlock{}, nil), vm.ErrDRWAExecution)
				}
			})
			require.Zero(t, queries, "poison precedes output-driver selection")
		})
	}
}
