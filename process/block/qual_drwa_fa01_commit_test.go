package block

import (
	dataBlock "github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/state"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"testing"
)

type qualFA01PoisonVM struct{ *mock.VMExecutionHandlerStub }

func (*qualFA01PoisonVM) DRWAExecutionError() error { return vm.ErrDRWAExecution }

// Isolate the inner barrier from the public CommitBlock entry guards.
func TestQualFA01CommitStatePoisonBarrier(t *testing.T) {
	for _, epochStart := range []bool{false, true} {
		commits := false
		accounts := &stateMock.AccountsStub{
			CommitCalled:        func() ([]byte, error) { commits = true; return nil, nil },
			CommitInEpochCalled: func(uint32, uint32) ([]byte, error) { commits = true; return nil, nil },
		}
		bp := &baseProcessor{
			vmContainer: &mock.VMContainerMock{GetCalled: func([]byte) (vmcommon.VMExecutionHandler, error) {
				return &qualFA01PoisonVM{VMExecutionHandlerStub: &mock.VMExecutionHandlerStub{}}, nil
			}},
			accountsDB: map[state.AccountsDbIdentifier]state.AccountsAdapter{state.UserAccountsState: accounts},
		}
		header := &dataBlock.MetaBlock{}
		if epochStart {
			header.EpochStart.LastFinalizedHeaders = []dataBlock.EpochStartShardData{{}}
		}
		require.ErrorIs(t, bp.commitState(header), vm.ErrDRWAExecution)
		require.False(t, commits)
	}
}
