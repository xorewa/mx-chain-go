package scrCommon

import (
	"errors"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/state"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualSP281CLaneFPhysical struct {
	*mock.VMExecutionHandlerStub
	qualD20CommonRefusalPhysical
	handoff vm.DRWANativeCallHandoff
	bindErr error
	trace   []string
}

func (p *qualSP281CLaneFPhysical) WithDRWANativeCall(_ data.TransactionHandler, _ any, _ state.AccountsAdapter,
	run func(vm.DRWANativeCallHandoff) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
	return run(p.handoff)
}

func (p *qualSP281CLaneFPhysical) ValidateDRWANativeTransaction(token vm.DRWANativeCallHandoff, _ data.TransactionHandler,
	_ state.AccountsAdapter, _, _ state.UserAccountHandler) error {
	if token != p.handoff {
		return vm.ErrDRWAExecution
	}
	p.trace = append(p.trace, "validate")
	return nil
}

func (p *qualSP281CLaneFPhysical) BindDRWANativeCall(token vm.DRWANativeCallHandoff, _ *vmcommon.ContractCallInput) error {
	if token != p.handoff {
		return vm.ErrDRWAExecution
	}
	p.trace = append(p.trace, "bind")
	return p.bindErr
}

func (p *qualSP281CLaneFPhysical) RunSmartContractCallWithDRWA(_ *vmcommon.ContractCallInput, token vm.DRWANativeCallHandoff) (*vmcommon.VMOutput, error) {
	if token != p.handoff {
		return nil, vm.ErrDRWAExecution
	}
	p.trace = append(p.trace, "run")
	return &vmcommon.VMOutput{ReturnCode: vmcommon.UserError}, nil
}

func TestQualSP281CLaneFSharedCallOrderAndFailureLatch(t *testing.T) {
	for _, mode := range []string{"exact", "lookup", "no-token", "no-binder", "denied-bind", "repeat-bind"} {
		t.Run(mode, func(t *testing.T) {
			sentinel := errors.New("inert dependency denial")
			physical := &qualSP281CLaneFPhysical{VMExecutionHandlerStub: &mock.VMExecutionHandlerStub{}, handoff: &qualD20CommonToken{}}
			lock := &sync.RWMutex{}
			input := &vmcommon.ContractCallInput{Function: "inert"}
			if mode == "denied-bind" {
				physical.bindErr = sentinel
			}
			if mode == "no-token" {
				physical.handoff = nil
			}
			tx := &transaction.Transaction{RcvAddr: core.ESDTSCAddress}
			accounts := &stateMock.AccountsStub{}
			container := &mock.VMContainerMock{GetCalled: func([]byte) (vmcommon.VMExecutionHandler, error) {
				if mode == "lookup" {
					return nil, sentinel
				}
				return physical, nil
			}}
			bodies := 0
			code, err := WithDRWANativeCall(container, lock, accounts, tx, nil, func(call *DRWANativeCall) (vmcommon.ReturnCode, error) {
				bodies++
				require.False(t, lock.TryLock())
				require.ErrorIs(t, call.Bind(input), vm.ErrDRWAExecution)
				require.NoError(t, call.Begin(tx, accounts, nil, nil))
				if mode == "no-binder" {
					call.physical = &qualD20CommonRefusalPhysical{}
				}
				err := call.Bind(input)
				switch mode {
				case "exact":
					require.NoError(t, err)
					output, err := call.Run(input)
					require.NoError(t, err)
					return output.ReturnCode, nil
				case "repeat-bind":
					require.NoError(t, err)
					require.ErrorIs(t, call.Bind(input), vm.ErrDRWAExecution)
				case "denied-bind":
					require.ErrorIs(t, err, sentinel)
				default:
					require.ErrorIs(t, err, vm.ErrDRWAExecution)
				}
				output, err := call.Run(input)
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.Nil(t, output)
				return vmcommon.Ok, nil
			})
			require.True(t, lock.TryLock())
			lock.Unlock()
			if mode == "exact" {
				require.NoError(t, err)
				require.Equal(t, vmcommon.UserError, code)
				require.Equal(t, []string{"validate", "bind", "run"}, physical.trace)
			} else {
				require.Equal(t, vmcommon.ExecutionFailed, code)
				require.NotContains(t, physical.trace, "run")
				if mode == "lookup" {
					require.ErrorIs(t, err, sentinel)
				} else {
					require.ErrorIs(t, err, vm.ErrDRWAExecution)
				}
			}
			if mode == "lookup" || mode == "no-token" {
				require.Zero(t, bodies)
			} else {
				require.Equal(t, 1, bodies)
			}
		})
	}
}

func TestQualSP281CLaneFSharedCallCannotBeginWithoutPrivateToken(t *testing.T) {
	require.ErrorIs(t, (*DRWANativeCall)(nil).Begin(nil, nil, nil, nil), vm.ErrDRWAExecution)
	physical := &qualSP281CLaneFPhysical{}
	call := &DRWANativeCall{physical: physical}
	require.ErrorIs(t, call.Begin(nil, nil, nil, nil), vm.ErrDRWAExecution)
	require.Empty(t, physical.trace)
}
