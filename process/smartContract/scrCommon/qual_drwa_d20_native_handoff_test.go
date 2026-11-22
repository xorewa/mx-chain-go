package scrCommon

import (
	"bytes"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	nativeVM "github.com/multiversx/mx-chain-go/vm/process"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

func TestQualD20SharedNativeHandoffRefusals(t *testing.T) {
	for _, name := range []string{"missing-container", "missing-accounts", "missing-tx", "missing-lock", "missing-body", "missing-native-owner"} {
		t.Run(name, func(t *testing.T) {
			accounts := &stateMock.AccountsStub{}
			tx := &transaction.Transaction{RcvAddr: bytes.Clone(core.ESDTSCAddress)}
			locker := &sync.RWMutex{}
			lookups := 0
			container := &mock.VMContainerMock{GetCalled: func([]byte) (vmcommon.VMExecutionHandler, error) {
				lookups++
				return &mock.VMExecutionHandlerStub{}, nil
			}}
			calls := 0
			body := func(*DRWANativeCall) (vmcommon.ReturnCode, error) { calls++; return vmcommon.Ok, nil }
			var err error
			switch name {
			case "missing-container":
				_, err = WithDRWANativeCall(nil, locker, accounts, tx, nil, body)
			case "missing-accounts":
				_, err = WithDRWANativeCall(container, locker, nil, tx, nil, body)
			case "missing-tx":
				_, err = WithDRWANativeCall(container, locker, accounts, nil, nil, body)
			case "missing-lock":
				_, err = WithDRWANativeCall(container, nil, accounts, tx, nil, body)
			case "missing-body":
				_, err = WithDRWANativeCall(container, locker, accounts, tx, nil, nil)
			default:
				_, err = WithDRWANativeCall(container, locker, accounts, tx, struct{}{}, body)
			}
			require.ErrorIs(t, err, vm.ErrDRWAExecution)
			require.Zero(t, calls)
			if name == "missing-native-owner" {
				require.Equal(t, 1, lookups)
			} else {
				require.Zero(t, lookups)
			}
			require.True(t, locker.TryLock())
			locker.Unlock()
		})
	}
	var empty *DRWANativeCall
	out, err := empty.Run(nil)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Nil(t, out)
	out, err = (&DRWANativeCall{}).Run(nil)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Nil(t, out)
}

func TestQualD20SharedNativeUnconfiguredRoute(t *testing.T) {
	// Explicit synthetic constructor costs only; not admitted deployment values.
	costs := map[string]map[string]uint64{common.BaseOpsAPICost: {common.AsyncCallStepField: 1000, common.AsyncCallbackGasLockField: 3000}}
	physical, err := nativeVM.NewSystemVM(nativeVM.ArgsNewSystemVM{SystemEI: &qualD20UnavailableContext{}, SystemContracts: &qualD20UnavailableContracts{}, VmType: factory.SystemVirtualMachine, GasSchedule: testscommon.NewGasScheduleNotifierMock(costs)})
	require.NoError(t, err)
	require.False(t, physical.DRWANativeCallConfigured())
	locker := &sync.RWMutex{}
	container := &mock.VMContainerMock{GetCalled: func([]byte) (vmcommon.VMExecutionHandler, error) { return physical, nil }}
	tx := &transaction.Transaction{RcvAddr: bytes.Clone(core.ESDTSCAddress)}
	calls := 0
	code, err := WithDRWANativeCall(container, locker, &stateMock.AccountsStub{}, tx, struct{}{}, func(call *DRWANativeCall) (vmcommon.ReturnCode, error) {
		calls++
		require.Nil(t, call)
		require.True(t, locker.TryLock(), "ordinary reselection must not inherit the native VM read lock")
		locker.Unlock()
		return vmcommon.UserError, nil
	})
	require.NoError(t, err)
	require.Equal(t, vmcommon.UserError, code)
	require.Equal(t, 1, calls)
}

// An always-denying physical provider, used only to observe whether known local
// failure incorrectly reaches a provider. It supplies no authentication lease.
type qualD20CommonRefusalPhysical struct{ calls int }

func (*qualD20CommonRefusalPhysical) DRWANativeCallConfigured() bool { return true }
func (*qualD20CommonRefusalPhysical) WithDRWANativeCall(data.TransactionHandler, any, state.AccountsAdapter, func(vm.DRWANativeCallHandoff) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
	return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
}
func (*qualD20CommonRefusalPhysical) ValidateDRWANativeTransaction(vm.DRWANativeCallHandoff, data.TransactionHandler, state.AccountsAdapter, state.UserAccountHandler, state.UserAccountHandler) error {
	return vm.ErrDRWAExecution
}
func (p *qualD20CommonRefusalPhysical) RunSmartContractCallWithDRWA(*vmcommon.ContractCallInput, vm.DRWANativeCallHandoff) (*vmcommon.VMOutput, error) {
	p.calls++
	return nil, vm.ErrDRWAExecution
}

type qualD20CommonToken struct{}

func (*qualD20CommonToken) IsInterfaceNil() bool { return false }
func TestQualD20SharedStickyPreflight(t *testing.T) {
	physical := &qualD20CommonRefusalPhysical{}
	call := &DRWANativeCall{physical: physical, handoff: &qualD20CommonToken{}}
	call.executed.Store(true) // private synthetic state after an already entered attempt
	call.prepared.Store(true) // isolate sticky refusal from the separate unprepared-call guard
	require.ErrorIs(t, call.Begin(&transaction.Transaction{}, &stateMock.AccountsStub{}, nil, nil), vm.ErrDRWAExecution)
	output, err := call.Run(nil)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Nil(t, output)
	require.Zero(t, physical.calls)
}

// Unavailable test dependencies: no embedded native method may be called.
// These cannot produce an execution/authentication lease or contract result.
type qualD20UnavailableContext struct{ vm.ContextHandler }

func (*qualD20UnavailableContext) IsInterfaceNil() bool { return false }

type qualD20UnavailableContracts struct{ vm.SystemSCContainer }

func (*qualD20UnavailableContracts) IsInterfaceNil() bool { return false }
