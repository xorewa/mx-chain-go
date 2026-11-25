package process

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/state"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Inert fixture lease. It authenticates nothing; verify is the test's own hook.
type qualSP281CClaudeLease struct {
	*qualD20CallLease
	verify func() error
}

func (l *qualSP281CClaudeLease) VerifyTransaction(data.TransactionHandler, state.AccountsAdapter, state.UserAccountHandler, state.UserAccountHandler) error {
	return l.verify()
}

func qualSP281CClaudeLeaseFor(verify func() error) *qualSP281CClaudeLease {
	return &qualSP281CClaudeLease{qualD20CallLease: &qualD20CallLease{expected: qualD20CallInput()}, verify: verify}
}

var qualSP281CClaudeOrdinarySteps = []string{"clean", "address", "value", "gas", "contract", "execute", "output"}

// E1: the three ordinary methods keep the pinned upstream results.
func TestQualSP281CClaudeOrdinaryLifecycleMethods(t *testing.T) {
	system, err := NewSystemVM(createMockArguments())
	require.NoError(t, err)
	require.Equal(t, "", system.GetVersion())
	require.NoError(t, system.Close())
	require.False(t, system.IsInterfaceNil())
	require.True(t, (*systemVM)(nil).IsInterfaceNil())
}

// E2: a context that wraps system calls runs the ordinary call path once.
func TestQualSP281CClaudeNativeDispatchRunsOrdinaryPathInsideContext(t *testing.T) {
	physical, trace := qualD20Physical(t)
	tx := &transaction.Transaction{}
	accounts := &stateMock.AccountsStub{}
	input := qualD20CallInput()
	lease := qualSP281CClaudeLeaseFor(func() error { return nil })
	call := &drwaNativeCall{vm: physical, lease: lease, active: true}
	require.NoError(t, physical.ValidateDRWANativeTransaction(call, tx, accounts, nil, nil))
	require.NoError(t, physical.BindDRWANativeCall(call, input))

	entries := 0
	context := &qualSP281CLaneFVMContext{qualD20Prelude: physical.systemEI.(*qualD20Prelude)}
	context.call = func(got *vmcommon.ContractCallInput, execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
		entries++
		require.Same(t, input, got)
		require.Empty(t, *trace)
		return execute()
	}
	physical.systemEI = context

	output, err := physical.RunSmartContractCallWithDRWA(input, call)
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, output.ReturnCode)
	require.Equal(t, uint64(23), output.GasRemaining)
	require.Equal(t, 1, entries)
	require.Equal(t, qualSP281CClaudeOrdinarySteps, *trace)
	require.Equal(t, 2, lease.calls)
}

// E3: a second dispatch with the same handoff during contract execution denies both.
func TestQualSP281CClaudeNestedDispatchDeniesHandoff(t *testing.T) {
	physical, trace := qualD20Physical(t)
	input := qualD20CallInput()
	lease := qualSP281CClaudeLeaseFor(func() error { return nil })
	call := &drwaNativeCall{vm: physical, lease: lease, active: true}
	require.NoError(t, physical.ValidateDRWANativeTransaction(call, &transaction.Transaction{}, &stateMock.AccountsStub{}, nil, nil))
	require.NoError(t, physical.BindDRWANativeCall(call, input))

	executions := 0
	var nestedOutput *vmcommon.VMOutput
	var nestedErr error
	stub := physical.systemEI.(*qualD20Prelude).SystemEIStub
	stub.GetContractCalled = func([]byte) (vm.SystemSmartContract, error) {
		*trace = append(*trace, "contract")
		return &mock.SystemSCStub{ExecuteCalled: func(in *vmcommon.ContractCallInput) vmcommon.ReturnCode {
			executions++
			*trace = append(*trace, "execute")
			nestedOutput, nestedErr = physical.RunSmartContractCallWithDRWA(in, call)
			return vmcommon.Ok
		}}, nil
	}

	output, err := physical.RunSmartContractCallWithDRWA(input, call)
	require.ErrorIs(t, nestedErr, vm.ErrDRWAExecution)
	require.Nil(t, nestedOutput)
	require.Equal(t, 1, executions)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Nil(t, output)

	before := append([]string(nil), (*trace)...)
	output, err = physical.RunSmartContractCallWithDRWA(input, call)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Nil(t, output)
	require.Equal(t, before, *trace)
	require.Equal(t, 1, executions)
}

// E4: a handoff submitted for validation while it is being validated is denied afterwards.
func TestQualSP281CClaudeNestedValidationDeniesHandoff(t *testing.T) {
	physical, trace := qualD20Physical(t)
	tx := &transaction.Transaction{}
	accounts := &stateMock.AccountsStub{}
	input := qualD20CallInput()
	nested := 0
	var nestedErr error
	var call *drwaNativeCall
	lease := qualSP281CClaudeLeaseFor(func() error {
		nested++
		nestedErr = physical.ValidateDRWANativeTransaction(call, tx, accounts, nil, nil)
		return nil
	})
	call = &drwaNativeCall{vm: physical, lease: lease, active: true}

	outerErr := physical.ValidateDRWANativeTransaction(call, tx, accounts, nil, nil)
	t.Logf("observed only, no expectation: outer validation returned %v", outerErr)
	require.Equal(t, 1, nested)
	require.ErrorIs(t, nestedErr, vm.ErrDRWAExecution)

	require.ErrorIs(t, physical.ValidateDRWANativeTransaction(call, tx, accounts, nil, nil), vm.ErrDRWAExecution)
	require.Equal(t, 1, nested)
	require.ErrorIs(t, physical.BindDRWANativeCall(call, input), vm.ErrDRWAExecution)
	output, err := physical.RunSmartContractCallWithDRWA(input, call)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Nil(t, output)
	require.Zero(t, lease.calls)
	require.Empty(t, *trace)
}

func qualSP281CClaudeNativeSource(physical *systemVM, lease vm.DRWANativeCallLease,
	saved *func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error)) {
	source := &qualD20HandoffContext{invoke: func(run func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
		if saved != nil {
			*saved = run
		}
		return run(lease)
	}}
	physical.systemEI = &qualSP281CLaneFNativeSource{qualD20Prelude: physical.systemEI.(*qualD20Prelude), source: source}
}

// E5: the source's callback invoked again while it is running denies the whole native call.
func TestQualSP281CClaudeNestedSourceCallbackDeniesNativeCall(t *testing.T) {
	physical, trace := qualD20Physical(t)
	tx := &transaction.Transaction{}
	accounts := &stateMock.AccountsStub{}
	input := qualD20CallInput()
	lease := qualSP281CClaudeLeaseFor(func() error { return nil })
	var callback func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error)
	qualSP281CClaudeNativeSource(physical, lease, &callback)

	entries := 0
	nestedCode := vmcommon.Ok
	var nestedErr error
	code, err := physical.WithDRWANativeCall(tx, nil, accounts, func(handoff vm.DRWANativeCallHandoff) (vmcommon.ReturnCode, error) {
		entries++
		nestedCode, nestedErr = callback(lease)
		require.NoError(t, physical.ValidateDRWANativeTransaction(handoff, tx, accounts, nil, nil))
		require.NoError(t, physical.BindDRWANativeCall(handoff, input))
		output, dispatchErr := physical.RunSmartContractCallWithDRWA(input, handoff)
		require.NoError(t, dispatchErr)
		return output.ReturnCode, nil
	})
	require.Equal(t, 1, entries)
	require.Equal(t, vmcommon.ExecutionFailed, nestedCode)
	require.ErrorIs(t, nestedErr, vm.ErrDRWAExecution)
	require.Equal(t, vmcommon.ExecutionFailed, code)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Equal(t, qualSP281CClaudeOrdinarySteps, *trace)
}

// E6: handoff misuse inside the native call denies it even when the caller returns Ok.
func TestQualSP281CClaudeMisusedHandoffDeniesNativeCall(t *testing.T) {
	physical, trace := qualD20Physical(t)
	tx := &transaction.Transaction{}
	accounts := &stateMock.AccountsStub{}
	var current vm.DRWANativeCallHandoff
	var nestedErr error
	lease := qualSP281CClaudeLeaseFor(func() error {
		nestedErr = physical.ValidateDRWANativeTransaction(current, tx, accounts, nil, nil)
		return nil
	})
	qualSP281CClaudeNativeSource(physical, lease, nil)

	code, err := physical.WithDRWANativeCall(tx, nil, accounts, func(handoff vm.DRWANativeCallHandoff) (vmcommon.ReturnCode, error) {
		current = handoff
		_ = physical.ValidateDRWANativeTransaction(handoff, tx, accounts, nil, nil)
		return vmcommon.Ok, nil
	})
	require.ErrorIs(t, nestedErr, vm.ErrDRWAExecution)
	require.Equal(t, vmcommon.ExecutionFailed, code)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Empty(t, *trace)
}

// E7: a lease denial hidden by the caller still denies the native call with its cause.
func TestQualSP281CClaudeHiddenLeaseDenialDeniesNativeCall(t *testing.T) {
	physical, trace := qualD20Physical(t)
	tx := &transaction.Transaction{}
	accounts := &stateMock.AccountsStub{}
	denied := errors.New("inert lease denies transaction")
	lease := qualSP281CClaudeLeaseFor(func() error { return denied })
	qualSP281CClaudeNativeSource(physical, lease, nil)

	code, err := physical.WithDRWANativeCall(tx, nil, accounts, func(handoff vm.DRWANativeCallHandoff) (vmcommon.ReturnCode, error) {
		require.ErrorIs(t, physical.ValidateDRWANativeTransaction(handoff, tx, accounts, nil, nil), denied)
		return vmcommon.Ok, nil
	})
	require.Equal(t, vmcommon.ExecutionFailed, code)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.ErrorIs(t, err, denied)
	require.Zero(t, lease.calls)
	require.Empty(t, *trace)
}
