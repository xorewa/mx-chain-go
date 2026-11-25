package process

import (
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/state"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CLaneFFrozenCallOwnsItsMutableFields(t *testing.T) {
	input := &vmcommon.ContractCallInput{Function: "inert"}
	input.CallerAddr = []byte{1}
	input.OriginalCallerAddr = []byte{2}
	input.RelayerAddr = []byte{3}
	input.RecipientAddr = []byte{4}
	input.OriginalTxHash = []byte{5}
	input.CurrentTxHash = []byte{6}
	input.PrevTxHash = []byte{7}
	input.TxGuardian = []byte{8}
	input.CallValue = big.NewInt(9)
	input.Arguments = [][]byte{nil, {10}}
	input.AsyncArguments = &vmcommon.AsyncArguments{
		CallID: []byte{11}, CallerCallID: []byte{12}, CallbackAsyncInitiatorCallID: []byte{13},
	}
	input.ESDTTransfers = []*vmcommon.ESDTTransfer{
		nil, {ESDTTokenName: []byte{14}, ESDTValue: big.NewInt(15)}, {ESDTTokenName: []byte{16}},
	}
	frozen := freezeDRWACall(input)
	require.Equal(t, input, frozen)
	before := [][]byte{frozen.CallerAddr, frozen.OriginalCallerAddr, frozen.RelayerAddr, frozen.RecipientAddr,
		frozen.OriginalTxHash, frozen.CurrentTxHash, frozen.PrevTxHash, frozen.TxGuardian, frozen.Arguments[1],
		frozen.AsyncArguments.CallID, frozen.AsyncArguments.CallerCallID, frozen.AsyncArguments.CallbackAsyncInitiatorCallID,
		frozen.ESDTTransfers[1].ESDTTokenName, frozen.ESDTTransfers[2].ESDTTokenName}
	for _, field := range [][]byte{input.CallerAddr, input.OriginalCallerAddr, input.RelayerAddr, input.RecipientAddr,
		input.OriginalTxHash, input.CurrentTxHash, input.PrevTxHash, input.TxGuardian, input.Arguments[1],
		input.AsyncArguments.CallID, input.AsyncArguments.CallerCallID, input.AsyncArguments.CallbackAsyncInitiatorCallID,
		input.ESDTTransfers[1].ESDTTokenName, input.ESDTTransfers[2].ESDTTokenName} {
		field[0] = 99
	}
	input.CallValue.SetInt64(99)
	input.ESDTTransfers[1].ESDTValue.SetInt64(99)
	require.Equal(t, [][]byte{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {10}, {11}, {12}, {13}, {14}, {16}}, before)
	require.Equal(t, big.NewInt(9), frozen.CallValue)
	require.Equal(t, big.NewInt(15), frozen.ESDTTransfers[1].ESDTValue)
	require.Nil(t, frozen.ESDTTransfers[0])
	require.Nil(t, frozen.ESDTTransfers[2].ESDTValue)
	require.Equal(t, &vmcommon.ContractCallInput{}, freezeDRWACall(&vmcommon.ContractCallInput{}))
}

func TestQualSP281CLaneFPhysicalVMRequiresInstalledDeletionGuard(t *testing.T) {
	physical, trace := qualD20Physical(t)
	entered := false
	execute := func() error { entered = true; return nil }

	require.False(t, (*systemVM)(nil).DRWANativeCallConfigured())
	require.False(t, physical.DRWANativeCallConfigured())
	require.True(t, (*drwaNativeCall)(nil).IsInterfaceNil())
	require.False(t, (&drwaNativeCall{}).IsInterfaceNil())
	require.ErrorIs(t, physical.WithDRWAAccountDeletion(nil, nil, nil), vm.ErrDRWAExecution)
	physical.criticalSection.Lock()
	err := physical.WithDRWAAccountDeletion(nil, nil, execute)
	physical.criticalSection.Unlock()
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.ErrorIs(t, physical.WithDRWAAccountDeletion(nil, nil, execute), vm.ErrDRWAExecution)
	require.False(t, entered)
	require.Empty(t, *trace)
}

type qualSP281CLaneFVMContext struct {
	*qualD20Prelude
	guard func(state.AccountsAdapter, [][]byte, func() error) error
	call  func(*vmcommon.ContractCallInput, func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error)
}

func (c *qualSP281CLaneFVMContext) WithDRWAAccountDeletion(accounts state.AccountsAdapter, addresses [][]byte, execute func() error) error {
	return c.guard(accounts, addresses, execute)
}

func (c *qualSP281CLaneFVMContext) ExecuteDRWASystemCall(input *vmcommon.ContractCallInput, execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	return c.call(input, execute)
}

func TestQualSP281CLaneFPhysicalVMForwardsExactDeletionCallback(t *testing.T) {
	physical, trace := qualD20Physical(t)
	accounts := &stateMock.AccountsStub{}
	addresses := [][]byte{[]byte("inert-account")}
	closed := errors.New("inert deletion callback outcome")
	context := &qualSP281CLaneFVMContext{qualD20Prelude: physical.systemEI.(*qualD20Prelude)}
	context.guard = func(received state.AccountsAdapter, keys [][]byte, execute func() error) error {
		require.Same(t, accounts, received)
		require.Equal(t, addresses, keys)
		require.False(t, physical.criticalSection.TryLock())
		return execute()
	}
	physical.systemEI = context
	entries := 0
	err := physical.WithDRWAAccountDeletion(accounts, addresses, func() error {
		entries++
		return closed
	})
	require.ErrorIs(t, err, closed)
	require.Equal(t, 1, entries)
	require.Empty(t, *trace)
	require.True(t, physical.criticalSection.TryLock())
	physical.criticalSection.Unlock()
}

type qualSP281CLaneFLease struct {
	*qualD20CallLease
	tx       data.TransactionHandler
	accounts state.AccountsAdapter
}

func (l *qualSP281CLaneFLease) VerifyTransaction(tx data.TransactionHandler, accounts state.AccountsAdapter, _, _ state.UserAccountHandler) error {
	if tx != l.tx || accounts != l.accounts {
		return l.denial
	}
	return nil
}

func TestQualSP281CLaneFPhysicalVMKeepsPrivateHandoffFailures(t *testing.T) {
	for _, mode := range []string{"exact", "missing", "foreign-transaction", "repeat-validation", "lease-without-binder", "mismatched-binding", "contended-binding", "contended-dispatch", "classifier-denial", "post-call-lease-denial"} {
		t.Run(mode, func(t *testing.T) {
			physical, trace := qualD20Physical(t)
			tx := &transaction.Transaction{}
			accounts := &stateMock.AccountsStub{}
			input := qualD20CallInput()
			denied := errors.New("inert lease denies candidate")
			lease := &qualSP281CLaneFLease{qualD20CallLease: &qualD20CallLease{expected: qualD20CallInput()}, tx: tx, accounts: accounts}
			call := &drwaNativeCall{lease: lease, vm: physical, active: true}
			switch mode {
			case "missing":
				require.ErrorIs(t, physical.ValidateDRWANativeTransaction(nil, tx, accounts, nil, nil), vm.ErrDRWAExecution)
				require.ErrorIs(t, physical.BindDRWANativeCall(nil, input), vm.ErrDRWAExecution)
				return
			case "foreign-transaction":
				lease.denial = denied
				err := physical.ValidateDRWANativeTransaction(call, &transaction.Transaction{}, accounts, nil, nil)
				require.ErrorIs(t, err, denied)
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.ErrorIs(t, physical.ValidateDRWANativeTransaction(call, tx, accounts, nil, nil), denied)
				require.ErrorIs(t, physical.BindDRWANativeCall(call, input), denied)
				require.Empty(t, *trace)
				return
			}
			require.NoError(t, physical.ValidateDRWANativeTransaction(call, tx, accounts, nil, nil))
			switch mode {
			case "repeat-validation":
				require.ErrorIs(t, physical.ValidateDRWANativeTransaction(call, tx, accounts, nil, nil), vm.ErrDRWAExecution)
			case "lease-without-binder":
				call.lease = struct{ vm.DRWANativeCallLease }{lease}
				require.ErrorIs(t, physical.BindDRWANativeCall(call, input), vm.ErrDRWAExecution)
			case "mismatched-binding":
				input.Function = "synthetic foreign function"
				require.ErrorIs(t, physical.BindDRWANativeCall(call, input), vm.ErrDRWAExecution)
			case "contended-binding":
				call.mut.Lock()
				err := physical.BindDRWANativeCall(call, input)
				call.mut.Unlock()
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
			default:
				require.NoError(t, physical.BindDRWANativeCall(call, input))
				if mode != "exact" && mode != "contended-dispatch" {
					context := &qualSP281CLaneFVMContext{qualD20Prelude: physical.systemEI.(*qualD20Prelude)}
					context.call = func(got *vmcommon.ContractCallInput, _ func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
						require.Same(t, input, got)
						if mode == "post-call-lease-denial" {
							lease.denial = denied
						}
						return nil, vm.ErrDRWAExecution
					}
					physical.systemEI = context
				}
			}
			if mode == "contended-dispatch" {
				call.mut.Lock()
				out, err := physical.RunSmartContractCallWithDRWA(input, call)
				call.mut.Unlock()
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.Nil(t, out)
			}
			out, err := physical.RunSmartContractCallWithDRWA(input, call)
			if mode == "exact" {
				require.NoError(t, err)
				require.Equal(t, vmcommon.Ok, out.ReturnCode)
				require.Equal(t, 2, lease.calls)
				require.Equal(t, []string{"clean", "address", "value", "gas", "contract", "execute", "output"}, *trace)
				return
			}
			require.ErrorIs(t, err, vm.ErrDRWAExecution)
			if mode == "post-call-lease-denial" {
				require.ErrorIs(t, err, denied)
			}
			require.Nil(t, out)
			require.Empty(t, *trace)
		})
	}
}

func TestQualSP281CLaneFPhysicalVMRejectsUnusedSuccessfulHandoff(t *testing.T) {
	physical, trace := qualD20Physical(t)
	tx := &transaction.Transaction{}
	accounts := &stateMock.AccountsStub{}
	lease := &qualSP281CLaneFLease{qualD20CallLease: &qualD20CallLease{expected: qualD20CallInput()}, tx: tx, accounts: accounts}
	context := &qualD20HandoffContext{SystemEIStub: physical.systemEI.(*qualD20Prelude).SystemEIStub}
	context.invoke = func(run func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
		_, _ = run(lease)
		return vmcommon.Ok, nil
	}
	physical.systemEI = context
	code, err := physical.WithDRWANativeCall(tx, nil, accounts, func(vm.DRWANativeCallHandoff) (vmcommon.ReturnCode, error) {
		return vmcommon.Ok, nil
	})
	require.Equal(t, vmcommon.ExecutionFailed, code)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Zero(t, lease.calls)
	require.Empty(t, *trace)
}

type qualSP281CLaneFNativeSource struct {
	*qualD20Prelude
	source *qualD20HandoffContext
}

func (s *qualSP281CLaneFNativeSource) WithDRWANativeCall(tx data.TransactionHandler, evidence any, accounts state.AccountsAdapter,
	target vmcommon.VMExecutionHandler, execute func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
	return s.source.WithDRWANativeCall(tx, evidence, accounts, target, execute)
}

func TestQualSP281CLaneFPhysicalVMReturnsUsedHandoffResult(t *testing.T) {
	physical, trace := qualD20Physical(t)
	tx := &transaction.Transaction{}
	accounts := &stateMock.AccountsStub{}
	input := qualD20CallInput()
	lease := &qualSP281CLaneFLease{qualD20CallLease: &qualD20CallLease{expected: qualD20CallInput()}, tx: tx, accounts: accounts}
	unexpected := func(vm.DRWANativeCallHandoff) (vmcommon.ReturnCode, error) {
		t.Fatal("a native handoff requires the source and transaction")
		return vmcommon.ExecutionFailed, nil
	}
	code, err := physical.WithDRWANativeCall(nil, nil, accounts, unexpected)
	require.Equal(t, vmcommon.ExecutionFailed, code)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	code, err = physical.WithDRWANativeCall(tx, nil, accounts, unexpected)
	require.Equal(t, vmcommon.ExecutionFailed, code)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	source := &qualD20HandoffContext{invoke: func(run func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
		return run(lease)
	}}
	physical.systemEI = &qualSP281CLaneFNativeSource{qualD20Prelude: physical.systemEI.(*qualD20Prelude), source: source}
	var returned vm.DRWANativeCallHandoff
	code, err = physical.WithDRWANativeCall(tx, nil, accounts, func(handoff vm.DRWANativeCallHandoff) (vmcommon.ReturnCode, error) {
		returned = handoff
		require.NoError(t, physical.ValidateDRWANativeTransaction(handoff, tx, accounts, nil, nil))
		require.NoError(t, physical.BindDRWANativeCall(handoff, input))
		output, dispatchErr := physical.RunSmartContractCallWithDRWA(input, handoff)
		require.NoError(t, dispatchErr)
		return output.ReturnCode, nil
	})
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, code)
	require.Equal(t, []string{"clean", "address", "value", "gas", "contract", "execute", "output"}, *trace)
	_, err = physical.RunSmartContractCallWithDRWA(input, returned)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Equal(t, 2, lease.calls)
}
