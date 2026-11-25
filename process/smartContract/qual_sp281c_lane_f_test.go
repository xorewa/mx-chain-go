package smartContract

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualSP281CLaneFToken struct{}

func (*qualSP281CLaneFToken) IsInterfaceNil() bool { return false }

type qualSP281CLaneFPhysical struct {
	*mock.VMExecutionHandlerStub
	configured  bool
	refuse      error
	validations int
}

func (p *qualSP281CLaneFPhysical) DRWANativeCallConfigured() bool { return p.configured }
func (p *qualSP281CLaneFPhysical) WithDRWANativeCall(_ data.TransactionHandler, _ any, _ state.AccountsAdapter,
	run func(vm.DRWANativeCallHandoff) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
	return run(&qualSP281CLaneFToken{})
}
func (p *qualSP281CLaneFPhysical) ValidateDRWANativeTransaction(vm.DRWANativeCallHandoff, data.TransactionHandler,
	state.AccountsAdapter, state.UserAccountHandler, state.UserAccountHandler) error {
	p.validations++
	return p.refuse
}
func (*qualSP281CLaneFPhysical) RunSmartContractCallWithDRWA(*vmcommon.ContractCallInput, vm.DRWANativeCallHandoff) (*vmcommon.VMOutput, error) {
	panic("test must stop before VM execution")
}

func TestQualSP281CLaneFNativeWrapperRetainsPreflightAndOrdinaryFallback(t *testing.T) {
	sentinel := errors.New("inert preflight refusal")
	physical := &qualSP281CLaneFPhysical{VMExecutionHandlerStub: &mock.VMExecutionHandlerStub{}, configured: true, refuse: sentinel}
	lock := &sync.RWMutex{}
	sc := &scProcessor{accounts: &stateMock.AccountsStub{}, wasmVMChangeLocker: lock,
		vmContainer: &mock.VMContainerMock{GetCalled: func([]byte) (vmcommon.VMExecutionHandler, error) { return physical, nil }}}
	tx := &transaction.Transaction{RcvAddr: core.ESDTSCAddress}
	code, err := sc.WithDRWANativeTransaction(tx, nil, nil)
	require.Equal(t, vmcommon.ExecutionFailed, code)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	code, err = sc.ExecuteSmartContractTransactionWithDRWA(tx, nil, nil, nil)
	require.Equal(t, vmcommon.ExecutionFailed, code)
	require.ErrorIs(t, err, sentinel)
	require.Equal(t, 1, physical.validations)
	require.True(t, lock.TryLock())
	lock.Unlock()

	physical.refuse = nil
	sc.economicsFee = &economicsmocks.EconomicsHandlerMock{
		CheckValidityTxValuesCalled: func(actual data.TransactionWithFeeHandler) error {
			require.Same(t, tx, actual)
			return sentinel
		},
	}
	sender := &stateMock.UserAccountStub{}
	_, err = sc.ExecuteSmartContractTransactionWithDRWA(tx, sender, nil, nil)
	require.ErrorIs(t, err, sentinel)
	require.Equal(t, 2, physical.validations)

	physical.configured = false
	code, err = sc.WithDRWANativeTransaction(tx, nil, func(execute vm.DRWANativeSCExecutor) (vmcommon.ReturnCode, error) {
		require.Nil(t, execute)
		require.True(t, lock.TryLock())
		lock.Unlock()
		return vmcommon.UserError, sentinel
	})
	require.Equal(t, vmcommon.UserError, code)
	require.ErrorIs(t, err, sentinel)
	require.Equal(t, 2, physical.validations)
	_, err = sc.ExecuteSmartContractTransactionWithDRWA(tx, sender, nil, nil)
	require.ErrorIs(t, err, sentinel)
	require.Equal(t, 2, physical.validations)
}

func TestQualSP281CLaneFSlowOrdinaryPaymentPreservesRefusal(t *testing.T) {
	tx := &transaction.Transaction{RcvAddr: core.ESDTSCAddress}
	refusal := errors.New("inert payment refusal")
	marshals := 0
	sc := &scProcessor{
		economicsFee: &economicsmocks.EconomicsHandlerMock{
			CheckValidityTxValuesCalled: func(actual data.TransactionWithFeeHandler) error {
				require.Same(t, tx, actual)
				time.Sleep(executeDurationAlarmThreshold + 10*time.Millisecond)
				return refusal
			},
		},
		marshalizer: &marshallerMock.MarshalizerStub{
			MarshalCalled: func(actual interface{}) ([]byte, error) {
				require.Same(t, tx, actual)
				marshals++
				return []byte("inert diagnostic input"), nil
			},
		},
		hasher: blake2b.NewBlake2b(),
	}
	code, err := sc.ExecuteSmartContractTransaction(tx, &stateMock.UserAccountStub{}, nil)
	require.Equal(t, vmcommon.Ok, code)
	require.ErrorIs(t, err, refusal)
	require.Equal(t, 1, marshals)
}
