package process

import (
	"bytes"
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"strings"
	"testing"
)

func createMockArguments() ArgsNewSystemVM {
	gasMap := make(map[string]map[string]uint64)
	gasMap[common.BaseOpsAPICost] = make(map[string]uint64)
	gasMap[common.BaseOpsAPICost][common.AsyncCallStepField] = 1000
	gasMap[common.BaseOpsAPICost][common.AsyncCallbackGasLockField] = 3000
	args := ArgsNewSystemVM{
		SystemEI:        &mock.SystemEIStub{},
		SystemContracts: &mock.SystemSCContainerStub{},
		VmType:          factory.SystemVirtualMachine,
		GasSchedule:     testscommon.NewGasScheduleNotifierMock(gasMap),
	}
	return args
}

func TestNewSystemVM_NilSystemEI(t *testing.T) {
	t.Parallel()

	args := createMockArguments()
	args.SystemEI = nil
	sVM, err := NewSystemVM(args)

	assert.Nil(t, sVM)
	assert.Equal(t, vm.ErrNilSystemEnvironmentInterface, err)
}

func TestNewSystemVM_NilContainer(t *testing.T) {
	t.Parallel()

	args := createMockArguments()
	args.SystemContracts = nil
	sVM, err := NewSystemVM(args)

	assert.Nil(t, sVM)
	assert.Equal(t, vm.ErrNilSystemContractsContainer, err)
}

func TestNewSystemVM_NilVMType(t *testing.T) {
	t.Parallel()

	args := createMockArguments()
	args.VmType = nil
	sVM, err := NewSystemVM(args)

	assert.Nil(t, sVM)
	assert.Equal(t, vm.ErrNilVMType, err)
}

func TestNewSystemVM_NilGasSchedule(t *testing.T) {
	t.Parallel()

	args := createMockArguments()
	args.GasSchedule = nil
	sVM, err := NewSystemVM(args)

	assert.Nil(t, sVM)
	assert.Equal(t, vm.ErrNilGasSchedule, err)
}

func TestNewSystemVM_NoApiCost(t *testing.T) {
	t.Parallel()

	args := createMockArguments()
	gasMap := make(map[string]map[string]uint64)
	args.GasSchedule = testscommon.NewGasScheduleNotifierMock(gasMap)
	sVM, err := NewSystemVM(args)

	assert.Nil(t, sVM)
	assert.Equal(t, vm.ErrNilGasSchedule, err)

	gasMap[common.BaseOpsAPICost] = make(map[string]uint64)
	args.GasSchedule = testscommon.NewGasScheduleNotifierMock(gasMap)
	sVM, err = NewSystemVM(args)

	assert.Nil(t, sVM)
	assert.Equal(t, vm.ErrNilGasSchedule, err)
}

func TestNewSystemVM_Ok(t *testing.T) {
	t.Parallel()

	args := createMockArguments()
	sVM, err := NewSystemVM(args)

	assert.Nil(t, err)
	assert.NotNil(t, sVM)
}

func TestSystemVM_RunSmartContractCreate(t *testing.T) {
	t.Parallel()

	args := createMockArguments()
	sVM, _ := NewSystemVM(args)

	vmOutput, err := sVM.RunSmartContractCreate(nil)
	assert.Nil(t, vmOutput)
	assert.Equal(t, vm.ErrInputArgsIsNil, err)

	vmOutput, err = sVM.RunSmartContractCreate(&vmcommon.ContractCreateInput{})
	assert.Nil(t, vmOutput)
	assert.Equal(t, vm.ErrInputCallerAddrIsNil, err)
}

func TestSystemVM_RunSmartContractCallWrongSmartContract(t *testing.T) {
	t.Parallel()

	args := createMockArguments()
	args.SystemEI = &mock.SystemEIStub{GetContractCalled: func(address []byte) (vm.SystemSmartContract, error) {
		return nil, vm.ErrUnknownSystemSmartContract
	}}
	sVM, _ := NewSystemVM(args)

	vmOutput, err := sVM.RunSmartContractCall(&vmcommon.ContractCallInput{RecipientAddr: []byte("dummyAddress")})
	assert.Nil(t, vmOutput)
	assert.Equal(t, vm.ErrUnknownSystemSmartContract, err)
}

func TestSystemVM_RunSmartContractCall(t *testing.T) {
	t.Parallel()

	sc := &mock.SystemSCStub{ExecuteCalled: func(args *vmcommon.ContractCallInput) vmcommon.ReturnCode {
		return vmcommon.Ok
	}}
	scAddress := []byte("dummyAddress")

	container := &mock.SystemSCContainerStub{GetCalled: func(key []byte) (contract vm.SystemSmartContract, e error) {
		if bytes.Equal(scAddress, key) {
			return sc, nil
		}
		return nil, vm.ErrUnknownSystemSmartContract
	}}

	args := createMockArguments()
	args.SystemContracts = container
	sVM, _ := NewSystemVM(args)

	vmOutput, err := sVM.RunSmartContractCall(&vmcommon.ContractCallInput{RecipientAddr: scAddress})
	assert.Nil(t, err)
	assert.Equal(t, vmcommon.Ok, vmOutput.ReturnCode)
}

type vMCallGuard struct {
	*mock.SystemEIStub
	denial  error
	entries int
}

func (c *vMCallGuard) ExecuteDRWASystemCall(_ *vmcommon.ContractCallInput, execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	c.entries++
	if c.denial != nil {
		return nil, c.denial
	}
	return execute()
}

type vMReplacement struct {
	*mock.SystemEIStub
	called bool
	denial error
}

func (c *vMReplacement) ReplaceDRWAClassifier(vm.DRWATokenClassifier) error {
	c.called = true
	return c.denial
}

// Compare the same native operation/output under legacy and guarded wrappers.
// Expected init dispatch and failure shape are from the pinned native source.
func TestSystemVM_RunSmartContractCreateNativeSemantics(t *testing.T) {
	for _, guarded := range []bool{false, true} {
		for _, unknown := range []bool{false, true} {
			t.Run(strings.ReplaceAll(map[bool]string{false: "legacy", true: "guarded"}[guarded]+map[bool]string{false: "/native", true: "/unknown"}[unknown], "/", " ")+" should preserve the expected result", func(t *testing.T) {
				clean, codes, executions := 0, 0, 0
				address := []byte("synthetic-system-address")
				code := []byte("native-code-fixture")
				output := &vmcommon.VMOutput{ReturnData: [][]byte{[]byte("native-result")}, GasRemaining: 17}
				ctx := &mock.SystemEIStub{CleanCacheCalled: func() { clean++ }, AddCodeCalled: func(a, b []byte) { codes++; require.Equal(t, address, a); require.Equal(t, code, b) }, CreateVMOutputCalled: func() *vmcommon.VMOutput { return output }}
				args := createMockArguments()
				args.SystemEI = ctx
				if guarded {
					args.SystemEI = &vMCallGuard{SystemEIStub: ctx}
				}
				args.SystemContracts = &mock.SystemSCContainerStub{GetCalled: func(a []byte) (vm.SystemSmartContract, error) {
					require.Equal(t, address, a)
					if unknown {
						return nil, errors.New("native contract missing")
					}
					return &mock.SystemSCStub{ExecuteCalled: func(input *vmcommon.ContractCallInput) vmcommon.ReturnCode {
						executions++
						require.Equal(t, core.SCDeployInitFunctionName, input.Function)
						require.Equal(t, address, input.RecipientAddr)
						return vmcommon.Ok
					}}, nil
				}}
				runtime, err := NewSystemVM(args)
				require.NoError(t, err)
				actual, err := runtime.RunSmartContractCreate(&vmcommon.ContractCreateInput{VMInput: vmcommon.VMInput{CallerAddr: address, CallValue: big.NewInt(0)}, ContractCode: code})
				require.Equal(t, 1, clean)
				if unknown {
					require.ErrorIs(t, err, vm.ErrUnknownSystemSmartContract)
					require.Nil(t, actual)
					require.Zero(t, codes)
					require.Zero(t, executions)
				} else {
					require.NoError(t, err)
					require.Same(t, output, actual)
					require.Equal(t, vmcommon.Ok, actual.ReturnCode)
					require.Equal(t, 1, codes)
					require.Equal(t, 1, executions)
				}
			})
		}
	}
}

func TestSystemVM_RunSmartContractCallNativeSemantics(t *testing.T) {
	for _, guarded := range []bool{false, true} {
		for _, mode := range []string{"success", "native denial", "direct init", "unknown"} {
			t.Run(strings.ReplaceAll(map[bool]string{false: "legacy", true: "guarded"}[guarded]+"/"+mode, "/", " ")+" should preserve the expected result", func(t *testing.T) {
				executions := 0
				output := &vmcommon.VMOutput{GasRemaining: 17, GasRefund: big.NewInt(2), ReturnData: [][]byte{[]byte("native-result")}}
				contract := &mock.SystemSCStub{ExecuteCalled: func(*vmcommon.ContractCallInput) vmcommon.ReturnCode {
					executions++
					if mode == "native denial" {
						return vmcommon.UserError
					}
					return vmcommon.Ok
				}}
				ctx := &mock.SystemEIStub{ReturnMessage: "native rejection reason", CreateVMOutputCalled: func() *vmcommon.VMOutput { return output }, GetContractCalled: func([]byte) (vm.SystemSmartContract, error) {
					if mode == "unknown" {
						return nil, errors.New("absent")
					}
					return contract, nil
				}}
				args := createMockArguments()
				args.SystemEI = ctx
				if guarded {
					args.SystemEI = &vMCallGuard{SystemEIStub: ctx}
				}
				runtime, err := NewSystemVM(args)
				require.NoError(t, err)
				function := "native-operation"
				if mode == "direct init" {
					function = core.SCDeployInitFunctionName
				}
				actual, err := runtime.RunSmartContractCall(&vmcommon.ContractCallInput{RecipientAddr: []byte("synthetic-system-address"), Function: function, VMInput: vmcommon.VMInput{CallValue: big.NewInt(0)}})
				switch mode {
				case "unknown":
					require.ErrorIs(t, err, vm.ErrUnknownSystemSmartContract)
					require.Nil(t, actual)
					require.Zero(t, executions)
				case "direct init":
					require.NoError(t, err)
					require.Equal(t, vmcommon.UserError, actual.ReturnCode)
					require.Zero(t, executions)
				case "native denial":
					require.NoError(t, err)
					require.Equal(t, vmcommon.UserError, actual.ReturnCode)
					require.Zero(t, actual.GasRemaining)
					require.Equal(t, big.NewInt(0), actual.GasRefund)
					require.Equal(t, "native rejection reason", actual.ReturnMessage)
					require.Equal(t, 1, executions)
				default:
					require.NoError(t, err)
					require.Same(t, output, actual)
					require.Equal(t, vmcommon.Ok, actual.ReturnCode)
					require.Equal(t, 1, executions)
				}
			})
		}
	}
}

func TestSystemVM_RunSmartContractCreateBeforeEffect(t *testing.T) {
	for _, create := range []bool{false, true} {
		t.Run(strings.ReplaceAll(map[bool]string{false: "call", true: "create"}[create], "/", " ")+" should preserve the expected result", func(t *testing.T) {
			sentinel := errors.New("classifier unavailable")
			effects := 0
			ctx := &vMCallGuard{SystemEIStub: &mock.SystemEIStub{CleanCacheCalled: func() { effects++ }, AddCodeCalled: func([]byte, []byte) { effects++ }, AddTxValueToSmartContractCalled: func(*big.Int, []byte) { effects++ }}, denial: sentinel}
			args := createMockArguments()
			args.SystemEI = ctx
			runtime, err := NewSystemVM(args)
			require.NoError(t, err)
			var out *vmcommon.VMOutput
			if create {
				out, err = runtime.RunSmartContractCreate(&vmcommon.ContractCreateInput{VMInput: vmcommon.VMInput{CallerAddr: []byte("synthetic-system-address")}})
			} else {
				out, err = runtime.RunSmartContractCall(&vmcommon.ContractCallInput{RecipientAddr: []byte("synthetic-system-address")})
			}
			require.ErrorIs(t, err, sentinel)
			require.Nil(t, out)
			require.Equal(t, 1, ctx.entries)
			require.Zero(t, effects)
		})
	}
}

func TestSystemVM_ReplaceDRWAClassifier(t *testing.T) {
	sentinel := errors.New("native owner denied replacement")
	for _, mode := range []string{"legacy", "denied", "success"} {
		t.Run(strings.ReplaceAll(mode, "/", " ")+" should preserve the expected result", func(t *testing.T) {
			args := createMockArguments()
			ctx := &vMReplacement{SystemEIStub: &mock.SystemEIStub{}}
			if mode != "legacy" {
				args.SystemEI = ctx
			}
			if mode == "denied" {
				ctx.denial = sentinel
			}
			runtime, err := NewSystemVM(args)
			require.NoError(t, err)
			err = runtime.ReplaceDRWAClassifier(nil)
			if mode == "legacy" {
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.False(t, ctx.called)
			} else {
				require.True(t, ctx.called)
				require.ErrorIs(t, err, ctx.denial)
			}
		})
	}
}
