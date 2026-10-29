package process

import (
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type sp1VMCallGuard struct {
	*mock.SystemEIStub
	denial  error
	entries int
}

func (c *sp1VMCallGuard) ExecuteDRWASystemCall(_ *vmcommon.ContractCallInput, execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	c.entries++
	if c.denial != nil {
		return nil, c.denial
	}
	return execute()
}

type sp1VMReplacement struct {
	*mock.SystemEIStub
	called bool
	denial error
}

func (c *sp1VMReplacement) ReplaceDRWAClassifier(vm.DRWATokenClassifier) error {
	c.called = true
	return c.denial
}

// Compare the same native operation/output under legacy and guarded wrappers.
// Expected init dispatch and failure shape are from the pinned native source.
func TestSP1CoverageSystemVMCreate(t *testing.T) {
	for _, guarded := range []bool{false, true} {
		for _, unknown := range []bool{false, true} {
			t.Run(map[bool]string{false: "legacy", true: "guarded"}[guarded]+map[bool]string{false: "/native", true: "/unknown"}[unknown], func(t *testing.T) {
				clean, codes, executions := 0, 0, 0
				address := []byte("synthetic-system-address")
				code := []byte("native-code-fixture")
				output := &vmcommon.VMOutput{ReturnData: [][]byte{[]byte("native-result")}, GasRemaining: 17}
				ctx := &mock.SystemEIStub{CleanCacheCalled: func() { clean++ }, AddCodeCalled: func(a, b []byte) { codes++; require.Equal(t, address, a); require.Equal(t, code, b) }, CreateVMOutputCalled: func() *vmcommon.VMOutput { return output }}
				args := createMockArguments()
				args.SystemEI = ctx
				if guarded {
					args.SystemEI = &sp1VMCallGuard{SystemEIStub: ctx}
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
func TestSP1CoverageSystemVMCall(t *testing.T) {
	for _, guarded := range []bool{false, true} {
		for _, mode := range []string{"success", "native denial", "direct init", "unknown"} {
			t.Run(map[bool]string{false: "legacy", true: "guarded"}[guarded]+"/"+mode, func(t *testing.T) {
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
					args.SystemEI = &sp1VMCallGuard{SystemEIStub: ctx}
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
func TestSP1CoverageSystemVMBeforeEffect(t *testing.T) {
	for _, create := range []bool{false, true} {
		t.Run(map[bool]string{false: "call", true: "create"}[create], func(t *testing.T) {
			sentinel := errors.New("classifier unavailable")
			effects := 0
			ctx := &sp1VMCallGuard{SystemEIStub: &mock.SystemEIStub{CleanCacheCalled: func() { effects++ }, AddCodeCalled: func([]byte, []byte) { effects++ }, AddTxValueToSmartContractCalled: func(*big.Int, []byte) { effects++ }}, denial: sentinel}
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
func TestSP1CoverageSystemVMReplacementForward(t *testing.T) {
	sentinel := errors.New("native owner denied replacement")
	for _, mode := range []string{"legacy", "denied", "success"} {
		t.Run(mode, func(t *testing.T) {
			args := createMockArguments()
			ctx := &sp1VMReplacement{SystemEIStub: &mock.SystemEIStub{}}
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
