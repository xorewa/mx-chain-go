package process

import (
	"bytes"
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/state"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"math/big"
	"reflect"
	"sync"
	"testing"
)

// Mechanical PRIVATE-token fixtures only. No source below is installed in the
// real vmContext, authenticates an EOA/appointment, or supplies canonical G6/B
// history/funding. Explicit inputs are synthetic; they are not profile defaults.
type qualD20CallLease struct {
	expected *vmcommon.ContractCallInput
	denial   error
	calls    int
}

// Check an independently chosen fixture, never accept arbitrary bound bytes.
func (l *qualD20CallLease) BindCall(in *vmcommon.ContractCallInput) error {
	if !reflect.DeepEqual(in, l.expected) {
		return vm.ErrDRWAExecution
	}
	return nil
}
func (l *qualD20CallLease) VerifyTransaction(data.TransactionHandler, state.AccountsAdapter, state.UserAccountHandler, state.UserAccountHandler) error {
	return vm.ErrDRWAExecution
}
func (l *qualD20CallLease) IsInterfaceNil() bool { return l == nil }
func (l *qualD20CallLease) VerifyCall(in *vmcommon.ContractCallInput) error {
	l.calls++
	if l.denial != nil {
		return l.denial
	}
	if !reflect.DeepEqual(in, l.expected) {
		return vm.ErrDRWAExecution
	}
	return nil
}

type qualD20HandoffContext struct {
	*mock.SystemEIStub
	invoke func(func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error)
}

func (c *qualD20HandoffContext) WithDRWANativeCall(_ data.TransactionHandler, _ any, _ state.AccountsAdapter,
	_ vmcommon.VMExecutionHandler, execute func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
	return c.invoke(execute)
}

type qualD20ForgedHandoff struct{}

func (*qualD20ForgedHandoff) IsInterfaceNil() bool { return false }

type qualD20Prelude struct {
	*mock.SystemEIStub
	trace *[]string
}

func (c *qualD20Prelude) SetSCAddress([]byte)   { *c.trace = append(*c.trace, "address") }
func (c *qualD20Prelude) SetGasProvided(uint64) { *c.trace = append(*c.trace, "gas") }
func qualD20CallInput() *vmcommon.ContractCallInput {
	return &vmcommon.ContractCallInput{RecipientAddr: bytes.Clone(core.ESDTSCAddress), Function: "synthetic-native-call",
		VMInput: vmcommon.VMInput{CallerAddr: bytes.Repeat([]byte{1}, 32), Arguments: [][]byte{[]byte("fixture")}, CallValue: big.NewInt(17), GasProvided: 31}}
}
func qualD20Physical(t *testing.T) (*systemVM, *[]string) {
	t.Helper()
	trace := []string{}
	stub := &mock.SystemEIStub{CleanCacheCalled: func() { trace = append(trace, "clean") },
		AddTxValueToSmartContractCalled: func(v *big.Int, a []byte) {
			require.Equal(t, big.NewInt(17), v)
			require.Equal(t, core.ESDTSCAddress, a)
			trace = append(trace, "value")
		},
		GetContractCalled: func([]byte) (vm.SystemSmartContract, error) {
			trace = append(trace, "contract")
			return &mock.SystemSCStub{ExecuteCalled: func(*vmcommon.ContractCallInput) vmcommon.ReturnCode {
				trace = append(trace, "execute")
				return vmcommon.Ok
			}}, nil
		},
		CreateVMOutputCalled: func() *vmcommon.VMOutput {
			trace = append(trace, "output")
			return &vmcommon.VMOutput{GasRemaining: 23, GasRefund: big.NewInt(2)}
		}}
	args := createMockArguments()
	args.SystemEI = &qualD20Prelude{stub, &trace}
	s, err := NewSystemVM(args)
	require.NoError(t, err)
	return s, &trace
}
func TestQualD20NativeHandoffPrivateToken(t *testing.T) {
	for _, name := range []string{"exact", "nil", "forged", "foreign", "expired", "used", "nil-lease", "denied-lease", "changed-input", "busy"} {
		t.Run(name, func(t *testing.T) {
			s, trace := qualD20Physical(t)
			in := qualD20CallInput()
			lease := &qualD20CallLease{expected: qualD20CallInput()}
			call := &drwaNativeCall{vm: s, lease: lease, active: true, validated: true, prepared: qualD20CallInput()}
			var token vm.DRWANativeCallHandoff = call
			switch name {
			case "nil":
				token = nil
			case "forged":
				token = &qualD20ForgedHandoff{}
			case "foreign":
				call.vm, _ = qualD20Physical(t)
			case "expired":
				call.active = false
			case "used":
				call.used = true
			case "nil-lease":
				call.lease = nil
			case "denied-lease":
				lease.denial = vm.ErrDRWAExecution
			case "changed-input":
				in.Arguments[0] = []byte("other")
			case "busy":
				s.criticalSection.Lock()
				defer s.criticalSection.Unlock()
			}
			out, err := s.RunSmartContractCallWithDRWA(in, token)
			if name != "exact" {
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.Nil(t, out)
				require.Empty(t, *trace)
				return
			}
			require.NoError(t, err)
			require.Equal(t, vmcommon.Ok, out.ReturnCode)
			require.Equal(t, uint64(23), out.GasRemaining)
			require.Equal(t, []string{"clean", "address", "value", "gas", "contract", "execute", "output"}, *trace)
			require.Equal(t, 2, lease.calls)
			before := append([]string(nil), (*trace)...)
			out, err = s.RunSmartContractCallWithDRWA(in, token)
			require.ErrorIs(t, err, vm.ErrDRWAExecution)
			require.Nil(t, out)
			require.Equal(t, before, *trace)
		})
	}
}
func TestQualD20NativeHandoffMissingAndEndedSource(t *testing.T) {
	s, trace := qualD20Physical(t)
	tx := &transaction.Transaction{RcvAddr: bytes.Clone(core.ESDTSCAddress)}
	accounts := &stateMock.AccountsStub{}
	called := 0
	_, err := s.WithDRWANativeCall(tx, struct{}{}, accounts, func(vm.DRWANativeCallHandoff) (vmcommon.ReturnCode, error) { called++; return vmcommon.Ok, nil })
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Zero(t, called)
	require.Empty(t, *trace)
	for _, mode := range []string{"missing-callback", "nil-lease", "swallowed-error", "repeat-callback", "late-callback", "concurrent-callback"} {
		t.Run(mode, func(t *testing.T) {
			sentinel := errors.New("synthetic native-source refusal")
			var saved vm.DRWANativeCallHandoff
			var later func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error)
			context := &qualD20HandoffContext{SystemEIStub: &mock.SystemEIStub{}}
			context.invoke = func(cb func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
				later = cb
				lease := &qualD20CallLease{denial: sentinel}
				switch mode {
				case "missing-callback":
					return vmcommon.Ok, nil
				case "nil-lease":
					_, _ = cb(nil)
				case "repeat-callback":
					_, _ = cb(lease)
					_, _ = cb(lease)
				case "concurrent-callback":
					var wg sync.WaitGroup
					for i := 0; i < 4; i++ {
						wg.Add(1)
						go func() { defer wg.Done(); _, _ = cb(&qualD20CallLease{denial: sentinel}) }()
					}
					wg.Wait()
				default:
					_, _ = cb(lease)
				}
				return vmcommon.Ok, nil
			}
			args := createMockArguments()
			args.SystemEI = context
			physical, e := NewSystemVM(args)
			require.NoError(t, e)
			_, e = physical.WithDRWANativeCall(tx, nil, accounts, func(token vm.DRWANativeCallHandoff) (vmcommon.ReturnCode, error) {
				saved = token
				return vmcommon.ExecutionFailed, sentinel
			})
			require.Error(t, e)
			if saved != nil {
				out, e := physical.RunSmartContractCallWithDRWA(qualD20CallInput(), saved)
				require.ErrorIs(t, e, vm.ErrDRWAExecution)
				require.Nil(t, out)
			}
			if mode == "late-callback" {
				_, e = later(&qualD20CallLease{denial: sentinel})
				require.ErrorIs(t, e, vm.ErrDRWAExecution)
			}
		})
	}
}

// Reproduces a pre-effect ordering defect in the producer's private token,
// without installing an authentication source or admitting a native positive.
func TestQualD20NativeHandoffStickyPreflight(t *testing.T) {
	physical, trace := qualD20Physical(t)
	call := &drwaNativeCall{vm: physical, lease: &qualD20CallLease{expected: qualD20CallInput()}, active: true}
	call.mut.Lock()
	err := physical.ValidateDRWANativeTransaction(call, &transaction.Transaction{}, &stateMock.AccountsStub{}, nil, nil)
	call.mut.Unlock()
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	output, err := physical.RunSmartContractCallWithDRWA(qualD20CallInput(), call)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Nil(t, output)
	require.Empty(t, *trace, "a known sticky provenance failure must precede the native prelude")
}

// A source lease alone cannot authorize gas/call bytes not produced by SC preparation.
func TestQualD20NativeCallRequiresPreparedBinding(t *testing.T) {
	physical, trace := qualD20Physical(t)
	input := qualD20CallInput()
	token := &drwaNativeCall{vm: physical, lease: &qualD20CallLease{expected: qualD20CallInput()}, active: true}
	output, err := physical.RunSmartContractCallWithDRWA(input, token)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Nil(t, output)
	require.Empty(t, *trace, "unbound effective call must be rejected before native value/gas/output effects")
}

// Mechanical prepared-call transport only; the independent fixture lease is
// not an installed native authentication, G6, appointment or funding producer.
func TestQualD20NativePreparedCallBinding(t *testing.T) {
	for _, change := range []string{"exact", "gas", "caller", "arguments", "value", "function", "hash", "guardian", "recipient", "original-caller", "relayer", "expired", "foreign", "rebind"} {
		t.Run(change, func(t *testing.T) {
			physical, trace := qualD20Physical(t)
			input := qualD20CallInput()
			lease := &qualD20CallLease{expected: qualD20CallInput()}
			call := &drwaNativeCall{vm: physical, lease: lease, active: true, validated: true}
			require.NoError(t, physical.BindDRWANativeCall(call, input))
			switch change {
			case "gas":
				input.GasProvided++
			case "caller":
				input.CallerAddr[0] ^= 1
			case "arguments":
				input.Arguments[0][0] ^= 1
			case "value":
				input.CallValue.Add(input.CallValue, big.NewInt(1))
			case "function":
				input.Function = "other"
			case "hash":
				input.CurrentTxHash = []byte("different")
			case "guardian":
				input.TxGuardian = []byte("different")
			case "recipient":
				input.RecipientAddr[0] ^= 1
			case "original-caller":
				input.OriginalCallerAddr = []byte("different")
			case "relayer":
				input.RelayerAddr = []byte("different")
			case "expired":
				call.active = false
			case "foreign":
				physical, _ = qualD20Physical(t)
			case "rebind":
				require.ErrorIs(t, physical.BindDRWANativeCall(call, input), vm.ErrDRWAExecution)
			}
			output, err := physical.RunSmartContractCallWithDRWA(input, call)
			if change == "exact" {
				require.NoError(t, err)
				require.Equal(t, vmcommon.Ok, output.ReturnCode)
				require.Equal(t, []string{"clean", "address", "value", "gas", "contract", "execute", "output"}, *trace)
			} else {
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.Nil(t, output)
				require.Empty(t, *trace)
			}
		})
	}
}

func TestQualD20PreparedCallRequiresTransactionValidation(t *testing.T) {
	physical, trace := qualD20Physical(t)
	token := &drwaNativeCall{vm: physical, lease: &qualD20CallLease{expected: qualD20CallInput()}, active: true}
	require.ErrorIs(t, physical.BindDRWANativeCall(token, qualD20CallInput()), vm.ErrDRWAExecution)
	require.Empty(t, *trace)
}
