package process

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualDRWAStatusContext struct {
	*mock.SystemEIStub
	failure error
}

func (c *qualDRWAStatusContext) DRWAExecutionError() error { return c.failure }

// DS02-M7: expose the same native context error without clearing, translating
// or creating a second latch. The inherited gas fixture is experimental (R7).
func TestQualDRWAVMStatusForwarding(t *testing.T) {
	for _, shape := range []string{"marker", "wrapped", "joined", "healthy", "legacy_context"} {
		t.Run(shape, func(t *testing.T) {
			failure := vm.ErrDRWAExecution
			switch shape {
			case "wrapped":
				failure = fmt.Errorf("experimental context: %w", failure)
			case "joined":
				failure = errors.Join(failure, errors.New("experimental rollback failure"))
			case "healthy", "legacy_context":
				failure = nil
			}
			args := createMockArguments()
			if shape != "legacy_context" {
				args.SystemEI = &qualDRWAStatusContext{SystemEIStub: &mock.SystemEIStub{}, failure: failure}
			}
			runtime, err := NewSystemVM(args)
			require.NoError(t, err)
			reader, exists := interface{}(runtime).(interface{ DRWAExecutionError() error })
			require.True(t, exists, "native System VM must expose its retained context error")
			if failure == nil {
				require.NoError(t, reader.DRWAExecutionError())
			} else {
				require.Same(t, failure, reader.DRWAExecutionError())
			}
		})
	}
}

// This spy is an ordinary native context without DRWASystemCallContext.
// Its ordinary contract return is not a registration verifier or permission.
type qualT01MissingContextEI struct {
	*mock.SystemEIStub
	effects map[string]int
}

func (e *qualT01MissingContextEI) CleanCache() {
	e.effects["cache"]++
}

func (e *qualT01MissingContextEI) SetSCAddress(_ []byte) {
	e.effects["address"]++
}

func (e *qualT01MissingContextEI) SetGasProvided(_ uint64) {
	e.effects["gas"]++
}

func (e *qualT01MissingContextEI) AddTxValueToSmartContract(_ *big.Int, _ []byte) {
	e.effects["value"]++
}

func (e *qualT01MissingContextEI) GetContract(_ []byte) (vm.SystemSmartContract, error) {
	e.effects["contract_lookup"]++
	return &mock.SystemSCStub{ExecuteCalled: func(*vmcommon.ContractCallInput) vmcommon.ReturnCode {
		e.effects["contract_execute"]++
		return vmcommon.Ok
	}}, nil
}

func (e *qualT01MissingContextEI) CreateVMOutput() *vmcommon.VMOutput {
	e.effects["output"]++
	return &vmcommon.VMOutput{}
}

func (e *qualT01MissingContextEI) GetReturnMessage() string {
	e.effects["return_message"]++
	return ""
}

func TestQualA72UnconfiguredRegistrationUsesNativeEffects(t *testing.T) {
	for _, recipient := range []struct {
		name    string
		address []byte
	}{
		{name: "esdt", address: core.ESDTSCAddress},
		{name: "wrong_recipient", address: []byte("not-esdt")},
	} {
		for _, value := range []int64{0, 1} {
			t.Run(fmt.Sprintf("%s/value_%d", recipient.name, value), func(t *testing.T) {
				effects := map[string]int{
					"cache": 0, "address": 0, "gas": 0, "value": 0,
					"contract_lookup": 0, "contract_execute": 0, "output": 0, "return_message": 0,
				}
				host := &qualT01MissingContextEI{SystemEIStub: &mock.SystemEIStub{}, effects: effects}
				_, protectedContext := interface{}(host).(vm.DRWASystemCallContext)
				require.False(t, protectedContext)
				args := createMockArguments()
				args.SystemEI = host
				runtime, err := NewSystemVM(args)
				require.NoError(t, err)

				output, err := runtime.RunSmartContractCall(&vmcommon.ContractCallInput{
					VMInput: vmcommon.VMInput{
						CallValue: big.NewInt(value), GasProvided: 1,
					},
					RecipientAddr: append([]byte(nil), recipient.address...),
					Function:      "DRWARegisterToken",
				})
				t.Logf("ordinary effects: %v", effects)
				for _, effect := range []string{"cache", "address", "gas", "value", "contract_lookup", "contract_execute", "output", "return_message"} {
					want := 1
					if effect == "return_message" {
						want = 0
					}
					require.Equal(t, want, effects[effect], "native ordinary callback %s", effect)
				}
				require.NoError(t, err)
				require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, output)
			})
		}
	}
}

// A11 synthetic ordinary controls run on untouched entry source before the
// protected-install guard is edited. They convey no native DRWA authority.
type qualA11OrdinaryEI struct {
	*qualT01MissingContextEI
	code        vmcommon.ReturnCode
	lookupError error
}

func (e *qualA11OrdinaryEI) GetContract(_ []byte) (vm.SystemSmartContract, error) {
	e.effects["contract_lookup"]++
	if e.lookupError != nil {
		return nil, e.lookupError
	}
	return &mock.SystemSCStub{ExecuteCalled: func(*vmcommon.ContractCallInput) vmcommon.ReturnCode {
		e.effects["contract_execute"]++
		return e.code
	}}, nil
}
func TestQualA11OrdinarySystemVMEntryComparison(t *testing.T) {
	for _, shape := range []string{"success", "denial", "unknown", "init", "near_name"} {
		t.Run(shape, func(t *testing.T) {
			effects := map[string]int{}
			host := &qualA11OrdinaryEI{qualT01MissingContextEI: &qualT01MissingContextEI{SystemEIStub: &mock.SystemEIStub{}, effects: effects}, code: vmcommon.Ok}
			fn := "ordinary"
			if shape == "denial" {
				host.code = vmcommon.UserError
			}
			if shape == "unknown" {
				host.lookupError = errors.New("synthetic unknown")
			}
			if shape == "init" {
				fn = core.SCDeployInitFunctionName
			}
			if shape == "near_name" {
				fn = "DRWAInstallInitialProgrammeAuthoritiesSuffix"
			}
			args := createMockArguments()
			args.SystemEI = host
			runtime, err := NewSystemVM(args)
			require.NoError(t, err)
			output, err := runtime.RunSmartContractCall(&vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallValue: big.NewInt(7), GasProvided: 101}, RecipientAddr: []byte("ordinary"), Function: fn})
			want := map[string]int{"cache": 1, "address": 1, "value": 1, "gas": 1, "contract_lookup": 1}
			switch shape {
			case "unknown":
				require.ErrorIs(t, err, vm.ErrUnknownSystemSmartContract)
				require.Nil(t, output)
			case "init":
				require.NoError(t, err)
				require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.UserError, ReturnMessage: "cannot call smart contract init function"}, output)
			case "denial":
				want["contract_execute"] = 1
				want["return_message"] = 1
				require.NoError(t, err)
				require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.UserError, GasRefund: big.NewInt(0)}, output)
			default:
				want["contract_execute"] = 1
				want["output"] = 1
				require.NoError(t, err)
				require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, output)
			}
			require.Equal(t, want, effects)
			t.Logf("A11_ORDINARY shape=%s effects=%v output=%+v error=%v", shape, effects, output, err)
		})
	}
}

func TestQualA72UnconfiguredInstallationUsesNativeEffects(t *testing.T) {
	for _, recipient := range [][]byte{nil, core.ESDTSCAddress, []byte("foreign")} {
		for _, value := range []int64{0, 1} {
			t.Run(fmt.Sprintf("recipient_%x/value_%d", recipient, value), func(t *testing.T) {
				effects := map[string]int{}
				host := &qualT01MissingContextEI{SystemEIStub: &mock.SystemEIStub{}, effects: effects}
				args := createMockArguments()
				args.SystemEI = host
				runtime, err := NewSystemVM(args)
				require.NoError(t, err)
				output, err := runtime.RunSmartContractCall(&vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallValue: big.NewInt(value), GasProvided: 100, Arguments: [][]byte{[]byte("synthetic programme"), []byte("synthetic A possession"), []byte("synthetic C possession")}}, RecipientAddr: recipient, Function: "DRWAInstallInitialProgrammeAuthorities"})
				require.NoError(t, err)
				require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, output)
				require.Equal(t, map[string]int{"cache": 1, "address": 1, "gas": 1, "value": 1, "contract_lookup": 1, "contract_execute": 1, "output": 1}, effects)
			})
		}
	}
}
