package systemSmartContracts

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmprocess "github.com/multiversx/mx-chain-go/vm/process"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Architecture INV-0 / 4.5.1: an ordinary token retains native System-SC
// supply semantics. The classifier is an explicit ordinary-token fixture;
// this exercises native dispatch and output buffers, not a configured node or
// an authenticated DRWA operation owner. The gas schedule is synthetic.
func TestQualFA01OrdinarySystemSCSupplyEquivalence(t *testing.T) {
	for _, function := range []string{"mint", core.BuiltInFunctionESDTBurn} {
		for _, scenario := range []string{"success", "disabled", "zero", "callValue", "arguments", "permission", "gas", "destination", "refund"} {
			if function == "mint" && scenario == "refund" || function != "mint" && (scenario == "destination" || scenario == "permission" || scenario == "gas") {
				continue
			}
			t.Run(function+"/"+scenario, func(t *testing.T) {
				var baseline *vmcommon.VMOutput
				for _, configured := range []bool{false, true} {
					owner := bytes.Repeat([]byte{1}, 32)
					id := []byte("ORD-abcdef")
					args := createMockArgumentsForESDT()
					args.ESDTSCAddress = core.ESDTSCAddress
					args.GasCost.MetaChainSystemSCsCost.ESDTOperations = 7
					if scenario == "disabled" {
						args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).RemoveActiveFlags(common.GlobalMintBurnFlag)
					}
					token := &ESDTDataV2{OwnerAddress: owner, TokenType: []byte(core.FungibleESDT), Mintable: scenario != "permission", Burnable: scenario != "refund", MintedValue: big.NewInt(100), BurntValue: big.NewInt(0)}
					prestate, err := args.Marshalizer.Marshal(token)
					require.NoError(t, err)
					contextArgs := createDefaultEeiArgs()
					contextArgs.BlockChainHook = &mock.BlockChainHookStub{GetStorageDataCalled: func(address, key []byte) ([]byte, uint32, error) {
						if bytes.Equal(address, core.ESDTSCAddress) && bytes.Equal(key, id) {
							return bytes.Clone(prestate), 0, nil
						}
						return nil, 0, nil
					}}
					classifier := &qualGateG21OrdinaryClassifier{}
					if configured {
						contextArgs.DRWAClassifier = classifier
					}
					host, err := NewVMContext(contextArgs)
					require.NoError(t, err)
					host.SetSCAddress(core.ESDTSCAddress)
					args.Eei = host
					contract, err := NewESDTSmartContract(args)
					require.NoError(t, err)
					input := getDefaultVmInputForFunc(function, [][]byte{id, {7}})
					input.CallerAddr, input.RecipientAddr, input.GasProvided = owner, core.ESDTSCAddress, 100
					wantCode, wantMessage, wantGas := vmcommon.Ok, "", uint64(100)
					wantMinted, wantBurnt := int64(100), int64(0)
					wantTransfer := false
					destination := owner
					if function == "mint" {
						wantGas, wantMinted, wantTransfer = 93, 107, true
					} else {
						wantGas, wantBurnt = 0, 7
					}
					switch scenario {
					case "disabled":
						wantCode, wantGas, wantMinted, wantBurnt, wantTransfer = vmcommon.UserError, 100, 100, 0, false
						if function == "mint" {
							wantMessage = "global mint is no more enabled, use local mint"
						} else {
							wantMessage = "global burn is no more enabled, use local burn"
						}
					case "zero":
						input.Arguments[1] = nil
						wantCode, wantMinted, wantBurnt, wantTransfer = vmcommon.UserError, 100, 0, false
						if function == "mint" {
							wantMessage = "negative or zero mint value"
						} else {
							wantGas, wantMessage = 100, "negative or 0 value to burn"
						}
					case "callValue":
						input.CallValue = big.NewInt(1)
						wantCode, wantMessage, wantGas, wantMinted, wantBurnt, wantTransfer = vmcommon.OutOfFunds, "callValue must be 0", 100, 100, 0, false
					case "arguments":
						input.Arguments = input.Arguments[:1]
						wantCode, wantGas, wantMinted, wantBurnt, wantTransfer = vmcommon.FunctionWrongSignature, 100, 100, 0, false
						if function == "mint" {
							wantMessage = "accepted arguments number 2/3"
						} else {
							wantMessage = "number of arguments must be equal with 2"
						}
					case "permission":
						wantCode, wantMessage, wantMinted, wantTransfer = vmcommon.UserError, "token is not mintable", 100, false
					case "gas":
						input.GasProvided = 6
						wantCode, wantMessage, wantGas, wantMinted, wantTransfer = vmcommon.OutOfGas, "not enough gas", 6, 100, false
					case "destination":
						destination = bytes.Repeat([]byte{2}, 32)
						input.Arguments = append(input.Arguments, destination)
					case "refund":
						// Native legacy refund branch returns Ok with an error message;
						// preserve this rather than imposing DRWA supply semantics.
						wantMessage, wantGas, wantBurnt, wantTransfer = "token is not burnable", 100, 0, true
					}
					host.SetGasProvided(input.GasProvided)
					output, err := host.ExecuteDRWASystemCall(input, func() (*vmcommon.VMOutput, error) {
						code := contract.Execute(input)
						require.Equal(t, wantCode, code)
						result := host.CreateVMOutput()
						result.ReturnCode = code
						return result, nil
					})
					require.NoError(t, err)
					require.Equal(t, wantMessage, output.ReturnMessage)
					require.Equal(t, wantGas, output.GasRemaining)
					require.Zero(t, output.GasRefund.Sign())
					require.Empty(t, output.ReturnData)
					require.Empty(t, output.Logs)
					current, err := contract.getExistingToken(id)
					require.NoError(t, err)
					expected := *token
					expected.MintedValue, expected.BurntValue = big.NewInt(wantMinted), big.NewInt(wantBurnt)
					require.Equal(t, &expected, current)
					if wantTransfer {
						transfers := output.OutputAccounts[string(destination)].OutputTransfers
						require.Len(t, transfers, 1)
						require.Equal(t, []byte(core.BuiltInFunctionESDTTransfer+"@"+hex.EncodeToString(id)+"@07"), transfers[0].Data)
						require.Zero(t, transfers[0].Value.Sign())
						require.Zero(t, transfers[0].GasLimit)
					} else {
						for _, account := range output.OutputAccounts {
							require.Empty(t, account.OutputTransfers)
						}
					}
					if configured {
						require.Equal(t, 2, classifier.calls, "public VM boundary and native System-SC entry both classify")
						require.Equal(t, baseline, output)
					} else {
						require.Zero(t, classifier.calls)
						baseline = output
					}
				}
			})
		}
	}
}

// INV-0: an unconfigured context must reach native execution without owning
// the DRWA lock. TryLock observes ownership without timing or blocked goroutines.
func TestQualFA01OrdinarySystemSCNoClassifierLock(t *testing.T) {
	host, err := NewVMContext(createDefaultEeiArgs())
	require.NoError(t, err)
	args := createMockArgumentsForESDT()
	args.Eei = host
	sc, err := NewESDTSmartContract(args)
	require.NoError(t, err)
	observed := false
	args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).IsFlagEnabledCalled = func(flag core.EnableEpochFlag) bool {
		if flag == common.ESDTFlag {
			observed = true
			unlocked := host.mutDRWAClassifier.TryLock()
			if unlocked {
				host.mutDRWAClassifier.Unlock()
			}
			require.True(t, unlocked, "ordinary native dispatch owns the DRWA lock")
		}
		return false
	}
	require.Equal(t, vmcommon.UserError, sc.Execute(&vmcommon.ContractCallInput{
		VMInput:       vmcommon.VMInput{CallValue: big.NewInt(0), CallerAddr: core.ESDTSCAddress},
		RecipientAddr: core.ESDTSCAddress, Function: "pause",
	}))
	require.True(t, observed)
	for _, recipient := range [][]byte{nil, core.ESDTSCAddress} {
		_, err = host.ExecuteDRWASystemCall(&vmcommon.ContractCallInput{RecipientAddr: recipient}, func() (*vmcommon.VMOutput, error) {
			unlocked := host.mutDRWAClassifier.TryLock()
			if unlocked {
				host.mutDRWAClassifier.Unlock()
			}
			require.True(t, unlocked, "ordinary VM boundary owns the DRWA lock")
			return nil, nil
		})
		require.NoError(t, err)
	}
}

type qualFA01HandoffClassifier struct {
	vm.DRWATokenClassifier
	replaced bool
}

func (c *qualFA01HandoffClassifier) IsInterfaceNil() bool { return c == nil }
func (c *qualFA01HandoffClassifier) ValidateAccounts(state.AccountsAdapter, state.AccountsAdapter) error {
	return nil
}
func (c *qualFA01HandoffClassifier) WithDRWAClassifierReplacement(_ vm.DRWATokenClassifier, replace func()) error {
	c.replaced = true
	replace()
	return nil
}

// Isolate the context boundary from the separate System-VM and owner guards.
func TestQualFA01ContextHandoffLock(t *testing.T) {
	old := &qualFA01HandoffClassifier{}
	args := createDefaultEeiArgs()
	args.DRWAClassifier = old
	host, err := NewVMContext(args)
	require.NoError(t, err)
	host.mutDRWAClassifier.RLock()
	err = host.ReplaceDRWAClassifier(&qualFA01HandoffClassifier{})
	host.mutDRWAClassifier.RUnlock()
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.False(t, old.replaced)
	require.Same(t, old, host.drwaClassifier)
}

// These markers and classifier controls are test-local state, not registration
// authority, a native-positive lease, a deployment profile or a proof fixture.
type qualT01NativeState struct {
	address       []byte
	storage       map[string]map[string][]byte
	accounts      map[string]*vmcommon.OutputAccount
	gas           uint64
	message       string
	output        [][]byte
	logs          []*vmcommon.LogEntry
	transferIndex uint32
}

func qualT01SnapshotNativeState(host *vmContext) qualT01NativeState {
	snapshot := qualT01NativeState{
		address: append([]byte(nil), host.scAddress...), storage: make(map[string]map[string][]byte),
		accounts: make(map[string]*vmcommon.OutputAccount), gas: host.gasRemaining,
		message: host.returnMessage, output: make([][]byte, len(host.output)),
		logs: append([]*vmcommon.LogEntry(nil), host.logs...), transferIndex: host.crtTransferIndex,
	}
	for address, values := range host.storageUpdate {
		snapshot.storage[address] = make(map[string][]byte)
		for key, value := range values {
			snapshot.storage[address][key] = append([]byte(nil), value...)
		}
	}
	for address, account := range host.outputAccounts {
		copyAccount := *account
		copyAccount.Address = append([]byte(nil), account.Address...)
		if account.Balance != nil {
			copyAccount.Balance = new(big.Int).Set(account.Balance)
		}
		if account.BalanceDelta != nil {
			copyAccount.BalanceDelta = new(big.Int).Set(account.BalanceDelta)
		}
		snapshot.accounts[address] = &copyAccount
	}
	for index, value := range host.output {
		snapshot.output[index] = append([]byte(nil), value...)
	}
	return snapshot
}

func qualT01SeedNativeState(host *vmContext) {
	host.SetSCAddress([]byte("prior-context"))
	host.storageUpdate = map[string]map[string][]byte{"prior-context": {"key": []byte("prior-value")}}
	host.outputAccounts = map[string]*vmcommon.OutputAccount{
		"prior-context": {Address: []byte("prior-context"), Balance: big.NewInt(11), BalanceDelta: big.NewInt(13)},
	}
	host.SetGasProvided(37)
	host.returnMessage = "prior-message"
	host.output = [][]byte{[]byte("prior-output")}
	host.logs = []*vmcommon.LogEntry{nil}
	host.crtTransferIndex = 9
}

func qualT01NewNativeHost(t *testing.T, configured bool) (*vmContext, *publicOwner) {
	args := createDefaultEeiArgs()
	owner := &publicOwner{publicClassifier: &publicClassifier{}}
	if configured {
		args.DRWAClassifier = owner
	}
	host, err := NewVMContext(args)
	require.NoError(t, err)
	_, nativeContext := interface{}(host).(vm.DRWASystemCallContext)
	require.True(t, nativeContext)
	return host, owner
}

func qualT01OuterNativeCall(t *testing.T, host *vmContext, lookups, executions *int) func(*vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	container := &mock.SystemSCContainerStub{GetCalled: func([]byte) (vm.SystemSmartContract, error) {
		*lookups++
		return &mock.SystemSCStub{ExecuteCalled: func(*vmcommon.ContractCallInput) vmcommon.ReturnCode {
			*executions++
			return vmcommon.UserError
		}}, nil
	}}
	require.NoError(t, host.SetSystemSCContainer(container))
	gas := map[string]map[string]uint64{
		common.BaseOpsAPICost: {common.AsyncCallStepField: 1000, common.AsyncCallbackGasLockField: 3000},
	}
	runtime, err := vmprocess.NewSystemVM(vmprocess.ArgsNewSystemVM{
		SystemEI: host, SystemContracts: container, VmType: factory.SystemVirtualMachine,
		GasSchedule: testscommon.NewGasScheduleNotifierMock(gas),
	})
	require.NoError(t, err)
	return runtime.RunSmartContractCall
}

func qualA72NativeUnknownContextCases(t *testing.T, outer bool) {
	for _, configured := range []bool{false, true} {
		for _, recipient := range []struct {
			name    string
			address []byte
		}{
			{name: "esdt", address: core.ESDTSCAddress},
			{name: "wrong", address: []byte("other-contract")},
			{name: "nil", address: nil},
		} {
			for _, malformed := range []bool{false, true} {
				for _, value := range []int64{0, 1} {
					name := fmt.Sprintf("healthy/configured_%t/%s/malformed_%t/value_%d", configured, recipient.name, malformed, value)
					t.Run(name, func(t *testing.T) {
						host, owner := qualT01NewNativeHost(t, configured)
						calls, lookups, executions := 0, 0, 0
						var invoke func(*vmcommon.ContractCallInput) (*vmcommon.VMOutput, error)
						if outer {
							invoke = qualT01OuterNativeCall(t, host, &lookups, &executions)
						} else {
							invoke = func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
								return host.ExecuteDRWASystemCall(input, func() (*vmcommon.VMOutput, error) {
									calls++
									host.CleanCache()
									host.SetSCAddress(input.RecipientAddr)
									host.SetGasProvided(input.GasProvided)
									host.AddTxValueToSmartContract(input.CallValue, input.RecipientAddr)
									host.Finish([]byte("ordinary-output"))
									return &vmcommon.VMOutput{ReturnCode: vmcommon.UserError}, nil
								})
							}
						}
						// Snapshot after the real constructors and test setup, not before
						// NewVMContext's own CleanCache initialization.
						qualT01SeedNativeState(host)
						before := qualT01SnapshotNativeState(host)
						input := &vmcommon.ContractCallInput{
							VMInput:       vmcommon.VMInput{CallValue: big.NewInt(value), GasProvided: 100},
							RecipientAddr: append([]byte(nil), recipient.address...), Function: "DRWARegisterToken",
						}
						if malformed {
							input.Arguments = [][]byte{[]byte("malformed")}
						}
						output, err := invoke(input)
						t.Logf("ordinary callbacks=%d lookups=%d executions=%d", calls, lookups, executions)
						require.NoError(t, err)
						if outer {
							require.Zero(t, calls)
							require.Equal(t, 1, lookups)
							require.Equal(t, 1, executions)
							require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.UserError, GasRefund: big.NewInt(0)}, output)
						} else {
							require.Equal(t, 1, calls)
							require.Zero(t, lookups)
							require.Zero(t, executions)
							require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.UserError}, output)
						}
						require.NotEqual(t, before, qualT01SnapshotNativeState(host), "native prelude effects retained")
						require.True(t, bytes.Equal(recipient.address, host.scAddress))
						require.Equal(t, uint64(100), host.gasRemaining)
						require.Empty(t, host.storageUpdate)
						require.Nil(t, host.drwaExecutionError.Load(), "ordinary native outcome must not create a corruption latch")
						require.Zero(t, owner.calls, "an intent id is not a token classification permit")
					})
				}
			}
		}
	}
}

func qualT01NativeContextFailureCases(t *testing.T, outer bool) {
	for _, latched := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing_failure/latched_%t", latched), func(t *testing.T) {
			host, owner := qualT01NewNativeHost(t, true)
			cause := errors.New("existing native-owner failure")
			if latched {
				host.retainDRWAExecutionError(cause)
			} else {
				owner.failure = cause
			}
			calls, lookups, executions := 0, 0, 0
			var invoke func(*vmcommon.ContractCallInput) (*vmcommon.VMOutput, error)
			if outer {
				invoke = qualT01OuterNativeCall(t, host, &lookups, &executions)
			} else {
				invoke = func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
					return host.ExecuteDRWASystemCall(input, func() (*vmcommon.VMOutput, error) {
						calls++
						return &vmcommon.VMOutput{ReturnCode: vmcommon.UserError}, nil
					})
				}
			}
			qualT01SeedNativeState(host)
			before := qualT01SnapshotNativeState(host)
			input := &vmcommon.ContractCallInput{
				VMInput:       vmcommon.VMInput{CallValue: big.NewInt(0)},
				RecipientAddr: core.ESDTSCAddress, Function: "DRWARegisterToken",
			}
			output, err := invoke(input)
			require.Nil(t, output)
			require.ErrorIs(t, err, vm.ErrDRWAExecution)
			require.ErrorIs(t, err, cause)
			require.Zero(t, calls)
			require.Zero(t, lookups)
			require.Zero(t, executions)
			require.Equal(t, before, qualT01SnapshotNativeState(host))
			latch := host.drwaExecutionError.Load()
			require.NotNil(t, latch)
			require.Same(t, *latch, err, "preserve the existing native failure, not a policy rejection")
			require.Same(t, err, host.DRWAExecutionError())
		})
	}
}

func TestQualA72NativeContextUnknownNamesPreserveNativeEffects(t *testing.T) {
	qualA72NativeUnknownContextCases(t, false)
	qualT01NativeContextFailureCases(t, false)
	for _, configured := range []bool{false, true} {
		for _, nilInput := range []bool{false, true} {
			t.Run(fmt.Sprintf("ordinary/configured_%t/nil_%t", configured, nilInput), func(t *testing.T) {
				host, _ := qualT01NewNativeHost(t, configured)
				var input *vmcommon.ContractCallInput
				if !nilInput {
					input = &vmcommon.ContractCallInput{Function: "getTokenProperties"}
				}
				calls := 0
				expected := &vmcommon.VMOutput{ReturnCode: vmcommon.UserError}
				output, err := host.ExecuteDRWASystemCall(input, func() (*vmcommon.VMOutput, error) {
					calls++
					return expected, nil
				})
				require.NoError(t, err)
				require.Same(t, expected, output)
				require.Equal(t, 1, calls)
			})
		}
	}
}

func TestQualA72SystemVMContextUnknownNamesPreserveNativeEffects(t *testing.T) {
	qualA72NativeUnknownContextCases(t, true)
	qualT01NativeContextFailureCases(t, true)
}

// A11 differential controls: no classifier/provider is installed. Native
// callback identity, errors, lock ownership and journal buffers are preserved.
func TestQualA11OrdinaryContextEntryComparison(t *testing.T) {
	for _, recipient := range []string{"nil", "esdt", "foreign"} {
		for _, shape := range []string{"success", "error", "nested", "near_name"} {
			t.Run(recipient+"/"+shape, func(t *testing.T) {
				host, _ := qualT01NewNativeHost(t, false)
				qualT01SeedNativeState(host)
				before := qualT01SnapshotNativeState(host)
				input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallValue: big.NewInt(7), GasProvided: 101}, Function: "ordinary"}
				if recipient == "esdt" {
					input.RecipientAddr = core.ESDTSCAddress
				}
				if recipient == "foreign" {
					input.RecipientAddr = []byte("foreign")
				}
				if shape == "near_name" {
					input.Function = "DRWAInstallInitialProgrammeAuthoritiesSuffix"
				}
				expected := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 23, GasRefund: big.NewInt(3), ReturnData: [][]byte{[]byte("synthetic ordinary output")}}
				var expectedError error
				if shape == "error" {
					expectedError = errors.New("synthetic native callback error")
				}
				calls := 0
				output, err := host.ExecuteDRWASystemCall(input, func() (*vmcommon.VMOutput, error) {
					calls++
					unlocked := host.mutDRWAClassifier.TryLock()
					if unlocked {
						host.mutDRWAClassifier.Unlock()
					}
					require.True(t, unlocked)
					if shape == "nested" {
						nested, nestedErr := host.ExecuteDRWASystemCall(nil, func() (*vmcommon.VMOutput, error) { calls++; return expected, nil })
						require.NoError(t, nestedErr)
						require.Same(t, expected, nested)
					}
					return expected, expectedError
				})
				require.Same(t, expected, output)
				if expectedError == nil {
					require.NoError(t, err)
				} else {
					require.Same(t, expectedError, err)
				}
				wantCalls := 1
				if shape == "nested" {
					wantCalls = 2
				}
				require.Equal(t, wantCalls, calls)
				require.Equal(t, before, qualT01SnapshotNativeState(host))
				require.Nil(t, host.drwaExecutionError.Load())
				t.Logf("A11_ORDINARY recipient=%s shape=%s callbacks=%d state_unchanged=true output=%+v error=%v", recipient, shape, calls, output, err)
			})
		}
	}
}

func TestQualA72InstallationNameNativeRoutingAndFailure(t *testing.T) {
	for _, configured := range []bool{false, true} {
		for _, outer := range []bool{false, true} {
			for _, recipient := range [][]byte{nil, core.ESDTSCAddress, []byte("foreign")} {
				for _, callType := range []vmData.CallType{vmData.DirectCall, vmData.AsynchronousCall, vmData.AsynchronousCallBack} {
					for _, value := range []int64{0, 1} {
						t.Run(fmt.Sprintf("configured_%t/outer_%t/recipient_%x/type_%d/value_%d", configured, outer, recipient, callType, value), func(t *testing.T) {
							host, owner := qualT01NewNativeHost(t, configured)
							calls, lookups, executions := 0, 0, 0
							invoke := func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
								return host.ExecuteDRWASystemCall(input, func() (*vmcommon.VMOutput, error) { calls++; return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil })
							}
							if outer {
								invoke = qualT01OuterNativeCall(t, host, &lookups, &executions)
							}
							qualT01SeedNativeState(host)
							before := qualT01SnapshotNativeState(host)
							output, err := invoke(&vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallType: callType, CallValue: big.NewInt(value), GasProvided: 100, CallerAddr: []byte("synthetic caller is not authenticated"), Arguments: [][]byte{[]byte("synthetic programme"), []byte("synthetic A possession"), []byte("synthetic C possession")}}, RecipientAddr: recipient, Function: "DRWAInstallInitialProgrammeAuthorities"})
							require.NoError(t, err)
							if outer {
								require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.UserError, GasRefund: big.NewInt(0)}, output)
								require.Zero(t, calls)
								require.Equal(t, 1, lookups)
								require.Equal(t, 1, executions)
								require.NotEqual(t, before, qualT01SnapshotNativeState(host))
							} else {
								require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, output)
								require.Equal(t, 1, calls)
								require.Zero(t, lookups)
								require.Zero(t, executions)
								require.Equal(t, before, qualT01SnapshotNativeState(host))
							}
							require.Zero(t, owner.calls)
							require.Nil(t, host.drwaExecutionError.Load())
						})
					}
				}
			}
		}
	}
	for _, latched := range []bool{false, true} {
		t.Run(fmt.Sprintf("native_failure/latched_%t", latched), func(t *testing.T) {
			host, owner := qualT01NewNativeHost(t, true)
			cause := errors.New("synthetic existing owner failure")
			if latched {
				host.retainDRWAExecutionError(cause)
			} else {
				owner.failure = cause
			}
			qualT01SeedNativeState(host)
			before := qualT01SnapshotNativeState(host)
			calls := 0
			output, err := host.ExecuteDRWASystemCall(&vmcommon.ContractCallInput{Function: "DRWAInstallInitialProgrammeAuthorities"}, func() (*vmcommon.VMOutput, error) { calls++; return nil, nil })
			require.Nil(t, output)
			require.ErrorIs(t, err, vm.ErrDRWAExecution)
			require.ErrorIs(t, err, cause)
			require.Zero(t, calls)
			require.Equal(t, before, qualT01SnapshotNativeState(host))
			require.Same(t, err, host.DRWAExecutionError())
		})
	}
}
