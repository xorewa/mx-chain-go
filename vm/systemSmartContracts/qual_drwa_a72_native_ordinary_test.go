package systemSmartContracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmprocess "github.com/multiversx/mx-chain-go/vm/process"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Exercise only the in-process validation and native owner-health boundaries.
// No fixture supplies a protected endpoint or a canonical admission provider.
func TestQualDRWAStep1SharedValueValidation(t *testing.T) {
	for _, path := range []string{"physical", "nested"} {
		cases := []string{"attached-egld", "missing-value", "containment-failure"}
		if path == "physical" {
			cases = append(cases, "attached-esdt")
		}
		for _, scenario := range cases {
			t.Run(path+"/"+scenario, func(t *testing.T) {
				host, owner := qualT01NewNativeHost(t, true)
				lookups, executions := 0, 0
				runPhysical := qualT01OuterNativeCall(t, host, &lookups, &executions)
				qualT01SeedNativeState(host)
				sender := bytes.Clone(host.scAddress)
				senderBalance := host.GetBalance(sender)
				destinationBalance := host.GetBalance(core.ESDTSCAddress)
				stateBefore := qualT01SnapshotNativeState(host)
				failure := errors.New("synthetic original rollback failure")
				input := &vmcommon.ContractCallInput{
					VMInput:       vmcommon.VMInput{CallerAddr: sender, CallValue: big.NewInt(1)},
					RecipientAddr: core.ESDTSCAddress,
					Function:      "DRWARegisterBootstrapIntent",
				}
				switch scenario {
				case "missing-value":
					input.CallValue = nil
				case "attached-esdt":
					input.CallValue = big.NewInt(0)
					input.ESDTTransfers = []*vmcommon.ESDTTransfer{{ESDTValue: big.NewInt(1)}}
				case "containment-failure":
					owner.failure = failure
				}

				var out *vmcommon.VMOutput
				var err error
				if path == "physical" {
					out, err = runPhysical(input)
				} else {
					out, err = host.ExecuteOnDestContext(input.RecipientAddr, sender, input.CallValue, []byte(input.Function))
				}

				if scenario == "containment-failure" {
					require.ErrorIs(t, err, vm.ErrDRWAExecution)
					require.ErrorIs(t, err, failure)
					require.Nil(t, out)
					owner.failure = nil
					require.ErrorIs(t, host.DRWAExecutionError(), failure)
				} else {
					require.NoError(t, err)
					require.Equal(t, &vmcommon.VMOutput{
						ReturnCode:    vmcommon.UserError,
						GasRefund:     big.NewInt(0),
						ReturnMessage: "DRWA bootstrap intent requires zero attached value",
					}, out)
					require.NoError(t, host.DRWAExecutionError())
				}
				require.Zero(t, lookups)
				require.Zero(t, executions)
				require.Zero(t, owner.calls)
				require.Equal(t, stateBefore, qualT01SnapshotNativeState(host))
				require.Equal(t, senderBalance, host.GetBalance(sender))
				require.Equal(t, destinationBalance, host.GetBalance(core.ESDTSCAddress))
			})
		}
	}
}

// Ordinary synthetic input data only. Real native contract/prelude behavior is
// compared to untouched pinned source; this supplies no DRWA authority fact.
func TestQualA72NativeReservedNamesOrdinaryBaseline(t *testing.T) {
	for _, recipient := range []struct {
		name    string
		address []byte
	}{{"esdt", core.ESDTSCAddress}, {"governance", vm.GovernanceSCAddress}} {
		for _, enabled := range []bool{false, true} {
			for _, value := range []int64{0, 1} {
				for _, function := range []string{"DRWARegisterBootstrapIntent", "DRWARegisterToken", "DRWAInstallInitialProgrammeAuthorities", "syntheticUnknown", core.SCDeployInitFunctionName, "getTokenProperties", "viewConfig"} {
					t.Run(fmt.Sprintf("%s/enabled_%t/value_%d/%s", recipient.name, enabled, value, function), func(t *testing.T) {
						host, err := NewVMContext(createDefaultEeiArgs())
						require.NoError(t, err)
						require.False(t, host.drwaClassifierConfigured)
						esdtArgs := createMockArgumentsForESDT()
						esdtArgs.Eei = host
						flags := esdtArgs.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
						if enabled {
							flags.AddActiveFlags(common.ESDTFlag)
						} else {
							flags.RemoveActiveFlags(common.ESDTFlag)
						}
						esdt, err := NewESDTSmartContract(esdtArgs)
						require.NoError(t, err)
						govArgs := createMockGovernanceArgs()
						govArgs.Eei = host
						governance, err := NewGovernanceContract(govArgs)
						require.NoError(t, err)
						calls := 0
						container := &mock.SystemSCContainerStub{GetCalled: func(address []byte) (vm.SystemSmartContract, error) {
							calls++
							if bytes.Equal(address, core.ESDTSCAddress) {
								return esdt, nil
							}
							return governance, nil
						}}
						require.NoError(t, host.SetSystemSCContainer(container))
						gas := map[string]map[string]uint64{common.BaseOpsAPICost: {common.AsyncCallStepField: 1000, common.AsyncCallbackGasLockField: 3000}}
						runtime, err := vmprocess.NewSystemVM(vmprocess.ArgsNewSystemVM{SystemEI: host, SystemContracts: container, VmType: factory.SystemVirtualMachine, GasSchedule: testscommon.NewGasScheduleNotifierMock(gas)})
						require.NoError(t, err)
						qualT01SeedNativeState(host)
						out, err := runtime.RunSmartContractCall(&vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: []byte("synthetic ordinary caller"), CallValue: big.NewInt(value), GasProvided: 100}, RecipientAddr: recipient.address, Function: function})
						require.NoError(t, err)
						require.NotNil(t, out)
						observed := struct {
							Recipient, Function string
							Enabled             bool
							Value               int64
							Output              *vmcommon.VMOutput
							Calls               int
							Address             []byte
							Storage             map[string]map[string][]byte
							Accounts            map[string]*vmcommon.OutputAccount
							Gas                 uint64
							Message             string
							Data                [][]byte
						}{recipient.name, function, enabled, value, out, calls, host.scAddress, host.storageUpdate, host.outputAccounts, host.gasRemaining, host.returnMessage, host.output}
						encoded, err := json.Marshal(observed)
						require.NoError(t, err)
						t.Logf("A72_NATIVE_ORDINARY %s", encoded)
						require.Equal(t, 1, calls, "native contract lookup must not be bypassed for a reserved name")
						require.True(t, bytes.Equal(recipient.address, host.scAddress))
						require.Empty(t, host.storageUpdate)
						if function == core.SCDeployInitFunctionName {
							require.Equal(t, vmcommon.UserError, out.ReturnCode)
							require.Equal(t, "cannot call smart contract init function", out.ReturnMessage)
							return
						}
						if recipient.name == "esdt" && !enabled {
							require.Equal(t, vmcommon.UserError, out.ReturnCode)
							require.Equal(t, "ESDT SC disabled", out.ReturnMessage)
							return
						}
						if function == "DRWARegisterBootstrapIntent" || function == "DRWARegisterToken" || function == "DRWAInstallInitialProgrammeAuthorities" || function == "syntheticUnknown" {
							require.Equal(t, vmcommon.FunctionNotFound, out.ReturnCode)
							require.Equal(t, "invalid method to call", out.ReturnMessage)
						}
					})
				}
			}
		}
	}
}
