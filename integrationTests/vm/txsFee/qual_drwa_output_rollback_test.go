package txsFee

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-scenario-go/worldmock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	contextmock "github.com/multiversx/mx-chain-vm-go/mock/context"
	test "github.com/multiversx/mx-chain-vm-go/testcommon"
	"github.com/multiversx/mx-chain-vm-go/vmhost"
	"github.com/stretchr/testify/require"
)

// TestQualDRWAOutputRollback characterizes the adopted VM v1.5.52 host boundary
// (execution.go ExecuteOnDestContext), not DRWA policy or real WASM execution.
// Expectations are recorded before execution in repair_fa2/EXPECTED_FA2.md.
// Experimental fixture coordinates/markers/gas: register XV-SP2-81-002;
// owner confirmation or replacement before testnet admission.
func TestQualDRWAOutputRollback(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		for _, outcome := range []string{"success", "child_error", "builtin_error"} {
			t.Run(fmt.Sprintf("rollback=%t/%s", rollback, outcome), func(t *testing.T) {
				parentMarker := []byte("parent marker")
				childMarker := []byte("child marker")
				childCalls, builtinCalls := 0, 0
				countLog := func(output *vmcommon.VMOutput, identifier []byte) int {
					count := 0
					for _, entry := range output.Logs {
						if bytes.Equal(entry.Identifier, identifier) {
							count++
						}
					}
					return count
				}
				_, err := test.BuildMockInstanceCallTest(t).
					WithContracts(
						test.CreateMockContract(test.ParentAddress).WithBalance(0).
							WithMethods(func(instance *contextmock.InstanceMock, _ interface{}) {
								instance.AddMockMethod("parent", func() *contextmock.InstanceMock {
									host := instance.Host
									require.Equal(t, rollback, host.Runtime().OutputRollbackOnDestContext())
									host.Output().WriteLogWithIdentifier(test.ParentAddress, nil, nil, parentMarker)
									input := &vmcommon.ContractCallInput{
										VMInput: vmcommon.VMInput{
											CallerAddr: test.ParentAddress, CallValue: big.NewInt(0),
											GasProvided: test.GasProvided / 2, CallType: vm.DirectCall,
											AsyncArguments: &vmcommon.AsyncArguments{CallID: []byte{}, CallerCallID: []byte{}},
											Arguments:      [][]byte{[]byte(qualDRWAMetadataToken), {1}, []byte("child")},
										},
										RecipientAddr: test.ChildAddress, Function: core.BuiltInFunctionESDTTransfer,
									}
									nested, childComplete, nestedErr := host.ExecuteOnDestContext(input)
									require.NotNil(t, nested)
									require.True(t, childComplete)
									require.Equal(t, 1, builtinCalls)
									if outcome == "success" {
										require.NoError(t, nestedErr)
										require.Equal(t, vmcommon.Ok, nested.ReturnCode)
										require.Equal(t, 1, countLog(nested, []byte(core.BuiltInFunctionESDTTransfer)), "builtin output must survive child merge")
										require.Equal(t, 1, countLog(nested, childMarker))
										require.Equal(t, [][]byte{[]byte("child result")}, nested.ReturnData)
									} else {
										require.Error(t, nestedErr)
										require.NotEqual(t, vmcommon.Ok, nested.ReturnCode)
										require.Zero(t, countLog(nested, []byte(core.BuiltInFunctionESDTTransfer)))
									}
									active := host.Output().GetVMOutput()
									require.Equal(t, 1, countLog(active, parentMarker), "pre-call output must survive")
									expectedBuiltinLogs := 0
									if outcome == "success" || (outcome == "child_error" && !rollback) {
										expectedBuiltinLogs = 1
									}
									require.Equal(t, expectedBuiltinLogs, countLog(active, []byte(core.BuiltInFunctionESDTTransfer)), "outer output rollback gate")
									if outcome == "success" {
										require.Equal(t, 1, countLog(active, childMarker))
									} else {
										require.Zero(t, countLog(active, childMarker))
									}
									expectedChildCalls := 1
									if outcome == "builtin_error" {
										expectedChildCalls = 0
									}
									require.Equal(t, expectedChildCalls, childCalls)
									return instance
								})
							}),
						test.CreateMockContract(test.ChildAddress).WithBalance(0).
							WithMethods(func(instance *contextmock.InstanceMock, _ interface{}) {
								instance.AddMockMethod("child", func() *contextmock.InstanceMock {
									childCalls++
									instance.Host.Output().WriteLogWithIdentifier(test.ChildAddress, nil, nil, childMarker)
									instance.Host.Output().Finish([]byte("child result"))
									if outcome == "child_error" {
										instance.Host.Runtime().SignalUserError("child rejected")
									}
									return instance
								})
							}),
					).
					WithSetup(func(host vmhost.VMHost, world *worldmock.MockWorld) {
						flags := host.EnableEpochsHandler().(*worldmock.EnableEpochsHandlerStub)
						flags.IsFlagEnabledCalled = func(flag core.EnableEpochFlag) bool {
							return flag != vmhost.OutputRollbackOnDestContextFlag || rollback
						}
						require.NoError(t, world.InitBuiltinFunctions(host.GetGasScheduleMap()))
						require.NoError(t, world.BuiltinFuncs.Container.Replace(core.BuiltInFunctionESDTTransfer, &test.MockBuiltin{
							ProcessBuiltinFunctionCall: func(_, _ vmcommon.UserAccountHandler, input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
								builtinCalls++
								if outcome == "builtin_error" {
									return nil, errors.New("builtin rejected")
								}
								return &vmcommon.VMOutput{
									ReturnCode: vmcommon.Ok, GasRemaining: input.GasProvided,
									OutputAccounts: map[string]*vmcommon.OutputAccount{
										string(test.ChildAddress): {
											Address: test.ChildAddress, BalanceDelta: big.NewInt(0),
											OutputTransfers: []vmcommon.OutputTransfer{{Value: big.NewInt(0), GasLimit: input.GasProvided, Data: []byte("child"), SenderAddress: test.ParentAddress}},
										},
									},
									Logs: []*vmcommon.LogEntry{{Address: test.ParentAddress, Identifier: []byte(core.BuiltInFunctionESDTTransfer), Topics: [][]byte{[]byte(qualDRWAMetadataToken), {}, {1}, test.ChildAddress}}},
								}, nil
							},
						}))
						host.SetBuiltInFunctionsContainer(world.BuiltinFuncs.Container)
					}).
					WithInput(test.CreateTestContractCallInputBuilder().WithRecipientAddr(test.ParentAddress).WithGasProvided(test.GasProvided).WithFunction("parent").Build()).
					AndAssertResults(func(_ *worldmock.MockWorld, verify *test.VMOutputVerifier) { verify.Ok() })
				require.NoError(t, err)
			})
		}
	}
}
