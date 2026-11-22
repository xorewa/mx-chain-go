package smartContract

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/process/factory/containers"
	"github.com/multiversx/mx-chain-go/process/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// T09 M20 exercises native query dispatch with source-registered VM keys.
// VM/context doubles observe dispatch only; no contract or built-in executes.
func TestQualDRWACandidateCrawlerQueryDispatch(t *testing.T) {
	_, crawlers := qualDRWACandidateCrawlerProcessor(t, 0, 3)
	for _, kind := range []struct {
		name string
		key  []byte
	}{
		{"shard", factory.WasmVirtualMachine},
		{"metachain", factory.SystemVirtualMachine},
	} {
		for _, function := range []string{vmcommon.ESDTAddMetadata, vmcommon.ESDTDeleteMetadata} {
			for _, route := range []string{"query_default_caller", "query_explicit_caller", "estimate"} {
				for index := 0; index <= len(crawlers); index++ {
					t.Run(fmt.Sprintf("%s_%s_%s_address_%d", kind.name, function, route, index), func(t *testing.T) {
						control := index == len(crawlers)
						address := make([]byte, 32)
						if control {
							copy(address[8:10], kind.key)
							address[31] = 1
							// Synthetic SC-format dispatch control, not deployed code.
							require.True(t, core.IsSmartContractAddress(address))
						} else {
							copy(address, crawlers[index])
							require.False(t, core.IsSmartContractAddress(address))
						}
						vmType, err := vmcommon.ParseVMTypeFromContractAddress(address)
						require.NoError(t, err, "native parser extracts a type even for a non-SC crawler")
						if control {
							require.Equal(t, kind.key, vmType)
						} else {
							require.NotEqual(t, kind.key, vmType)
						}
						calls := 0
						container := containers.NewVirtualMachinesContainer()
						require.NoError(t, container.Add(kind.key, &mock.VMExecutionHandlerStub{
							RunSmartContractCallCalled: func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
								calls++
								require.True(t, control, "crawler must not reach a VM")
								require.Equal(t, address, input.RecipientAddr)
								require.Equal(t, address, input.CallerAddr)
								require.Equal(t, function, input.Function)
								require.Zero(t, input.CallValue.Sign())
								return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: input.GasProvided}, nil
							},
						}))
						args := createMockArgumentsForSCQuery()
						args.VmContainer = container
						service, err := NewSCQueryService(args)
						require.NoError(t, err)
						t.Cleanup(func() { require.NoError(t, service.Close()) })
						if route == "estimate" {
							_, err = service.ComputeScCallGasLimit(&transaction.Transaction{
								SndAddr: address, RcvAddr: address, Data: []byte(function), Value: big.NewInt(0),
							})
						} else {
							query := &process.SCQuery{ScAddress: address, FuncName: function}
							if route == "query_explicit_caller" {
								query.CallerAddr = address
							}
							var output *vmcommon.VMOutput
							output, _, err = service.ExecuteQuery(query)
							if control {
								require.NotNil(t, output)
							} else {
								require.Nil(t, output)
								if route == "query_default_caller" {
									require.Nil(t, query.CallerAddr, "denial precedes prepareScQuery")
								}
							}
						}
						if control {
							require.NoError(t, err)
							require.Equal(t, 1, calls)
						} else {
							require.ErrorIs(t, err, process.ErrInvalidContainerKey)
							require.Zero(t, calls)
						}
					})
				}
			}
		}
	}
}
