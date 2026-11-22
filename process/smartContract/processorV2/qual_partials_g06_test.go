package processorV2

import (
	"bytes"
	"math/big"
	"testing"

	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/multiversx/mx-chain-vm-go/config"
	cryptoFactory "github.com/multiversx/mx-chain-vm-go/crypto/factory"
	contextmock "github.com/multiversx/mx-chain-vm-go/mock/context"
	"github.com/multiversx/mx-chain-vm-go/vmhost"
	"github.com/multiversx/mx-chain-vm-go/vmhost/contexts"
	"github.com/stretchr/testify/require"
)

type qualG06Host struct {
	*contextmock.VMHostMock
	invoke func(*vmcommon.ContractCallInput) (*vmcommon.VMOutput, bool, error)
}

func (h *qualG06Host) ExecuteOnDestContext(in *vmcommon.ContractCallInput) (*vmcommon.VMOutput, bool, error) {
	return h.invoke(in)
}

// Experimental local host/runtime/metering fixtures surround the real pinned
// async context. No native executor or node/factory admission is qualified.
func TestQualPartialsG06AsyncBoundary(t *testing.T) {
	for _, mode := range []string{"reentry", "gas_error_observation"} {
		t.Run(mode, func(t *testing.T) {
			parent, dest, original, root := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32)
			runtime := &contextmock.RuntimeContextMock{SCAddress: parent, OriginalCallerAddr: original, VMInput: &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{GasProvided: 999, GasPrice: 11, CurrentTxHash: root}}}
			metering := &contextmock.MeteringContextMock{}
			metering.SetGasSchedule(config.MakeGasMapForTests())
			metering.GasCost.BaseOpsAPICost.AsyncCallStep = 5
			metering.GasCost.BaseOperationCost.DataCopyPerByte = 0
			crypto, err := cryptoFactory.NewVMCrypto()
			require.NoError(t, err)
			host := &qualG06Host{VMHostMock: &contextmock.VMHostMock{RuntimeContext: runtime, MeteringContext: metering, CryptoHook: crypto}}
			storage, err := contexts.NewStorageContext(host, &testscommon.BlockChainHookStub{}, []byte("ELROND"))
			require.NoError(t, err)
			host.StorageContext = storage
			esdt, err := parsers.NewESDTTransferParser(&marshal.GogoProtoMarshalizer{})
			require.NoError(t, err)
			async, err := contexts.NewAsyncContext(host, parsers.NewCallArgsParser(), esdt, &marshal.GogoProtoMarshalizer{})
			require.NoError(t, err)
			require.NoError(t, async.InitStateFromInput(&vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: original, CallType: vmData.DirectCall, CurrentTxHash: root}}))
			call := &vmhost.AsyncCall{CallID: bytes.Repeat([]byte{5}, 32), Status: vmhost.AsyncCallResolved, Destination: dest, GasLocked: 13, SuccessCallback: "success"}
			output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 37, GasRefund: big.NewInt(0)}
			inputs := []*vmcommon.ContractCallInput{}
			host.invoke = func(in *vmcommon.ContractCallInput) (*vmcommon.VMOutput, bool, error) {
				inputs = append(inputs, in)
				require.Equal(t, parent, in.RecipientAddr)
				require.Equal(t, dest, in.CallerAddr)
				require.Equal(t, "success", in.Function)
				require.Equal(t, vmData.AsynchronousCallBack, in.CallType)
				require.Equal(t, uint64(45), in.GasProvided)
				require.Equal(t, uint64(11), in.GasPrice)
				require.Equal(t, call.CallID, in.AsyncArguments.CallerCallID)
				require.Equal(t, root, in.AsyncArguments.CallbackAsyncInitiatorCallID, "callback initiator lineage")
				require.Equal(t, uint64(17), in.AsyncArguments.GasAccumulated)
				if len(inputs) == 1 {
					runtime.VMInput.GasProvided = 888
					complete, out := async.ExecuteSyncCallbackAndFinishOutput(call, output, nil, 17, nil)
					require.True(t, complete)
					require.NotNil(t, out)
					require.Zero(t, runtime.VMInput.GasProvided, "nested callback boundary clears runtime gas")
					runtime.VMInput.GasProvided = 777
				}
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, true, nil
			}
			if mode == "gas_error_observation" {
				// Source observation G06.H-sync-error: the wrapper discards the gas error.
				// This is not an adopted error-handling requirement or owner disposition.
				call.GasLocked = 0
				output.GasRemaining = 0
				complete, out := async.ExecuteSyncCallbackAndFinishOutput(call, output, nil, 17, nil)
				require.True(t, complete)
				require.Nil(t, out)
				require.Empty(t, inputs)
				require.Zero(t, runtime.VMInput.GasProvided)
				return
			}
			complete, out := async.ExecuteSyncCallbackAndFinishOutput(call, output, nil, 17, nil)
			require.True(t, complete)
			require.NotNil(t, out)
			require.Len(t, inputs, 2)
			require.NotEqual(t, inputs[0].AsyncArguments.CallID, inputs[1].AsyncArguments.CallID, "reentrant callbacks get distinct call IDs")
			require.Equal(t, uint64(26), metering.GasLeftMock)
			require.Equal(t, root, async.GetCallID())
			require.Zero(t, runtime.VMInput.GasProvided, "outer callback boundary clears runtime gas")
		})
	}
}
