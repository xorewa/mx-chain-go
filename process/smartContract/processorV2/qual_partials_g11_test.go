package processorV2

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	vmconfig "github.com/multiversx/mx-chain-vm-go/config"
	"github.com/multiversx/mx-chain-vm-go/executor"
	contextmock "github.com/multiversx/mx-chain-vm-go/mock/context"
	"github.com/multiversx/mx-chain-vm-go/vmhost"
	"github.com/multiversx/mx-chain-vm-go/vmhost/hostCore"
	vmmock "github.com/multiversx/mx-chain-vm-go/vmhost/mock"
	"github.com/stretchr/testify/require"
)

func qualG11LoadedHandler(t *testing.T, epoch uint32) common.EnableEpochsHandler {
	p := filepath.Join(t.TempDir(), "epochs.toml")
	require.NoError(t, os.WriteFile(p, []byte("[EnableEpochs]\nFixDataTrieLeafValidationEnableEpoch=11\nFixCorrectSmallIntAndGasLimitsEnableEpoch=23\nOutputRollbackOnDestContextEnableEpoch=37\nKeepReturnDataOnAsyncTransferCallbackEnableEpoch=53\n"), 0600))
	cfg, e := common.LoadEpochConfig(p)
	require.NoError(t, e)
	h, e := enablers.NewEnableEpochsHandler(cfg.EnableEpochs, &epochNotifier.EpochNotifierStub{})
	require.NoError(t, e)
	h.EpochConfirmed(epoch, 0)
	return h
}

// Experimental addresses/epochs/gas/return bytes. These are local consumer
// joins, without node factories, native executor instances or network traffic.
func TestQualPartialsG11LoadedSCRConsumers(t *testing.T) {
	for _, epoch := range []uint32{22, 23, 24, 36, 37, 38, 52, 53, 54} {
		t.Run(fmt.Sprintf("epoch_%d", epoch), func(t *testing.T) {
			args := createMockSmartContractProcessorArguments()
			args.EnableEpochsHandler = qualG11LoadedHandler(t, epoch)
			args.ArgsParser = smartContract.NewArgumentParser()
			sc, e := NewSmartContractProcessorV2(args)
			require.NoError(t, e)
			tx := &smartContractResult.SmartContractResult{SndAddr: []byte("caller"), RcvAddr: []byte("callee"), Value: big.NewInt(0)}
			out := &vmcommon.VMOutput{GasRemaining: 5, ReturnCode: vmcommon.Ok}
			cb, results := sc.createSmartContractResults(&vmcommon.VMInput{CallType: vmData.AsynchronousCall}, out, &vmcommon.OutputAccount{Address: tx.SndAddr, BalanceDelta: big.NewInt(0)}, tx, []byte("hash"))
			require.Equal(t, epoch < 23, cb, "loaded correct-small-int callback branch")
			require.Len(t, results, map[bool]int{true: 0, false: 1}[epoch >= 23], "loaded correct-small-int SCR count")
			result := &smartContractResult.SmartContractResult{GasLimit: 7}
			input := &vmcommon.VMInput{CallType: vmData.AsynchronousCall, AsyncArguments: &vmcommon.AsyncArguments{CallID: []byte("id"), CallerCallID: []byte("parent")}}
			out.ReturnData = [][]byte{[]byte("independent-return")}
			used := sc.useLastTransferAsAsyncCallBackWhenNeeded(input, &vmcommon.OutputAccount{Address: tx.SndAddr}, &vmcommon.OutputTransfer{SenderAddress: tx.RcvAddr}, out, tx, result, true)
			require.True(t, used)
			require.Equal(t, vmData.AsynchronousCallBack, result.CallType)
			require.Equal(t, uint64(12), result.GasLimit)
			require.Equal(t, epoch >= 53, containsG11Return(result.Data), "loaded keep-return-data callback bytes")
		})
	}
}
func containsG11Return(b []byte) bool {
	needle := hex.EncodeToString([]byte("independent-return"))
	s := string(b)
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

type qualG11Executor struct{ executor.Executor }

func (*qualG11Executor) IsInterfaceNil() bool                    { return false }
func (*qualG11Executor) FunctionNames() vmcommon.FunctionNames   { return vmcommon.FunctionNames{} }
func (*qualG11Executor) SetOpcodeCosts(*executor.WASMOpcodeCost) {}

type qualG11ExecutorFactory struct{}

func (*qualG11ExecutorFactory) CreateExecutor(executor.ExecutorFactoryArgs) (executor.Executor, error) {
	return &qualG11Executor{}, nil
}
func (*qualG11ExecutorFactory) IsInterfaceNil() bool { return false }

type qualG11Builtin struct{ vmcommon.BuiltinFunction }

func (*qualG11Builtin) IsActive() bool       { return true }
func (*qualG11Builtin) IsInterfaceNil() bool { return false }

func TestQualPartialsG11LoadedRollbackConsumer(t *testing.T) {
	for _, epoch := range []uint32{36, 37, 38} {
		t.Run(fmt.Sprintf("epoch_%d", epoch), func(t *testing.T) {
			h := qualG11LoadedHandler(t, epoch)
			bfc := builtInFunctions.NewBuiltInFunctionContainer()
			require.NoError(t, bfc.Add("experimentalBuiltin", &qualG11Builtin{}))
			parser, e := parsers.NewESDTTransferParser(&marshal.GogoProtoMarshalizer{})
			require.NoError(t, e)
			hook := &contextmock.BlockchainHookStub{}
			snapshots, reverts := 0, 0
			hook.GetSnapshotCalled = func() int { snapshots++; return 9 }
			hook.RevertToSnapshotCalled = func(n int) error { require.Equal(t, 9, n); reverts++; return nil }
			host, e := hostCore.NewVMHost(hook, &vmhost.VMHostParameters{VMType: []byte{5, 0}, ESDTTransferParser: parser, BuiltInFuncContainer: bfc, EpochNotifier: &vmmock.EpochNotifierStub{}, EnableEpochsHandler: h, Hasher: blake2b.NewBlake2b(), MapOpcodeAddressIsAllowed: map[string]map[string]struct{}{}, GasSchedule: vmconfig.MakeGasMapForTests(), BlockGasLimit: 1000000, OverrideVMExecutor: &qualG11ExecutorFactory{}, ProtectedKeyPrefix: []byte("ELROND")})
			require.NoError(t, e)
			host.Output().Finish([]byte("before"))
			hook.ProcessBuiltInFunctionCalled = func(*vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				host.Output().Finish([]byte("failed-effect"))
				return nil, vmhost.ErrExecutionFailed
			}
			_, child, e := host.ExecuteOnDestContext(&vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: []byte("caller"), CallValue: big.NewInt(0)}, RecipientAddr: []byte("callee"), Function: "experimentalBuiltin"})
			require.ErrorIs(t, e, vmhost.ErrExecutionFailed)
			require.True(t, child)
			require.Equal(t, 1, snapshots)
			require.Equal(t, 1, reverts)
			want := [][]byte{[]byte("before")}
			if epoch < 37 {
				want = append(want, []byte("failed-effect"))
			}
			require.Equal(t, want, host.Output().ReturnData(), "loaded rollback restores active output")
		})
	}
}
