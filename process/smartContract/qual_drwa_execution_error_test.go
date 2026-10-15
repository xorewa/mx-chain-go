package smartContract

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/testscommon"
	cacheMock "github.com/multiversx/mx-chain-go/testscommon/cache"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"
)

// DS02-M6/M7: processor consumer contract. Faults are injected at native
// VM/hook interfaces, not an admitted DRWA runtime. Earlier native payment or
// built-in mutations still require outer candidate rollback and recovery.
// Synthetic coordinates are experimental; replace before testnet admission.
func TestQualDRWAExecutionErrorPropagation(t *testing.T) {
	for _, route := range []string{"call", "create", "hook", "nested_vm", "scr_call", "scr_hook", "meta_scr_call"} {
		for _, shape := range []string{"marker", "wrapped", "joined", "ordinary_same_message"} {
			t.Run(route+"/"+shape, func(t *testing.T) {
				original := errors.New("native operation failed")
				rollback := errors.New("native rollback failed")
				injected := vm.ErrDRWAExecution
				switch shape {
				case "wrapped":
					injected = fmt.Errorf("native context: %w", injected)
				case "joined":
					injected = errors.Join(injected, original, rollback)
				case "ordinary_same_message":
					injected = errors.New(injected.Error())
				}
				stopRevert := errors.New("stop at ordinary revert boundary")
				afterFault := false
				events := []string{}
				observe := func(event string) {
					if afterFault {
						events = append(events, event)
					}
				}
				calls := 0
				fault := func() (*vmcommon.VMOutput, error) {
					calls++
					afterFault = true
					return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, ReturnMessage: "tentative", GasRemaining: 1000000,
						Logs: []*vmcommon.LogEntry{{Identifier: []byte("unpublished")}}}, injected
				}
				args := createMockSmartContractProcessorArguments()
				src := bytes.Repeat([]byte{1}, args.PubkeyConv.Len())
				dst := bytes.Clone(core.ESDTSCAddress)
				destAccount := createAccount(dst)
				args.EnableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.SCDeployFlag, common.BuiltInFunctionsFlag)
				args.ShardCoordinator = &testscommon.ShardsCoordinatorMock{}
				if route == "meta_scr_call" {
					args.ShardCoordinator = &testscommon.ShardsCoordinatorMock{CurrentShard: core.MetachainShardId}
				}
				args.ArgsParser = &testscommon.ArgumentParserMock{
					ParseCallDataCalled:   func(string) (string, [][]byte, error) { return "pause", [][]byte{[]byte("AAA-abcdef")}, nil },
					ParseDeployDataCalled: parsers.NewDeployArgsParser().ParseData,
				}
				args.AccountsDB = &stateMock.AccountsStub{
					LoadAccountCalled:      func([]byte) (vmcommon.AccountHandler, error) { observe("load"); return destAccount, nil },
					SaveAccountCalled:      func(vmcommon.AccountHandler) error { observe("save"); return nil },
					RevertToSnapshotCalled: func(int) error { observe("revert"); return stopRevert },
				}
				forward := &mock.IntermediateTransactionHandlerMock{AddIntermediateTransactionsCalled: func([]data.TransactionHandler, []byte) error { observe("result"); return nil }}
				args.ScrForwarder = forward
				args.BadTxForwarder = forward
				args.TxFeeHandler = &mock.FeeAccumulatorStub{ProcessTransactionFeeCalled: func(*big.Int, *big.Int, []byte) { observe("fee") }}
				args.TxLogsProcessor = &mock.TxLogsProcessorStub{SaveLogCalled: func([]byte, data.TransactionHandler, []*vmcommon.LogEntry) error { observe("log"); return nil }}
				args.GasHandler = &testscommon.GasHandlerStub{
					SetGasRefundedCalled:  func(uint64, []byte) { observe("refund") },
					SetGasPenalizedCalled: func(uint64, []byte) { observe("penalty") },
				}
				args.VMOutputCacher = &cacheMock.CacherStub{PutCalled: func([]byte, interface{}, int) bool { observe("cache"); return false }}
				args.VmContainer = &mock.VMContainerMock{GetCalled: func([]byte) (vmcommon.VMExecutionHandler, error) {
					return &mock.VMExecutionHandlerStub{
						RunSmartContractCallCalled:   func(*vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) { return fault() },
						RunSmartContractCreateCalled: func(*vmcommon.ContractCreateInput) (*vmcommon.VMOutput, error) { return fault() },
					}, nil
				}}
				args.BlockChainHook = &testscommon.BlockChainHookStub{
					ProcessBuiltInFunctionCalled: func(*vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
						if route != "nested_vm" {
							return fault()
						}
						return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 0, OutputAccounts: map[string]*vmcommon.OutputAccount{
							string(dst): {Address: dst, BalanceDelta: big.NewInt(0), OutputTransfers: []vmcommon.OutputTransfer{{Value: big.NewInt(0), GasLimit: 1000000, Data: []byte("pause")}}},
						}}, nil
					},
					SaveNFTMetaDataToSystemAccountCalled: func(data.TransactionHandler) error { observe("nft_save"); return nil },
				}
				args.TxTypeHandler = &testscommon.TxTypeHandlerMock{ComputeTransactionTypeCalled: func(data.TransactionHandler) (process.TransactionType, process.TransactionType, bool) {
					if route == "scr_hook" || route == "meta_scr_call" {
						return process.BuiltInFunctionCall, process.SCInvoking, false
					}
					return process.SCInvoking, process.SCInvoking, false
				}}
				sc, err := NewSmartContractProcessor(args)
				require.NoError(t, err)
				sc.esdtTransferParser = &testscommon.ESDTTransferParserStub{ParseESDTTransfersCalled: func([]byte, []byte, string, [][]byte) (*vmcommon.ParsedESDTTransfers, error) {
					return &vmcommon.ParsedESDTTransfers{RcvAddr: dst, CallFunction: "pause"}, nil
				}}
				tx := &transaction.Transaction{SndAddr: src, RcvAddr: dst, Data: []byte("pause"), Value: big.NewInt(0), GasLimit: 1000000}
				var code vmcommon.ReturnCode
				switch {
				case route == "create":
					tx.RcvAddr = make([]byte, args.PubkeyConv.Len())
					tx.Data = []byte("abba@0500@0000")
					code, err = sc.DeploySmartContract(tx, nil)
				case strings.Contains(route, "scr"):
					scr := &smartContractResult.SmartContractResult{SndAddr: src, RcvAddr: dst, Data: tx.Data, Value: big.NewInt(0), GasLimit: tx.GasLimit}
					code, err = sc.ProcessSmartContractResult(scr)
				case route == "hook" || route == "nested_vm":
					code, err = sc.ExecuteBuiltInFunction(tx, nil, destAccount)
				default:
					code, err = sc.ExecuteSmartContractTransaction(tx, nil, destAccount)
				}
				t.Logf("native_calls=%d code=%s err=%v post_fault_events=%v", calls, code, err, events)
				require.Equal(t, 1, calls, "must reach the injected native boundary")
				if shape == "ordinary_same_message" {
					require.ErrorIs(t, err, stopRevert, "native ordinary failure path remains reachable")
					require.NotErrorIs(t, err, vm.ErrDRWAExecution)
					require.Contains(t, events, "revert")
					return
				}
				require.Same(t, injected, err, "preserve the original fatal error object")
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				if shape == "joined" {
					require.ErrorIs(t, err, original)
					require.ErrorIs(t, err, rollback)
				}
				require.Empty(t, events, "fatal context must bypass ordinary error/output materialization")
			})
		}
	}
}
