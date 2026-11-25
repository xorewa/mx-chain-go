package transaction_test

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/coordinator"
	txproc "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"
)

// INV-0: valid ordinary dispatch retains the upstream SC execution owner.
// The executor is the same inert unit-test callback used by the native tests;
// the fixture observes dispatch, not VM execution or token settlement.
func TestQualSP222OrdinaryMetaInvocation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  process.TransactionType
		data  string
		value int64
		esdt  bool
	}{
		{"sc without ESDT flag", process.SCInvoking, "ordinaryCall", 5, false},
		{"sc with ESDT flag", process.SCInvoking, "ordinaryCall", 5, true},
		{"enabled ordinary built-in", process.BuiltInFunctionCall, "SaveKeyValue@6b6579@76616c7565", 0, true},
	} {
		for _, entry := range []string{"direct", "receipt-aware"} {
			t.Run(tc.name+"/"+entry, func(t *testing.T) {
				tx := &transaction.Transaction{
					SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Repeat([]byte{2}, 32),
					Value: big.NewInt(tc.value), GasPrice: 1, GasLimit: 1, Data: []byte(tc.data),
				}
				require.False(t, txproc.RequiresDRWANativeValidationReceipt(tx))
				sender, receiver := createUserAcc(tx.SndAddr), createUserAcc(tx.RcvAddr)
				require.NoError(t, sender.AddToBalance(big.NewInt(100)))
				require.NoError(t, receiver.AddToBalance(big.NewInt(12)))
				receiver.SetCode([]byte{65})

				args := createMockNewMetaTxArgs()
				if tc.esdt {
					args.EnableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.ESDTFlag)
				}
				accounts := createAccountStub(tx.SndAddr, tx.RcvAddr, sender, receiver)
				args.Accounts = accounts
				wantHash, err := core.CalculateHash(args.Marshalizer, args.Hasher, tx)
				require.NoError(t, err)
				var trace []string
				accounts.SetTxHashForLatestStateAccessesCalled = func(hash []byte) {
					require.Equal(t, wantHash, hash)
					trace = append(trace, "record hash")
				}
				accounts.SaveAccountCalled = func(vmcommon.AccountHandler) error {
					trace = append(trace, "unexpected dispatcher save")
					return nil
				}
				args.TxTypeHandler = &testscommon.TxTypeHandlerMock{
					ComputeTransactionTypeCalled: func(input data.TransactionHandler) (process.TransactionType, process.TransactionType, bool) {
						require.Same(t, tx, input)
						trace = append(trace, "classify")
						return tc.kind, tc.kind, false
					},
				}
				args.ScProcessor = &testscommon.SCProcessorMock{
					ExecuteSmartContractTransactionCalled: func(input data.TransactionHandler, source, destination state.UserAccountHandler) (vmcommon.ReturnCode, error) {
						require.Same(t, tx, input)
						require.Same(t, sender, source)
						require.Same(t, receiver, destination)
						trace = append(trace, "execute")
						return vmcommon.Ok, nil
					},
					DeploySmartContractCalled: func(data.TransactionHandler, state.UserAccountHandler) (vmcommon.ReturnCode, error) {
						trace = append(trace, "unexpected deployment")
						return vmcommon.Ok, nil
					},
					ProcessIfErrorCalled: func(state.UserAccountHandler, []byte, data.TransactionHandler, string, []byte, int, uint64) error {
						trace = append(trace, "unexpected error dispatch")
						return nil
					},
				}
				processor, err := txproc.NewMetaTxProcessor(args)
				require.NoError(t, err)
				var code vmcommon.ReturnCode
				if entry == "direct" {
					code, err = processor.ProcessTransaction(tx)
				} else {
					code, err = processor.ProcessTransactionWithDRWA(tx, nil)
				}
				require.NoError(t, err)
				require.Equal(t, vmcommon.Ok, code)
				require.Equal(t, []string{"classify", "execute", "record hash"}, trace)
				require.Equal(t, big.NewInt(100), sender.GetBalance())
				require.Equal(t, big.NewInt(12), receiver.GetBalance())
			})
		}
	}
}

// The real upstream classifier and shard coordinator select the ordinary
// receiving account. Only the execution itself is an inert unit callback.
func TestQualSP222OrdinaryMetaReceivingInvocation(t *testing.T) {
	for _, entry := range []string{"direct", "receipt-aware"} {
		t.Run(entry, func(t *testing.T) {
			tx := &transaction.Transaction{
				SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Clone(vm.GovernanceSCAddress),
				Value: big.NewInt(0), GasLimit: 1, GasPrice: 1, Data: []byte("viewConfig"),
			}
			require.False(t, txproc.RequiresDRWANativeValidationReceipt(tx))
			args := createMockNewMetaTxArgs()
			shards, err := sharding.NewMultiShardCoordinator(3, core.MetachainShardId)
			require.NoError(t, err)
			require.Equal(t, uint32(1), shards.ComputeId(tx.SndAddr))
			require.Equal(t, uint32(core.MetachainShardId), shards.ComputeId(tx.RcvAddr))
			args.ShardCoordinator = shards
			esdtParser, err := parsers.NewESDTTransferParser(args.Marshalizer)
			require.NoError(t, err)
			classifier, err := coordinator.NewTxTypeHandler(coordinator.ArgNewTxTypeHandler{
				PubkeyConverter: args.PubkeyConv, ShardCoordinator: shards,
				BuiltInFunctions: builtInFunctions.NewBuiltInFunctionContainer(), ArgumentParser: parsers.NewCallArgsParser(),
				ESDTTransferParser: esdtParser, EnableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.ESDTMetadataContinuousCleanupFlag),
			})
			require.NoError(t, err)
			kind, destinationKind, relayed := classifier.ComputeTransactionType(tx)
			require.Equal(t, process.SCInvoking, kind)
			require.Equal(t, process.SCInvoking, destinationKind)
			require.False(t, relayed)
			args.TxTypeHandler = classifier

			receiver := createUserAcc(tx.RcvAddr)
			require.NoError(t, receiver.AddToBalance(big.NewInt(12)))
			accounts := createAccountStub(tx.SndAddr, tx.RcvAddr, nil, receiver)
			var trace []string
			accounts.LoadAccountCalled = func(address []byte) (vmcommon.AccountHandler, error) {
				require.Equal(t, tx.RcvAddr, address)
				trace = append(trace, "load receiver")
				return receiver, nil
			}
			accounts.SaveAccountCalled = func(vmcommon.AccountHandler) error {
				trace = append(trace, "unexpected dispatcher save")
				return nil
			}
			args.Accounts = accounts
			wantHash, err := core.CalculateHash(args.Marshalizer, args.Hasher, tx)
			require.NoError(t, err)
			accounts.SetTxHashForLatestStateAccessesCalled = func(hash []byte) {
				require.Equal(t, wantHash, hash)
				trace = append(trace, "record hash")
			}
			args.ScProcessor = &testscommon.SCProcessorMock{
				ExecuteSmartContractTransactionCalled: func(input data.TransactionHandler, source, destination state.UserAccountHandler) (vmcommon.ReturnCode, error) {
					require.Same(t, tx, input)
					require.Nil(t, source)
					require.Same(t, receiver, destination)
					trace = append(trace, "execute")
					return vmcommon.Ok, nil
				},
				ProcessIfErrorCalled: func(state.UserAccountHandler, []byte, data.TransactionHandler, string, []byte, int, uint64) error {
					trace = append(trace, "unexpected error dispatch")
					return nil
				},
			}
			processor, err := txproc.NewMetaTxProcessor(args)
			require.NoError(t, err)
			var code vmcommon.ReturnCode
			if entry == "direct" {
				code, err = processor.ProcessTransaction(tx)
			} else {
				code, err = processor.ProcessTransactionWithDRWA(tx, nil)
			}
			require.NoError(t, err)
			require.Equal(t, vmcommon.Ok, code)
			require.Equal(t, []string{"load receiver", "load receiver", "execute", "record hash"}, trace)
			require.Equal(t, big.NewInt(12), receiver.GetBalance())
		})
	}
}

func TestQualSP222OrdinaryMetaInactiveBuiltin(t *testing.T) {
	for _, entry := range []string{"direct", "receipt-aware"} {
		t.Run(entry, func(t *testing.T) {
			tx := &transaction.Transaction{
				SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Repeat([]byte{2}, 32),
				Value: big.NewInt(0), GasLimit: 1, GasPrice: 1, Data: []byte("SaveKeyValue@6b6579@76616c7565"),
			}
			require.False(t, txproc.RequiresDRWANativeValidationReceipt(tx))
			args := createMockNewMetaTxArgs()
			require.False(t, args.EnableEpochsHandler.IsFlagEnabled(common.ESDTFlag))
			sender, receiver := createUserAcc(tx.SndAddr), createUserAcc(tx.RcvAddr)
			require.NoError(t, sender.AddToBalance(big.NewInt(100)))
			accounts := createAccountStub(tx.SndAddr, tx.RcvAddr, sender, receiver)
			accounts.JournalLenCalled = func() int { return 3 }
			args.Accounts = accounts
			wantHash, err := core.CalculateHash(args.Marshalizer, args.Hasher, tx)
			require.NoError(t, err)
			var trace []string
			accounts.SetTxHashForLatestStateAccessesCalled = func(hash []byte) {
				require.Equal(t, wantHash, hash)
				trace = append(trace, "record hash")
			}
			accounts.SaveAccountCalled = func(vmcommon.AccountHandler) error {
				trace = append(trace, "unexpected dispatcher save")
				return nil
			}
			args.TxTypeHandler = &testscommon.TxTypeHandlerMock{
				ComputeTransactionTypeCalled: func(input data.TransactionHandler) (process.TransactionType, process.TransactionType, bool) {
					require.Same(t, tx, input)
					trace = append(trace, "classify")
					return process.BuiltInFunctionCall, process.BuiltInFunctionCall, false
				},
			}
			args.ScProcessor = &testscommon.SCProcessorMock{
				ExecuteSmartContractTransactionCalled: func(data.TransactionHandler, state.UserAccountHandler, state.UserAccountHandler) (vmcommon.ReturnCode, error) {
					trace = append(trace, "unexpected execution")
					return vmcommon.Ok, nil
				},
				ProcessIfErrorCalled: func(account state.UserAccountHandler, hash []byte, input data.TransactionHandler, reason string, message []byte, snapshot int, gasLocked uint64) error {
					require.Same(t, sender, account)
					require.Equal(t, wantHash, hash)
					require.Same(t, tx, input)
					require.Equal(t, process.ErrWrongTransaction.Error(), reason)
					require.Nil(t, message)
					require.Equal(t, 3, snapshot)
					require.Zero(t, gasLocked)
					trace = append(trace, "ordinary error handling")
					return nil
				},
			}
			processor, err := txproc.NewMetaTxProcessor(args)
			require.NoError(t, err)
			var code vmcommon.ReturnCode
			if entry == "direct" {
				code, err = processor.ProcessTransaction(tx)
			} else {
				code, err = processor.ProcessTransactionWithDRWA(tx, nil)
			}
			require.NoError(t, err)
			require.Equal(t, vmcommon.UserError, code)
			require.Equal(t, []string{"classify", "ordinary error handling", "record hash"}, trace)
			require.Equal(t, big.NewInt(100), sender.GetBalance())
			require.Zero(t, receiver.GetBalance().Sign())
		})
	}
}
