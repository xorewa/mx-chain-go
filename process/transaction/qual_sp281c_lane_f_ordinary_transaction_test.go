package transaction_test

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/mock"
	txproc "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CLaneFOrdinaryReceiptAdmission(t *testing.T) {
	var absent *txproc.InterceptedTransaction
	require.False(t, absent.RequiresDRWANativeValidationReceipt())
	require.Nil(t, absent.NativeValidationReceipt())

	tx := &transaction.Transaction{
		Nonce: 1, Value: big.NewInt(2), Data: []byte("data"),
		GasLimit: 3, GasPrice: 4, RcvAddr: recvAddress, SndAddr: senderAddress,
		Signature: sigOk, ChainID: []byte("chain"), Version: 1,
	}
	intercepted, err := createInterceptedTxFromPlainTx(tx, createFreeTxFeeHandler(), tx.ChainID, tx.Version)
	require.NoError(t, err)
	require.False(t, intercepted.RequiresDRWANativeValidationReceipt())
	require.Nil(t, intercepted.NativeValidationReceipt())
	require.NoError(t, intercepted.CheckValidity())
	require.False(t, intercepted.RequiresDRWANativeValidationReceipt())

	source := txproc.NativeValidationSource{}
	require.ErrorIs(t, txproc.VerifyNativeValidationReceipt(source, nil, tx, nil), vm.ErrDRWAExecution)
	require.ErrorIs(t, txproc.VerifyNativeValidationReceipt(source, &txproc.NativeValidationReceipt{}, tx, nil), vm.ErrDRWAExecution)
}

func TestQualSP281CLaneFOrdinaryMetaDispatch(t *testing.T) {
	sentinel := errors.New("ordinary dispatch fixture error")
	for _, entry := range []string{"direct", "receipt-aware"} {
		for _, scenario := range []string{"hash failure", "deployment", "wrong type", "cross-shard username mismatch"} {
			t.Run(entry+"/"+scenario, func(t *testing.T) {
				tx := &transaction.Transaction{
					SndAddr: bytes.Repeat([]byte{1}, 32),
					RcvAddr: bytes.Repeat([]byte{2}, 32),
					Value:   big.NewInt(0),
				}
				args := createMockNewMetaTxArgs()
				wantReason := process.ErrWrongTransaction.Error()
				txType := process.MoveBalance
				switch scenario {
				case "hash failure":
					args.Marshalizer = &mock.MarshalizerStub{MarshalCalled: func(obj any) ([]byte, error) {
						require.Same(t, tx, obj)
						return nil, sentinel
					}}
				case "deployment":
					tx.RcvAddr = make([]byte, 32)
					txType = process.SCDeployment
				case "cross-shard username mismatch":
					tx.RcvAddr = vm.GovernanceSCAddress
					tx.RcvUserName = []byte("username")
					wantReason = process.ErrUserNameDoesNotMatchInCrossShardTx.Error()
					var err error
					args.ShardCoordinator, err = sharding.NewMultiShardCoordinator(3, core.MetachainShardId)
					require.NoError(t, err)
				}
				sender, receiver := createUserAcc(tx.SndAddr), createUserAcc(tx.RcvAddr)
				accounts := createAccountStub(tx.SndAddr, tx.RcvAddr, sender, receiver)
				accounts.JournalLenCalled = func() int { return 3 }
				args.Accounts = accounts

				var wantHash []byte
				if scenario != "hash failure" {
					var err error
					wantHash, err = core.CalculateHash(args.Marshalizer, args.Hasher, tx)
					require.NoError(t, err)
				}
				var recordedHashes [][]byte
				accounts.SetTxHashForLatestStateAccessesCalled = func(hash []byte) {
					recordedHashes = append(recordedHashes, bytes.Clone(hash))
				}
				typeCalls, deployCalls, errorCalls := 0, 0, 0
				args.TxTypeHandler = &testscommon.TxTypeHandlerMock{
					ComputeTransactionTypeCalled: func(input data.TransactionHandler) (process.TransactionType, process.TransactionType, bool) {
						require.Same(t, tx, input)
						typeCalls++
						return txType, txType, false
					},
				}
				args.ScProcessor = &testscommon.SCProcessorMock{
					DeploySmartContractCalled: func(input data.TransactionHandler, account state.UserAccountHandler) (vmcommon.ReturnCode, error) {
						require.Same(t, tx, input)
						require.Same(t, sender, account)
						deployCalls++
						return vmcommon.Ok, nil
					},
					ProcessIfErrorCalled: func(account state.UserAccountHandler, hash []byte, input data.TransactionHandler, reason string, message []byte, snapshot int, gasLocked uint64) error {
						if scenario == "cross-shard username mismatch" {
							require.Nil(t, account)
						} else {
							require.Same(t, sender, account)
						}
						require.Equal(t, wantHash, hash)
						require.Same(t, tx, input)
						require.Equal(t, wantReason, reason)
						require.Nil(t, message)
						require.Equal(t, 3, snapshot)
						require.Zero(t, gasLocked)
						errorCalls++
						return sentinel
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

				switch scenario {
				case "hash failure":
					require.ErrorIs(t, err, sentinel)
					require.Zero(t, code)
					require.Empty(t, recordedHashes)
					require.Zero(t, typeCalls+deployCalls+errorCalls)
				case "deployment":
					require.NoError(t, err)
					require.Equal(t, vmcommon.Ok, code)
					require.Equal(t, [][]byte{wantHash}, recordedHashes)
					require.Equal(t, 1, typeCalls)
					require.Equal(t, 1, deployCalls)
					require.Zero(t, errorCalls)
				default:
					require.ErrorIs(t, err, sentinel)
					require.Zero(t, code)
					require.Equal(t, [][]byte{wantHash}, recordedHashes)
					require.Zero(t, deployCalls)
					require.Equal(t, 1, errorCalls)
					if scenario == "cross-shard username mismatch" {
						require.Zero(t, typeCalls)
					} else {
						require.Equal(t, 1, typeCalls)
					}
				}
			})
		}
	}
}

func TestQualSP281CLaneFOrdinaryMetaAccountReloadFailure(t *testing.T) {
	sentinel := errors.New("ordinary execution account unavailable")
	tx := &transaction.Transaction{SndAddr: senderAddress, RcvAddr: recvAddress, Value: big.NewInt(0)}
	sender, receiver := createUserAcc(tx.SndAddr), createUserAcc(tx.RcvAddr)
	accounts := createAccountStub(tx.SndAddr, tx.RcvAddr, sender, receiver)
	load := accounts.LoadAccountCalled
	senderReads := 0
	accounts.LoadAccountCalled = func(address []byte) (vmcommon.AccountHandler, error) {
		if bytes.Equal(address, tx.SndAddr) {
			senderReads++
			if senderReads == 2 {
				return nil, sentinel
			}
		}
		return load(address)
	}

	args := createMockNewMetaTxArgs()
	args.Accounts = accounts
	wantHash, err := core.CalculateHash(args.Marshalizer, args.Hasher, tx)
	require.NoError(t, err)
	hashRecords := 0
	accounts.SetTxHashForLatestStateAccessesCalled = func(hash []byte) {
		require.Equal(t, wantHash, hash)
		hashRecords++
	}
	args.TxTypeHandler = &testscommon.TxTypeHandlerMock{
		ComputeTransactionTypeCalled: func(data.TransactionHandler) (process.TransactionType, process.TransactionType, bool) {
			return process.SCInvoking, process.SCInvoking, false
		},
	}
	args.ScProcessor = &testscommon.SCProcessorMock{
		ExecuteSmartContractTransactionCalled: func(data.TransactionHandler, state.UserAccountHandler, state.UserAccountHandler) (vmcommon.ReturnCode, error) {
			t.Fatal("ordinary dispatch reached execution after account reload failure")
			return vmcommon.ExecutionFailed, nil
		},
	}

	processor, err := txproc.NewMetaTxProcessor(args)
	require.NoError(t, err)
	code, err := processor.ProcessTransactionWithDRWA(tx, nil)
	require.ErrorIs(t, err, sentinel)
	require.Zero(t, code)
	require.Equal(t, 2, senderReads)
	require.Equal(t, 1, hashRecords)
}
