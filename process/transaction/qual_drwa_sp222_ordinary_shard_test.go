package transaction_test

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/receipt"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/coordinator"
	"github.com/multiversx/mx-chain-go/process/mock"
	txproc "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"
)

// INV-0: ordinary transfer persistence and output ordering follow the pinned
// upstream move-balance path. The accounts and observers are in-memory only.
func TestQualSP222OrdinaryShardAccounting(t *testing.T) {
	for _, tc := range []struct {
		name                                        string
		self, destination                           uint32
		provided                                    uint64
		senderBalance, receiverBalance, fee, refund int64
		senderNonce, receiverNonce                  uint64
		value                                       int64
		sameAccount                                 bool
		trace                                       []string
	}{
		{"same_shard", 1, 1, 3, 79, 25, 6, 0, 5, 0, 15, false, []string{"load sender", "load receiver", "save sender:94:4", "save sender:79:5", "payable", "save receiver:25:0", "fee", "hash"}},
		{"source_shard", 1, 2, 3, 79, 10, 6, 0, 5, 0, 15, false, []string{"load sender", "save sender:94:4", "save sender:79:5", "payable", "fee", "hash"}},
		{"destination_shard", 2, 2, 3, 100, 25, 0, 0, 4, 0, 15, false, []string{"load receiver", "payable", "save receiver:25:0", "fee", "hash"}},
		{"same_shard_surplus", 1, 1, 5, 79, 25, 6, 4, 5, 0, 15, false, []string{"load sender", "load receiver", "save sender:94:4", "save sender:79:5", "payable", "save receiver:25:0", "receipt", "fee", "hash"}},
		{"same_account", 1, 1, 3, 94, 94, 6, 0, 5, 5, 15, true, []string{"load sender", "save sender:94:4", "save sender:79:5", "payable", "save sender:94:5", "fee", "hash"}},
		{"zero_value", 1, 1, 3, 94, 10, 6, 0, 5, 0, 0, false, []string{"load sender", "load receiver", "save sender:94:4", "save sender:94:5", "payable", "save receiver:10:0", "fee", "hash"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receiverByte := byte(5)
			if tc.destination == 2 {
				receiverByte = 2
			}
			if tc.sameAccount {
				receiverByte = 1
			}
			tx := &transaction.Transaction{SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Repeat([]byte{receiverByte}, 32), Value: big.NewInt(tc.value), Nonce: 4, GasLimit: tc.provided, GasPrice: 2}
			args := createArgsForTxProcessor()
			shards, err := sharding.NewMultiShardCoordinator(3, tc.self)
			require.NoError(t, err)
			require.Equal(t, uint32(1), shards.ComputeId(tx.SndAddr))
			require.Equal(t, tc.destination, shards.ComputeId(tx.RcvAddr))
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
			require.Equal(t, process.MoveBalance, kind)
			require.Equal(t, process.MoveBalance, destinationKind)
			require.False(t, relayed)
			args.TxTypeHandler = classifier

			sender, receiver := createUserAcc(tx.SndAddr), createUserAcc(tx.RcvAddr)
			sender.IncreaseNonce(4)
			require.NoError(t, sender.AddToBalance(big.NewInt(100)))
			if tc.sameAccount {
				receiver = sender
			} else {
				require.NoError(t, receiver.AddToBalance(big.NewInt(10)))
			}
			accounts := createAccountStub(tx.SndAddr, tx.RcvAddr, sender, receiver)
			var trace []string
			accounts.LoadAccountCalled = func(address []byte) (vmcommon.AccountHandler, error) {
				if bytes.Equal(address, tx.SndAddr) {
					trace = append(trace, "load sender")
					require.Equal(t, uint32(1), tc.self)
					return sender, nil
				}
				require.Equal(t, tx.RcvAddr, address)
				require.Equal(t, tc.destination, tc.self)
				trace = append(trace, "load receiver")
				return receiver, nil
			}
			accounts.SaveAccountCalled = func(account vmcommon.AccountHandler) error {
				user, ok := account.(state.UserAccountHandler)
				require.True(t, ok)
				name := "receiver"
				if user == sender {
					name = "sender"
				} else {
					require.Same(t, receiver, user)
				}
				trace = append(trace, fmt.Sprintf("save %s:%s:%d", name, user.GetBalance(), user.GetNonce()))
				return nil
			}
			args.Accounts = accounts
			wantHash, err := core.CalculateHash(args.Marshalizer, args.Hasher, tx)
			require.NoError(t, err)
			accounts.SetTxHashForLatestStateAccessesCalled = func(hash []byte) {
				require.Equal(t, wantHash, hash)
				trace = append(trace, "hash")
			}
			args.EconomicsFee = &economicsmocks.EconomicsHandlerMock{
				CheckValidityTxValuesCalled: func(input data.TransactionWithFeeHandler) error { require.Same(t, tx, input); return nil },
				ComputeGasLimitCalled:       func(input data.TransactionWithFeeHandler) uint64 { require.Same(t, tx, input); return 3 },
				ComputeMoveBalanceFeeCalled: func(input data.TransactionWithFeeHandler) *big.Int { require.Same(t, tx, input); return big.NewInt(6) },
				ComputeTxFeeCalled: func(input data.TransactionWithFeeHandler) *big.Int {
					require.Same(t, tx, input)
					return new(big.Int).SetUint64(input.GetGasLimit() * input.GetGasPrice())
				},
			}
			args.ScProcessor = &testscommon.SCProcessorMock{IsPayableCalled: func(snd, rcv []byte) (bool, error) {
				require.Equal(t, tx.SndAddr, snd)
				require.Equal(t, tx.RcvAddr, rcv)
				trace = append(trace, "payable")
				return true, nil
			}}
			args.ReceiptForwarder = &mock.IntermediateTransactionHandlerMock{AddIntermediateTransactionsCalled: func(items []data.TransactionHandler, key []byte) error {
				require.Positive(t, tc.refund)
				require.Len(t, items, 1)
				rpt, ok := items[0].(*receipt.Receipt)
				require.True(t, ok)
				require.Equal(t, big.NewInt(tc.refund), rpt.Value)
				require.Equal(t, tx.SndAddr, rpt.SndAddr)
				require.Equal(t, []byte("refundedGas"), rpt.Data)
				require.Equal(t, wantHash, rpt.TxHash)
				require.Equal(t, wantHash, key)
				trace = append(trace, "receipt")
				return nil
			}}
			args.TxFeeHandler = &mock.FeeAccumulatorStub{ProcessTransactionFeeCalled: func(cost, devFee *big.Int, hash []byte) {
				require.Equal(t, big.NewInt(tc.fee), cost)
				require.Equal(t, big.NewInt(0), devFee)
				require.Equal(t, wantHash, hash)
				trace = append(trace, "fee")
			}}
			processor, err := txproc.NewTxProcessor(args)
			require.NoError(t, err)
			code, err := processor.ProcessTransaction(tx)
			require.NoError(t, err)
			require.Equal(t, vmcommon.Ok, code)
			require.Equal(t, tc.trace, trace)
			require.Equal(t, big.NewInt(tc.senderBalance), sender.GetBalance())
			require.Equal(t, tc.senderNonce, sender.GetNonce())
			require.Equal(t, big.NewInt(tc.receiverBalance), receiver.GetBalance())
			require.Equal(t, tc.receiverNonce, receiver.GetNonce())
		})
	}
}
