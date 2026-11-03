package processorV2

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Experimental tariffs and balances discriminate fee/refund/reward ownership;
// they are not network economic parameters. Actual node entry/output/refund,
// fee-collector, SCR creation and AccountsDB paths are used with a VM fixture.
func TestQualPartialsG07GasFeeOwners(t *testing.T) {
	db := qualPartialsR01Accounts(t)
	sender := bytes.Repeat([]byte{7}, 32)
	main, child, remote := make([]byte, 32), make([]byte, 32), make([]byte, 32)
	for i, p := range [][]byte{main, child, remote} {
		p[8] = 5
		p[31] = byte(i + 1)
	}
	remote[31] = 9
	for _, addr := range [][]byte{sender, main, child} {
		a, e := db.LoadAccount(addr)
		require.NoError(t, e)
		u := a.(state.UserAccountHandler)
		if bytes.Equal(addr, sender) {
			require.NoError(t, u.AddToBalance(big.NewInt(10000)))
		} else {
			u.SetCode([]byte("fixture"))
			u.SetOwnerAddress(sender)
		}
		require.NoError(t, db.SaveAccount(u))
	}
	_, err := db.Commit()
	require.NoError(t, err)
	args := createMockSmartContractProcessorArguments()
	args.AccountsDB = db
	args.ArgsParser = smartContract.NewArgumentParser()
	args.Hasher = blake2b.NewBlake2b()
	args.Marshalizer = &marshal.GogoProtoMarshalizer{}
	args.EnableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.SCDeployFlag, common.FixCorrectSmallIntAndGasLimitsFlag)
	args.ShardCoordinator = &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return 0 }, ComputeIdCalled: func(addr []byte) uint32 {
		if bytes.Equal(addr, remote) {
			return 1
		}
		return 0
	}}
	args.EconomicsFee = &economicsmocks.EconomicsHandlerMock{
		ComputeGasLimitCalled:       func(data.TransactionWithFeeHandler) uint64 { return 100 },
		ComputeMoveBalanceFeeCalled: func(data.TransactionWithFeeHandler) *big.Int { return big.NewInt(11) },
		ComputeTxFeeCalled:          func(data.TransactionWithFeeHandler) *big.Int { return big.NewInt(2711) },
		ComputeFeeForProcessingCalled: func(_ data.TransactionWithFeeHandler, gas uint64) *big.Int {
			return new(big.Int).Mul(new(big.Int).SetUint64(gas), big.NewInt(3))
		},
		DeveloperPercentageCalled: func() float64 { return 0.1 },
	}
	feeCalls, refunded := 0, uint64(0)
	args.TxFeeHandler = &mock.FeeAccumulatorStub{ProcessTransactionFeeCalled: func(fee, dev *big.Int, _ []byte) {
		feeCalls++
		require.Equal(t, big.NewInt(1811), fee, "exact local fee")
		require.Equal(t, big.NewInt(180), dev, "exact developer component")
	}}
	args.GasHandler = &testscommon.GasHandlerStub{SetGasRefundedCalled: func(gas uint64, _ []byte) { refunded = gas }}
	var forwarded []data.TransactionHandler
	args.ScrForwarder = &mock.IntermediateTransactionHandlerMock{AddIntermediateTransactionsCalled: func(txs []data.TransactionHandler, _ []byte) error { forwarded = append(forwarded, txs...); return nil }}
	args.VmContainer = &mock.VMContainerMock{GetCalled: func([]byte) (vmcommon.VMExecutionHandler, error) {
		return &mock.VMExecutionHandlerStub{RunSmartContractCallCalled: func(in *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
			require.Equal(t, uint64(900), in.GasProvided)
			return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 200, GasRefund: big.NewInt(0), OutputAccounts: map[string]*vmcommon.OutputAccount{
				string(main):   {Address: main, BalanceDelta: big.NewInt(0)},
				string(child):  {Address: child, GasUsed: 100, BalanceDelta: big.NewInt(0)},
				string(remote): {Address: remote, BalanceDelta: big.NewInt(0), OutputTransfers: []vmcommon.OutputTransfer{{SenderAddress: main, Value: big.NewInt(0), GasLimit: 70, GasLocked: 30, Data: []byte("work"), CallType: vmData.AsynchronousCall}}},
			}}, nil
		}}, nil
	}}
	sc, err := NewSmartContractProcessorV2(args)
	require.NoError(t, err)
	tx := &transaction.Transaction{SndAddr: sender, RcvAddr: main, Value: big.NewInt(0), GasLimit: 1000, GasPrice: 9, Data: []byte("work")}
	src, err := db.GetExistingAccount(sender)
	require.NoError(t, err)
	dst, err := db.GetExistingAccount(main)
	require.NoError(t, err)
	rc, err := sc.ExecuteSmartContractTransaction(tx, src.(state.UserAccountHandler), dst.(state.UserAccountHandler))
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, rc)
	require.Equal(t, 1, feeCalls)
	require.Equal(t, uint64(200), refunded)
	require.Len(t, forwarded, 2)
	seenRemote, seenRefund := false, false
	for _, h := range forwarded {
		scr := h.(*smartContractResult.SmartContractResult)
		if bytes.Equal(scr.RcvAddr, remote) {
			seenRemote = true
			require.Equal(t, main, scr.SndAddr)
			require.Equal(t, uint64(100), scr.GasLimit, "outbound async locked gas owner")
			require.Equal(t, []byte("work@1e"), scr.Data)
			require.Equal(t, vmData.AsynchronousCall, scr.CallType)
			require.Zero(t, scr.Value.Sign())
		}
		if bytes.Equal(scr.RcvAddr, sender) {
			seenRefund = true
			require.Equal(t, big.NewInt(600), scr.Value, "returned gas refund")
			require.Zero(t, scr.GasLimit)
		}
	}
	require.True(t, seenRemote)
	require.True(t, seenRefund)
	root, err := db.Commit()
	require.NoError(t, err)
	require.NoError(t, db.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	for i, addr := range [][]byte{sender, main, child} {
		a, e := db.GetExistingAccount(addr)
		require.NoError(t, e)
		u := a.(state.UserAccountHandler)
		if i == 0 {
			require.Equal(t, big.NewInt(7889), u.GetBalance(), "sender fee/refund balance")
			require.Equal(t, uint64(1), u.GetNonce())
		} else {
			want := int64(150)
			if i == 2 {
				want = 30
			}
			require.Equal(t, big.NewInt(want), u.GetDeveloperReward(), "per-contract developer reward")
			require.Equal(t, sender, u.GetOwnerAddress())
		}
	}
}
