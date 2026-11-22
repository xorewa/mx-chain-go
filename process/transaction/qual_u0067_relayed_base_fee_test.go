package transaction_test

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/mock"
	txproc "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/stretchr/testify/require"
)

// U0067: exercise the existing shard processor export and account debit.
// Pinned v2.1.9 shardProcess.go:910-922 selects processing(baseGas) when
// FixRelayedBaseCostFlag is disabled and ComputeMoveBalanceFee when enabled.
// Gas 5, processing price 7, move fee 11 and balance 100 are experimental
// discriminators, not network parameters. The expected fees are 35 and 11.
func TestQualU0067RelayedMoveBalanceBaseFeeGuard(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		fee     int64
	}{
		{"disabled", false, 35},
		{"enabled", true, 11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := createArgsForTxProcessor()
			args.EnableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
			if tc.enabled {
				args.EnableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.FixRelayedBaseCostFlag)
			}
			userTx := &transaction.Transaction{GasLimit: 100, GasPrice: 1, Value: big.NewInt(0)}
			baseCalls, processingCalls, moveCalls := 0, 0, 0
			args.EconomicsFee = &economicsmocks.EconomicsHandlerMock{
				ComputeGasLimitCalled: func(tx data.TransactionWithFeeHandler) uint64 {
					require.Same(t, userTx, tx)
					baseCalls++
					return 5
				},
				ComputeFeeForProcessingCalled: func(tx data.TransactionWithFeeHandler, gas uint64) *big.Int {
					require.Same(t, userTx, tx)
					require.Equal(t, uint64(5), gas)
					processingCalls++
					return new(big.Int).Mul(new(big.Int).SetUint64(gas), big.NewInt(7))
				},
				ComputeMoveBalanceFeeCalled: func(tx data.TransactionWithFeeHandler) *big.Int {
					require.Same(t, userTx, tx)
					moveCalls++
					return big.NewInt(11)
				},
			}
			originalHash := []byte("original-transaction")
			collectorCalls := 0
			args.TxFeeHandler = &mock.FeeAccumulatorStub{
				ProcessTransactionFeeCalled: func(*big.Int, *big.Int, []byte) {
					t.Fatal("ordinary fee collector used for relayed user transaction")
				},
				ProcessTransactionFeeRelayedUserTxCalled: func(cost, developerFee *big.Int, _ []byte, original []byte) {
					collectorCalls++
					require.Equal(t, big.NewInt(tc.fee), cost, "relayed base-fee charged")
					require.Equal(t, big.NewInt(0), developerFee)
					require.Equal(t, originalHash, original)
				},
			}
			processor, err := txproc.NewTxProcessor(args)
			require.NoError(t, err)
			account := createUserAcc([]byte("sender"))
			require.NoError(t, account.AddToBalance(big.NewInt(100)))
			err = processor.ProcessMoveBalanceCostRelayedUserTx(userTx, &smartContractResult.SmartContractResult{}, account, originalHash)
			require.NoError(t, err)
			require.Equal(t, big.NewInt(100-tc.fee), account.GetBalance(), "same relayed base-fee debited")
			require.Equal(t, 1, collectorCalls)
			require.Equal(t, 1, baseCalls)
			require.Equal(t, 1, processingCalls)
			if tc.enabled {
				require.Equal(t, 1, moveCalls)
			} else {
				require.Zero(t, moveCalls)
			}
		})
	}
}
