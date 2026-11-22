package transaction

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state/accounts"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/stretchr/testify/require"
)

// U0067: local fee selection and its real checkTxValues consumer. These
// deliberately distinct fixture tariffs are experimental branch discriminators,
// not network economics: processing=3/gas, move=11, base gas=20, total gas=100.
// Pinned node v2.1.9 baseProcess.go:267-291 selects processing(100)=300
// before FixRelayedBaseCost; afterwards MoveBalance=11, other=11+3*80=251.
func TestQualPartialInnerFee(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fix         bool
		destination process.TransactionType
		expected    int64
		trace       []string
	}{
		{"legacy_move", false, process.MoveBalance, 300, []string{"processing"}},
		{"legacy_call", false, process.SCInvoking, 300, []string{"processing"}},
		{"fixed_move", true, process.MoveBalance, 11, []string{"type", "move"}},
		{"fixed_call", true, process.SCInvoking, 251, []string{"type", "base", "move", "processing"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &transaction.Transaction{GasLimit: 100, GasPrice: 7, Value: big.NewInt(0), SndAddr: []byte("sender"), RcvAddr: []byte("receiver")}
			p := createMockBaseTxProcessor()
			p.enableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.PenalizedTooMuchGasFlag)
			if tc.fix {
				p.enableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.PenalizedTooMuchGasFlag, common.FixRelayedBaseCostFlag)
			}
			trace := []string{}
			p.economicsFee = &economicsmocks.EconomicsHandlerMock{
				CheckValidityTxValuesCalled: func(data.TransactionWithFeeHandler) error { return nil },
				ComputeGasLimitCalled: func(got data.TransactionWithFeeHandler) uint64 {
					require.Same(t, tx, got)
					trace = append(trace, "base")
					return 20
				},
				ComputeMoveBalanceFeeCalled: func(got data.TransactionWithFeeHandler) *big.Int {
					require.Same(t, tx, got)
					trace = append(trace, "move")
					return big.NewInt(11)
				},
				ComputeFeeForProcessingCalled: func(got data.TransactionWithFeeHandler, gas uint64) *big.Int {
					require.Same(t, tx, got)
					trace = append(trace, "processing")
					return new(big.Int).Mul(new(big.Int).SetUint64(gas), big.NewInt(3))
				},
				ComputeTxFeeCalled: func(data.TransactionWithFeeHandler) *big.Int {
					t.Fatal("ordinary fee used for relayed inner transaction")
					return nil
				},
			}
			p.txTypeHandler = &testscommon.TxTypeHandlerMock{ComputeTransactionTypeCalled: func(got data.TransactionHandler) (process.TransactionType, process.TransactionType, bool) {
				require.Same(t, tx, got)
				trace = append(trace, "type")
				return process.MoveBalance, tc.destination, false
			}}
			require.Equal(t, tc.expected, p.computeInnerTxFee(tx).Int64(), "inner fee branch tariff")
			require.Equal(t, tc.trace, trace, "branch dispatch trace")
			sender, err := accounts.NewUserAccount(tx.SndAddr, &trie.DataTrieTrackerStub{}, &trie.TrieLeafParserStub{})
			require.NoError(t, err)
			require.NoError(t, sender.AddToBalance(big.NewInt(tc.expected-1)))
			err = p.checkTxValues(tx, sender, nil, true)
			require.ErrorIs(t, err, process.ErrInsufficientFee, "one below inner fee must be rejected")
			require.NoError(t, sender.AddToBalance(big.NewInt(1)))
			require.NoError(t, p.checkTxValues(tx, sender, nil, true), "exact inner fee must be admitted")
			tx.Value = big.NewInt(1)
			require.ErrorIs(t, p.checkTxValues(tx, sender, nil, true), process.ErrInsufficientFunds, "value remains sender-owned after fee selection")
			tx.Value = big.NewInt(0)
			tx.GasLimit = 19
			require.ErrorIs(t, p.checkTxValues(tx, sender, nil, true), process.ErrNotEnoughGasInUserTx, "base gas guard precedes unsigned subtraction")
		})
	}
}
