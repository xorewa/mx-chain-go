package transactionsfee

import (
	"encoding/json"
	"math/big"
	"testing"

	coredata "github.com/multiversx/mx-chain-core-go/data"
	outportcore "github.com/multiversx/mx-chain-core-go/data/outport"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	datafield "github.com/multiversx/mx-chain-vm-common-go/parsers/dataField"
	"github.com/stretchr/testify/require"
)

// Offline fee display only: amounts come from a synthetic calculator, not
// from execution, balances, resource policy, or a native fee calculation.
func TestQualSP218OrdinaryWideFeeDisplay(t *testing.T) {
	wide := func(offset int64) *big.Int {
		return new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(offset))
	}
	const gasUsed = uint64(50001)
	const wantFee = "18446744073709551643"
	const wantInitial = "18446744073709551745"
	const wantWire = `{"gasUsed":50001,"fee":18446744073709551643,"initialPaidFee":18446744073709551745}`
	fee, initial := wide(27), wide(129)
	dto := &transaction.Transaction{SndAddr: []byte("sender"), RcvAddr: []byte("receiver"), Value: big.NewInt(1), GasLimit: 60001}
	arg := prepareMockArg()
	arg.TxFeeCalculator = &economicsmocks.EconomicsHandlerMock{
		ComputeGasLimitCalled: func(tx coredata.TransactionWithFeeHandler) uint64 {
			require.Same(t, dto, tx)
			return gasUsed
		},
		ComputeTxFeeBasedOnGasUsedCalled: func(tx coredata.TransactionWithFeeHandler, used uint64) *big.Int {
			require.Same(t, dto, tx)
			require.Equal(t, gasUsed, used)
			return fee
		},
		ComputeTxFeeCalled: func(tx coredata.TransactionWithFeeHandler) *big.Int {
			require.Same(t, dto, tx)
			return initial
		},
	}
	processor, err := NewTransactionsFeeProcessor(arg)
	require.NoError(t, err)
	processor.dataFieldParser = &testscommon.DataFieldParserStub{
		ParseCalled: func(_ []byte, _, _ []byte, _, _ uint32) *datafield.ResponseParseData {
			return &datafield.ResponseParseData{Operation: datafield.OperationTransfer}
		},
	}
	item := &outportcore.TxInfo{Transaction: dto, FeeInfo: &outportcore.FeeInfo{}}
	pool := &outportcore.TransactionPool{Transactions: map[string]*outportcore.TxInfo{"display": item}}
	require.NoError(t, processor.PutFeeAndGasUsed(pool, 0))
	require.Equal(t, gasUsed, item.FeeInfo.GetGasUsed())
	require.Equal(t, wantFee, item.FeeInfo.GetFee().String())
	require.Equal(t, wantInitial, item.FeeInfo.GetInitialPaidFee().String())
	wire, err := json.Marshal(item.FeeInfo)
	require.NoError(t, err)
	// Compare exact decimal tokens, not float64-based JSON equivalence.
	require.Equal(t, wantWire, string(wire))
	var readback outportcore.FeeInfo
	require.NoError(t, json.Unmarshal(wire, &readback))
	require.Equal(t, gasUsed, readback.GetGasUsed())
	require.Equal(t, wantFee, readback.GetFee().String())
	require.Equal(t, wantInitial, readback.GetInitialPaidFee().String())
	require.Equal(t, wantFee, fee.String())
	require.Equal(t, wantInitial, initial.String())
}
