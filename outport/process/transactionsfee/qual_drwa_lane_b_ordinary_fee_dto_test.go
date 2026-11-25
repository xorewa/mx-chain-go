package transactionsfee

import (
	"encoding/json"
	"math/big"
	"testing"

	outportcore "github.com/multiversx/mx-chain-core-go/data/outport"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAOrdinaryFeeReportEmptyPool(t *testing.T) {
	t.Parallel()

	processor, err := NewTransactionsFeeProcessor(prepareMockArg())
	require.NoError(t, err)
	require.False(t, processor.IsInterfaceNil())
	pool := &outportcore.TransactionPool{}
	require.NoError(t, processor.PutFeeAndGasUsed(pool, 0))
	require.Equal(t, &outportcore.TransactionPool{}, pool)
}

func TestQualDRWAOrdinaryFeeReportDTOFormatting(t *testing.T) {
	t.Parallel()

	processor, err := NewTransactionsFeeProcessor(prepareMockArg())
	require.NoError(t, err)
	pool := &outportcore.TransactionPool{Transactions: map[string]*outportcore.TxInfo{
		"plain": {Transaction: &transaction.Transaction{Nonce: 1, SndAddr: []byte("sender"), RcvAddr: []byte("receiver"), Value: big.NewInt(1), GasLimit: 50_000, GasPrice: 1_000_000_000}, FeeInfo: &outportcore.FeeInfo{}},
		"memo":  {Transaction: &transaction.Transaction{Nonce: 2, SndAddr: []byte("sender"), RcvAddr: []byte("receiver"), Value: big.NewInt(2), Data: []byte("memo"), GasLimit: 80_000, GasPrice: 1_000_000_000}, FeeInfo: &outportcore.FeeInfo{}},
	}}
	require.NoError(t, processor.PutFeeAndGasUsed(pool, 0))
	for _, tc := range []struct {
		key      string
		want     *outportcore.FeeInfo
		wantJSON string
	}{
		{key: "plain", want: &outportcore.FeeInfo{GasUsed: 50_000, Fee: big.NewInt(50_000_000_000_000), InitialPaidFee: big.NewInt(50_000_000_000_000)}, wantJSON: `{"gasUsed":50000,"fee":50000000000000,"initialPaidFee":50000000000000}`},
		{key: "memo", want: &outportcore.FeeInfo{GasUsed: 56_000, Fee: big.NewInt(56_000_000_000_000), InitialPaidFee: big.NewInt(56_240_000_000_000)}, wantJSON: `{"gasUsed":56000,"fee":56000000000000,"initialPaidFee":56240000000000}`},
	} {
		got := pool.Transactions[tc.key].FeeInfo
		require.Equal(t, tc.want, got)
		wire, err := json.Marshal(got)
		require.NoError(t, err)
		require.JSONEq(t, tc.wantJSON, string(wire))
		var readback outportcore.FeeInfo
		require.NoError(t, json.Unmarshal(wire, &readback))
		require.Equal(t, tc.want, &readback)
	}
}
