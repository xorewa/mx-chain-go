package transactionAPI

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/receipt"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// Only the ordinary receipt response DTO codec is exercised, with no transaction
// object, retrieval, execution or account state.
func TestQualLaneDOrdinaryReceiptDisplay(t *testing.T) {
	codec := &marshal.GogoProtoMarshalizer{}
	sender := []byte("ordinary-sender-display")
	wire, err := codec.Marshal(&receipt.Receipt{
		Value: big.NewInt(17), SndAddr: sender,
		Data: []byte("ordinary-note"), TxHash: []byte{1, 2, 0xab},
	})
	require.NoError(t, err)
	calls := 0
	processor := &apiTransactionProcessor{txUnmarshaller: &txUnmarshaller{
		marshalizer: codec,
		addressPubKeyConverter: &testscommon.PubkeyConverterStub{
			SilentEncodeCalled: func(value []byte, _ core.Logger) string {
				calls++
				require.Equal(t, sender, value)
				return "ordinary-display"
			},
		},
	}}
	got, err := processor.UnmarshalReceipt(wire)
	require.NoError(t, err)
	require.Equal(t, &transaction.ApiReceipt{
		Value: big.NewInt(17), SndAddr: "ordinary-display",
		Data: "ordinary-note", TxHash: "0102ab",
	}, got)
	require.Equal(t, 1, calls)
}
