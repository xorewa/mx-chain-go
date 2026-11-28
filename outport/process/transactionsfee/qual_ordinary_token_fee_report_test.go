package transactionsfee

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	outportcore "github.com/multiversx/mx-chain-core-go/data/outport"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/testscommon"
	datafield "github.com/multiversx/mx-chain-vm-common-go/parsers/dataField"
	"github.com/stretchr/testify/require"
)

// TestQualOrdinaryTokenFeeReportMetadata tests the exported fee report using
// already-parsed synthetic DTO metadata. No executable payload is constructed.
func TestQualOrdinaryTokenFeeReportMetadata(t *testing.T) {
	sender := bytes.Repeat([]byte{0x11}, 32)
	user := bytes.Repeat([]byte{0x22}, 32)
	contract := make([]byte, 32)
	contract[len(contract)-1] = 0x33
	require.False(t, core.IsSmartContractAddress(user))
	require.True(t, core.IsSmartContractAddress(contract))

	for _, tc := range []struct {
		name     string
		receiver []byte
		function string
		gasUsed  uint64
		fee      int64
	}{
		{
			name:     "ordinary transfer report",
			receiver: user,
			gasUsed:  60_500,
			fee:      60_500_000_000_000,
		},
		{
			name:     "ordinary contract call report",
			receiver: contract,
			function: "receive",
			gasUsed:  80_000,
			fee:      60_695_000_000_000,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			processor, err := NewTransactionsFeeProcessor(prepareMockArg())
			require.NoError(t, err)

			// The data field is an inert fixture label, not encoded call data.
			marker := []byte("fixture")
			calls := 0
			processor.dataFieldParser = &testscommon.DataFieldParserStub{
				ParseCalled: func(data, from, to []byte, _, _ uint32) *datafield.ResponseParseData {
					require.Equal(t, marker, data)
					require.Equal(t, sender, from)
					require.Equal(t, tc.receiver, to)
					calls++
					return &datafield.ResponseParseData{
						Operation: core.BuiltInFunctionESDTTransfer,
						Function:  tc.function,
						Receivers: [][]byte{tc.receiver},
					}
				},
			}

			info := &outportcore.TxInfo{
				Transaction: &transaction.Transaction{
					SndAddr: sender, RcvAddr: tc.receiver, Data: marker,
					Value: big.NewInt(0), GasLimit: 80_000, GasPrice: 1_000_000_000,
				},
				FeeInfo: &outportcore.FeeInfo{},
			}
			pool := &outportcore.TransactionPool{
				Transactions: map[string]*outportcore.TxInfo{"fixture": info},
			}

			require.NoError(t, processor.PutFeeAndGasUsed(pool, 0))
			// Both fee classification and result-log handling read the DTO.
			require.Equal(t, 2, calls)
			require.Equal(t, tc.gasUsed, info.FeeInfo.GetGasUsed())
			require.Equal(t, big.NewInt(tc.fee), info.FeeInfo.GetFee())
			require.Equal(t, big.NewInt(60_695_000_000_000), info.FeeInfo.GetInitialPaidFee())
		})
	}
}
