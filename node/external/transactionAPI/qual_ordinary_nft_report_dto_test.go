package transactionAPI

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// Only in-memory reporting DTO fields and a converter stub are used here.
func TestQualOrdinaryNFTReportDTOClassification(t *testing.T) {
	contractAddress := make([]byte, 32)
	contractAddress[8] = 1
	contractAddress[31] = 1
	require.True(t, core.IsSmartContractAddress(contractAddress))

	tests := []struct {
		name          string
		receiver      string
		function      string
		receivers     []string
		decodeErr     error
		expectedCalls int
		expected      bool
	}{
		{name: "distinct receiver display", receiver: "receiver", function: "display", expected: true},
		{name: "decoded receiver display", receiver: "sender", function: "display",
			receivers: []string{"synthetic-receiver"}, expectedCalls: 1, expected: true},
		{name: "empty function display", receiver: "receiver"},
		{name: "absent receiver display", receiver: "sender", function: "display"},
		{name: "receiver format error", receiver: "sender", function: "display",
			receivers: []string{"synthetic-invalid"}, decodeErr: errors.New("ordinary format error"), expectedCalls: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			processor := &gasUsedAndFeeProcessor{
				pubKeyConverter: &testscommon.PubkeyConverterStub{
					DecodeCalled: func(label string) ([]byte, error) {
						calls++
						require.NotEmpty(t, tt.receivers)
						require.Equal(t, tt.receivers[0], label)
						if tt.decodeErr != nil {
							return nil, tt.decodeErr
						}
						return contractAddress, nil
					},
				},
			}
			dto := &transaction.ApiTransactionResult{
				Tx:        &transaction.Transaction{RcvAddr: contractAddress},
				Operation: core.BuiltInFunctionESDTNFTTransfer,
				Sender:    "sender",
				Receiver:  tt.receiver,
				Function:  tt.function,
				Receivers: tt.receivers,
			}

			require.Equal(t, tt.expected, processor.isESDTOperationWithSCCall(dto))
			require.Equal(t, tt.expectedCalls, calls)
		})
	}
}
