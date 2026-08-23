package drwaprototype

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrototypeSettlementReceiptRoundTripAndIdentityBinding(t *testing.T) {
	networkDomain := [32]byte{1}
	effectID := [32]byte{2}
	contextHash := [32]byte{3}
	executionIdentity := [32]byte{4}

	receipt, err := BuildSettlementReceipt(networkDomain, effectID, contextHash, executionIdentity)
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, receipt.DestinationResultIdentity)
	encoded, err := EncodeSettlementReceipt(receipt)
	require.NoError(t, err)
	decoded, err := DecodeSettlementReceipt(encoded)
	require.NoError(t, err)
	require.Equal(t, receipt, *decoded)

	changed, err := BuildSettlementReceipt([32]byte{9}, effectID, contextHash, executionIdentity)
	require.NoError(t, err)
	require.NotEqual(t, receipt.DestinationResultIdentity, changed.DestinationResultIdentity)
}

func TestPrototypeRefundEnvelopeRoundTrip(t *testing.T) {
	refund := RefundEnvelope{
		EffectID:                     [32]byte{1},
		ContextHash:                  [32]byte{2},
		DestinationExecutionIdentity: [32]byte{3},
		OriginalTransferPayload:      []byte("ESDTTransfer@544f4b454e2d616263646566@02"),
		RefundTo:                     [32]byte{4},
	}
	encoded, err := EncodeRefundEnvelope(refund)
	require.NoError(t, err)
	decoded, err := DecodeRefundEnvelope(encoded)
	require.NoError(t, err)
	require.Equal(t, refund, *decoded)

}

func TestPrototypeValueResultsRejectMissingIdentity(t *testing.T) {
	_, err := BuildSettlementReceipt([32]byte{}, [32]byte{1}, [32]byte{2}, [32]byte{3})
	require.ErrorIs(t, err, ErrInvalidSettlementReceipt)
	_, err = EncodeRefundEnvelope(RefundEnvelope{})
	require.ErrorIs(t, err, ErrInvalidRefundEnvelope)
}
