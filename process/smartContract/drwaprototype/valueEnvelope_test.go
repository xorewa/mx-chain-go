package drwaprototype

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

func TestValueEnvelopePrototypeDeterministicFixture(t *testing.T) {
	t.Parallel()

	fixture := createValueEnvelopeFixture()
	encoded, err := EncodeValueEnvelope(fixture)
	require.NoError(t, err)

	require.Equal(t, "010000002a455344545472616e736665724035343466346234353465326436313632363336343635363640303130300102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20012122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40000c544f4b454e2d61626364656601000201004142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80000000070100000000499602d28182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0000000000000006400000000000000c8000000000000012c0000000000000190", hex.EncodeToString(encoded))
	digest := sha256.Sum256(encoded)
	require.Equal(t, "cb56fe848a93f3781cb1b3d7e8bd37d8aef634c2c848b42ff47ee72ded2d4cda", hex.EncodeToString(digest[:]))

	decoded, err := DecodeValueEnvelope(encoded)
	require.NoError(t, err)
	require.Equal(t, fixture, *decoded)

	reencoded, err := EncodeValueEnvelope(*decoded)
	require.NoError(t, err)
	require.Equal(t, encoded, reencoded)
}

func TestValueEnvelopePrototypeDoesNotAliasCallerOrEncodedSlices(t *testing.T) {
	t.Parallel()

	fixture := createValueEnvelopeFixture()
	encoded, err := EncodeValueEnvelope(fixture)
	require.NoError(t, err)
	encodedBeforeMutation := append([]byte(nil), encoded...)

	fixture.OriginalTransferPayload[0] ^= 0xff
	fixture.Context.RegulatedTokenID[0] ^= 0xff
	fixture.Context.Quantity[0] ^= 0xff
	require.Equal(t, encodedBeforeMutation, encoded)

	decoded, err := DecodeValueEnvelope(encoded)
	require.NoError(t, err)
	decodedPayload := append([]byte(nil), decoded.OriginalTransferPayload...)
	decodedTokenID := append([]byte(nil), decoded.Context.RegulatedTokenID...)
	decodedQuantity := append([]byte(nil), decoded.Context.Quantity...)

	for index := range encoded {
		encoded[index] ^= 0xff
	}
	require.Equal(t, decodedPayload, decoded.OriginalTransferPayload)
	require.Equal(t, decodedTokenID, decoded.Context.RegulatedTokenID)
	require.Equal(t, decodedQuantity, decoded.Context.Quantity)
}

func TestEncodeValueEnvelopePrototypeRejectsUnsupportedOrUnboundedFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(envelope *ValueEnvelope)
	}{
		{
			name: "empty payload",
			mutate: func(envelope *ValueEnvelope) {
				envelope.OriginalTransferPayload = nil
			},
		},
		{
			name: "payload above prototype limit",
			mutate: func(envelope *ValueEnvelope) {
				envelope.OriginalTransferPayload = make([]byte, prototypePayloadLimit+1)
			},
		},
		{
			name: "unsupported effect kind",
			mutate: func(envelope *ValueEnvelope) {
				envelope.Context.EffectKind = ValueEffectKind(2)
			},
		},
		{
			name: "empty token identifier",
			mutate: func(envelope *ValueEnvelope) {
				envelope.Context.RegulatedTokenID = nil
			},
		},
		{
			name: "token identifier above prototype limit",
			mutate: func(envelope *ValueEnvelope) {
				envelope.Context.RegulatedTokenID = make([]byte, prototypeTokenIDLimit+1)
			},
		},
		{
			name: "unsupported token type",
			mutate: func(envelope *ValueEnvelope) {
				envelope.Context.RegulatedTokenType = TokenType(2)
			},
		},
		{
			name: "zero quantity",
			mutate: func(envelope *ValueEnvelope) {
				envelope.Context.Quantity = nil
			},
		},
		{
			name: "non-minimal quantity",
			mutate: func(envelope *ValueEnvelope) {
				envelope.Context.Quantity = []byte{0, 1}
			},
		},
		{
			name: "quantity above prototype limit",
			mutate: func(envelope *ValueEnvelope) {
				envelope.Context.Quantity = make([]byte, prototypeQuantityLimit+1)
				envelope.Context.Quantity[0] = 1
			},
		},
		{
			name: "unsupported transfer mode",
			mutate: func(envelope *ValueEnvelope) {
				envelope.Context.TransferMode = TransferMode(2)
			},
		},
		{
			name: "zero expiry",
			mutate: func(envelope *ValueEnvelope) {
				envelope.Context.SettlementExpiry = 0
			},
		},
		{
			name: "zero destination gate budget",
			mutate: func(envelope *ValueEnvelope) {
				envelope.Context.DestinationGateGasLimit = 0
			},
		},
		{
			name: "zero success receipt budget",
			mutate: func(envelope *ValueEnvelope) {
				envelope.Context.SuccessReceiptGasLimit = 0
			},
		},
		{
			name: "zero refund generation budget",
			mutate: func(envelope *ValueEnvelope) {
				envelope.Context.RefundGenerationGasLimit = 0
			},
		},
		{
			name: "zero source completion budget",
			mutate: func(envelope *ValueEnvelope) {
				envelope.Context.SourceCompletionGasLimit = 0
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := createValueEnvelopeFixture()
			test.mutate(&fixture)
			_, err := EncodeValueEnvelope(fixture)
			require.ErrorIs(t, err, ErrInvalidValueEnvelope)
		})
	}
}

func TestDecodeValueEnvelopePrototypeRejectsMalformedBytes(t *testing.T) {
	t.Parallel()

	encoded, err := EncodeValueEnvelope(createValueEnvelopeFixture())
	require.NoError(t, err)

	tests := []struct {
		name   string
		mutate func(value []byte) []byte
	}{
		{
			name: "unsupported version",
			mutate: func(value []byte) []byte {
				value[0] = 2
				return value
			},
		},
		{
			name: "truncated",
			mutate: func(value []byte) []byte {
				return value[:len(value)-1]
			},
		},
		{
			name: "trailing byte",
			mutate: func(value []byte) []byte {
				return append(value, 0)
			},
		},
		{
			name: "payload length above prototype limit",
			mutate: func(value []byte) []byte {
				value[1] = 0xff
				value[2] = 0xff
				value[3] = 0xff
				value[4] = 0xff
				return value
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			mutated := test.mutate(append([]byte(nil), encoded...))
			_, err := DecodeValueEnvelope(mutated)
			require.ErrorIs(t, err, ErrInvalidValueEnvelope)
		})
	}
}

func TestDecodeValueEnvelopePrototypeRejectsEveryTruncatedPrefix(t *testing.T) {
	t.Parallel()

	encoded, err := EncodeValueEnvelope(createValueEnvelopeFixture())
	require.NoError(t, err)

	for prefixLength := 0; prefixLength < len(encoded); prefixLength++ {
		_, err = DecodeValueEnvelope(encoded[:prefixLength])
		require.ErrorIsf(t, err, ErrInvalidValueEnvelope, "prefix length %d", prefixLength)
	}
}

func TestDecodeValueEnvelopePrototypeRejectsInvalidDecodedFields(t *testing.T) {
	t.Parallel()

	fixture := createValueEnvelopeFixture()
	encoded, err := EncodeValueEnvelope(fixture)
	require.NoError(t, err)

	offsets := valueEnvelopeFixtureOffsets(fixture)
	require.Equal(t, byte(fixture.Context.EffectKind), encoded[offsets.effectKind])
	require.Equal(t, byte(fixture.Context.RegulatedTokenType), encoded[offsets.tokenType])
	require.Equal(t, fixture.Context.Quantity, encoded[offsets.quantity:offsets.quantity+len(fixture.Context.Quantity)])
	require.Equal(t, byte(fixture.Context.TransferMode), encoded[offsets.transferMode])
	require.Equal(t, fixture.Context.SettlementExpiry, binary.BigEndian.Uint64(encoded[offsets.settlementExpiry:]))
	require.Equal(t, fixture.Context.DestinationGateGasLimit, binary.BigEndian.Uint64(encoded[offsets.destinationGateGasLimit:]))
	require.Equal(t, fixture.Context.SuccessReceiptGasLimit, binary.BigEndian.Uint64(encoded[offsets.successReceiptGasLimit:]))
	require.Equal(t, fixture.Context.RefundGenerationGasLimit, binary.BigEndian.Uint64(encoded[offsets.refundGenerationGasLimit:]))
	require.Equal(t, fixture.Context.SourceCompletionGasLimit, binary.BigEndian.Uint64(encoded[offsets.sourceCompletionGasLimit:]))

	tests := []struct {
		name   string
		mutate func(value []byte)
	}{
		{
			name: "unsupported effect kind",
			mutate: func(value []byte) {
				value[offsets.effectKind] = 2
			},
		},
		{
			name: "unsupported token type",
			mutate: func(value []byte) {
				value[offsets.tokenType] = 2
			},
		},
		{
			name: "non-minimal quantity",
			mutate: func(value []byte) {
				value[offsets.quantity] = 0
			},
		},
		{
			name: "unsupported transfer mode",
			mutate: func(value []byte) {
				value[offsets.transferMode] = 2
			},
		},
		{
			name: "zero settlement expiry",
			mutate: func(value []byte) {
				clear(value[offsets.settlementExpiry : offsets.settlementExpiry+8])
			},
		},
		{
			name: "zero destination gate budget",
			mutate: func(value []byte) {
				clear(value[offsets.destinationGateGasLimit : offsets.destinationGateGasLimit+8])
			},
		},
		{
			name: "zero success receipt budget",
			mutate: func(value []byte) {
				clear(value[offsets.successReceiptGasLimit : offsets.successReceiptGasLimit+8])
			},
		},
		{
			name: "zero refund generation budget",
			mutate: func(value []byte) {
				clear(value[offsets.refundGenerationGasLimit : offsets.refundGenerationGasLimit+8])
			},
		},
		{
			name: "zero source completion budget",
			mutate: func(value []byte) {
				clear(value[offsets.sourceCompletionGasLimit : offsets.sourceCompletionGasLimit+8])
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			mutated := append([]byte(nil), encoded...)
			test.mutate(mutated)
			_, err := DecodeValueEnvelope(mutated)
			require.ErrorIs(t, err, ErrInvalidValueEnvelope)
		})
	}
}

type valueEnvelopeOffsets struct {
	effectKind               int
	tokenType                int
	quantity                 int
	transferMode             int
	settlementExpiry         int
	destinationGateGasLimit  int
	successReceiptGasLimit   int
	refundGenerationGasLimit int
	sourceCompletionGasLimit int
}

func valueEnvelopeFixtureOffsets(fixture ValueEnvelope) valueEnvelopeOffsets {
	contextStart := 1 + 4 + len(fixture.OriginalTransferPayload)
	effectKind := contextStart + prototypeDigestLength
	tokenType := effectKind + 1 + prototypeDigestLength + 2 + len(fixture.Context.RegulatedTokenID)
	quantity := tokenType + 1 + 2
	transferMode := quantity + len(fixture.Context.Quantity) + 2*prototypeAddressLength + 4
	settlementExpiry := transferMode + 1
	destinationGateGasLimit := settlementExpiry + 8 + prototypeDigestLength

	return valueEnvelopeOffsets{
		effectKind:               effectKind,
		tokenType:                tokenType,
		quantity:                 quantity,
		transferMode:             transferMode,
		settlementExpiry:         settlementExpiry,
		destinationGateGasLimit:  destinationGateGasLimit,
		successReceiptGasLimit:   destinationGateGasLimit + 8,
		refundGenerationGasLimit: destinationGateGasLimit + 16,
		sourceCompletionGasLimit: destinationGateGasLimit + 24,
	}
}

func createValueEnvelopeFixture() ValueEnvelope {
	context := ValueContext{
		EffectKind:               ValueEffectKindDirectTransfer,
		RegulatedTokenID:         []byte("TOKEN-abcdef"),
		RegulatedTokenType:       TokenTypeFungible,
		Quantity:                 []byte{1, 0},
		CEBEpoch:                 7,
		TransferMode:             TransferModeGatedDirect,
		SettlementExpiry:         1_234_567_890,
		DestinationGateGasLimit:  100,
		SuccessReceiptGasLimit:   200,
		RefundGenerationGasLimit: 300,
		SourceCompletionGasLimit: 400,
	}
	for index := range context.EffectID {
		context.EffectID[index] = byte(index + 1)
		context.OriginExecutionIdentity[index] = byte(index + 33)
		context.SourceHolder[index] = byte(index + 65)
		context.DestinationHolder[index] = byte(index + 97)
		context.GasScheduleIdentity[index] = byte(index + 129)
	}

	return ValueEnvelope{
		OriginalTransferPayload: []byte("ESDTTransfer@544f4b454e2d616263646566@0100"),
		Context:                 context,
	}
}
