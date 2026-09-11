package drwa

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMixedBatchBindingCanonicalOrderedFixture(t *testing.T) {
	t.Parallel()

	legs := mixedBatchFixture()
	binding, err := BuildMixedBatchBinding(legs)
	require.NoError(t, err)
	require.Equal(t, []byte("RWA-123456"), binding.RegulatedTokenID)
	require.Equal(t,
		"f9501b10c6f538f5fa77bc6170a8740e082fcb69ef0694d6bf40708db23a6860",
		hex.EncodeToString(binding.FullBatchLegsDigest[:]),
	)
	require.Equal(t, legs, binding.Legs)
	require.NoError(t, ValidateMixedBatchBinding(*binding))

	legs[0].TokenID[0] = 'X'
	legs[1].Quantity[0] = 0xff
	require.Equal(t, []byte("USDC-abcdef"), binding.Legs[0].TokenID)
	require.Equal(t, []byte{5}, binding.Legs[1].Quantity)
}

func TestMixedBatchBindingDigestCommitsEveryLegAndItsOrder(t *testing.T) {
	t.Parallel()

	original := mixedBatchFixture()
	expected, err := BuildMixedBatchBinding(original)
	require.NoError(t, err)

	mutations := map[string]func([]MixedBatchLeg){
		"reorder": func(legs []MixedBatchLeg) {
			legs[0], legs[1] = legs[1], legs[0]
		},
		"ordinary token": func(legs []MixedBatchLeg) {
			legs[0].TokenID = []byte("USDT-abcdef")
		},
		"nonce": func(legs []MixedBatchLeg) {
			legs[1].Nonce++
		},
		"quantity": func(legs []MixedBatchLeg) {
			legs[3].Quantity = []byte{2}
		},
		"native position": func(legs []MixedBatchLeg) {
			legs[2], legs[3] = legs[3], legs[2]
		},
	}
	for name, mutate := range mutations {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			legs := cloneMixedBatchLegs(original)
			mutate(legs)
			actual, buildErr := BuildMixedBatchBinding(legs)
			require.NoError(t, buildErr)
			require.NotEqual(t, expected.FullBatchLegsDigest, actual.FullBatchLegsDigest)
		})
	}
}

func TestMixedBatchBindingEnforcesOneRegulatedIdentifierAcrossNonces(t *testing.T) {
	t.Parallel()

	accepted, err := BuildMixedBatchBinding([]MixedBatchLeg{
		{Kind: MixedBatchLegKindESDT, TokenID: []byte("RWA-123456"), Nonce: 1, Quantity: []byte{2}, Regulated: true},
		{Kind: MixedBatchLegKindESDT, TokenID: []byte("ORD-abcdef"), Quantity: []byte{3}},
		{Kind: MixedBatchLegKindESDT, TokenID: []byte("RWA-123456"), Nonce: 9, Quantity: []byte{4}, Regulated: true},
	})
	require.NoError(t, err)
	require.Equal(t, []byte("RWA-123456"), accepted.RegulatedTokenID)

	_, err = BuildMixedBatchBinding([]MixedBatchLeg{
		{Kind: MixedBatchLegKindESDT, TokenID: []byte("RWA-123456"), Quantity: []byte{1}, Regulated: true},
		{Kind: MixedBatchLegKindESDT, TokenID: []byte("RWA-654321"), Quantity: []byte{1}, Regulated: true},
	})
	require.ErrorIs(t, err, ErrMultipleRegulatedTokenIdentifiers)

	_, err = BuildMixedBatchBinding([]MixedBatchLeg{
		{Kind: MixedBatchLegKindESDT, TokenID: []byte("RWA-123456"), Nonce: 1, Quantity: []byte{2}, Regulated: true},
		{Kind: MixedBatchLegKindESDT, TokenID: []byte("RWA-123456"), Nonce: 9, Quantity: []byte{4}},
	})
	require.ErrorIs(t, err, ErrInvalidMixedBatch)
}

func TestMixedBatchBindingRejectsMalformedOrUnclassifiedVectors(t *testing.T) {
	t.Parallel()

	validRegulated := MixedBatchLeg{
		Kind: MixedBatchLegKindESDT, TokenID: []byte("RWA-123456"), Quantity: []byte{1}, Regulated: true,
	}
	tests := map[string][]MixedBatchLeg{
		"empty":                   nil,
		"no regulated token":      {{Kind: MixedBatchLegKindESDT, TokenID: []byte("ORD-abcdef"), Quantity: []byte{1}}},
		"invalid token":           {{Kind: MixedBatchLegKindESDT, TokenID: []byte("invalid"), Quantity: []byte{1}, Regulated: true}},
		"EGLD typed as ESDT":      {{Kind: MixedBatchLegKindESDT, TokenID: []byte("EGLD-000000"), Quantity: []byte{1}, Regulated: true}},
		"zero quantity":           {{Kind: MixedBatchLegKindESDT, TokenID: []byte("RWA-123456"), Regulated: true}},
		"non-minimal quantity":    {{Kind: MixedBatchLegKindESDT, TokenID: []byte("RWA-123456"), Quantity: []byte{0, 1}, Regulated: true}},
		"unknown kind":            {{Kind: 99, TokenID: []byte("RWA-123456"), Quantity: []byte{1}, Regulated: true}},
		"native token identifier": {validRegulated, {Kind: MixedBatchLegKindNativeEGLD, TokenID: []byte("EGLD-000000"), Quantity: []byte{1}}},
		"native nonce":            {validRegulated, {Kind: MixedBatchLegKindNativeEGLD, Nonce: 1, Quantity: []byte{1}}},
		"regulated native":        {validRegulated, {Kind: MixedBatchLegKindNativeEGLD, Quantity: []byte{1}, Regulated: true}},
	}
	for name, legs := range tests {
		legs := legs
		t.Run(name, func(t *testing.T) {
			_, err := BuildMixedBatchBinding(legs)
			require.Error(t, err)
		})
	}
}

func TestMixedBatchTerminalOutcomeBindsSettledAndFullRefundToExactBatch(t *testing.T) {
	t.Parallel()

	binding, err := BuildMixedBatchBinding(mixedBatchFixture())
	require.NoError(t, err)
	baseIntent := MixedBatchOutcomeIntent{
		EffectID:                     sequentialDRWADigest(1),
		ContextHash:                  sequentialDRWADigest(33),
		DestinationExecutionIdentity: sequentialDRWADigest(65),
	}

	settledIntent := baseIntent
	settledIntent.Kind = MixedBatchOutcomeSettled
	settled, err := BuildMixedBatchTerminalOutcome(*binding, settledIntent)
	require.NoError(t, err)
	require.Equal(t, binding.FullBatchLegsDigest, settled.FullBatchLegsDigest)
	require.NoError(t, ValidateMixedBatchTerminalOutcome(*binding, *settled))

	refundPayload := []byte("MultiESDTNFTTransfer@full-original-payload")
	refundIntent := baseIntent
	refundIntent.Kind = MixedBatchOutcomeRefunded
	refundIntent.OriginalTransferPayload = refundPayload
	refundIntent.RefundTo = sequentialDRWAAddress(97)
	refund, err := BuildMixedBatchTerminalOutcome(*binding, refundIntent)
	require.NoError(t, err)
	require.Equal(t, binding.FullBatchLegsDigest, refund.FullBatchLegsDigest)
	require.Equal(t, refundPayload, refund.OriginalTransferPayload)
	require.NoError(t, ValidateMixedBatchTerminalOutcome(*binding, *refund))

	refundPayload[0] = 'X'
	require.Equal(t, byte('M'), refund.OriginalTransferPayload[0])

	partialBinding, err := BuildMixedBatchBinding(mixedBatchFixture()[1:])
	require.NoError(t, err)
	require.ErrorIs(t, ValidateMixedBatchTerminalOutcome(*partialBinding, *refund), ErrInvalidMixedBatchOutcome)

	mutated := *refund
	mutated.FullBatchLegsDigest[0] ^= 0xff
	require.ErrorIs(t, ValidateMixedBatchTerminalOutcome(*binding, mutated), ErrInvalidMixedBatchOutcome)
}

func TestMixedBatchTerminalOutcomeRejectsInvalidTerminalShapes(t *testing.T) {
	t.Parallel()

	binding, err := BuildMixedBatchBinding(mixedBatchFixture())
	require.NoError(t, err)
	valid := MixedBatchOutcomeIntent{
		Kind:                         MixedBatchOutcomeRefunded,
		EffectID:                     sequentialDRWADigest(1),
		ContextHash:                  sequentialDRWADigest(33),
		DestinationExecutionIdentity: sequentialDRWADigest(65),
		OriginalTransferPayload:      []byte("payload"),
		RefundTo:                     sequentialDRWAAddress(97),
	}
	tests := map[string]func(*MixedBatchOutcomeIntent){
		"unknown kind":                func(intent *MixedBatchOutcomeIntent) { intent.Kind = 99 },
		"zero effect":                 func(intent *MixedBatchOutcomeIntent) { intent.EffectID = [drwaDigestLength]byte{} },
		"refund missing payload":      func(intent *MixedBatchOutcomeIntent) { intent.OriginalTransferPayload = nil },
		"refund missing recipient":    func(intent *MixedBatchOutcomeIntent) { intent.RefundTo = [drwaAddressLength]byte{} },
		"settled with refund payload": func(intent *MixedBatchOutcomeIntent) { intent.Kind = MixedBatchOutcomeSettled },
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			intent := valid
			mutate(&intent)
			_, err := BuildMixedBatchTerminalOutcome(*binding, intent)
			require.ErrorIs(t, err, ErrInvalidMixedBatchOutcome)
		})
	}
}

func mixedBatchFixture() []MixedBatchLeg {
	return []MixedBatchLeg{
		{Kind: MixedBatchLegKindESDT, TokenID: []byte("USDC-abcdef"), Quantity: []byte{100}},
		{Kind: MixedBatchLegKindESDT, TokenID: []byte("RWA-123456"), Nonce: 7, Quantity: []byte{5}, Regulated: true},
		{Kind: MixedBatchLegKindNativeEGLD, Quantity: []byte{2}},
		{Kind: MixedBatchLegKindESDT, TokenID: []byte("RWA-123456"), Nonce: 8, Quantity: []byte{1}, Regulated: true},
	}
}

func cloneMixedBatchLegs(legs []MixedBatchLeg) []MixedBatchLeg {
	cloned := make([]MixedBatchLeg, len(legs))
	for index, leg := range legs {
		cloned[index] = leg
		cloned[index].TokenID = append([]byte(nil), leg.TokenID...)
		cloned[index].Quantity = append([]byte(nil), leg.Quantity...)
	}
	return cloned
}

func sequentialDRWAAddress(first byte) [drwaAddressLength]byte {
	var address [drwaAddressLength]byte
	for index := range address {
		address[index] = first + byte(index)
	}
	return address
}
