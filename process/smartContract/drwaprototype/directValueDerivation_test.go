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

func TestBuildDirectValueArtifactsPrototypeDeterministicFixture(t *testing.T) {
	t.Parallel()

	networkDomain, originTxHash, intent := createDirectValueDerivationFixture()
	artifacts, err := BuildDirectValueArtifacts(networkDomain, originTxHash, intent)
	require.NoError(t, err)

	require.Equal(t, "9c931585107859413abd2c99142b5f65e12297ba2d96e6c3d93035aac962afef", hex.EncodeToString(artifacts.NormalizedEffectDigest[:]))
	require.Equal(t, "b4bbcc32826fc24506e0e7527a690464fdd6ca4f3958bee22973978ecbfd65a3", hex.EncodeToString(artifacts.Envelope.Context.EffectID[:]))
	require.Equal(t, "22f2f3d65b09dde3aa8acb55732c00077d082cee913dc89994be5edc8115ebbf", hex.EncodeToString(artifacts.ContextHash[:]))
	require.Equal(t, "ESDTTransfer@544f4b454e2d616263646566@0100", string(artifacts.Envelope.OriginalTransferPayload))
	normalizedBytes := encodePrototypeNormalizedDirectIntent(intent, artifacts.Envelope.OriginalTransferPayload)
	require.Equal(t, "0101000c544f4b454e2d61626364656601000201004142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80000000070100000000000004d28182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0000000000000006400000000000000c8000000000000012c00000000000001900000002a455344545472616e73666572403534346634623435346532643631363236333634363536364030313030", hex.EncodeToString(normalizedBytes))
	recomputedNormalizedDigest := sha256.Sum256(append([]byte("DRWA/PROTOTYPE/NORMALIZED_DIRECT/v1"), normalizedBytes...))
	require.Equal(t, artifacts.NormalizedEffectDigest, recomputedNormalizedDigest)

	encodedEnvelope, err := EncodeValueEnvelope(artifacts.Envelope)
	require.NoError(t, err)
	require.Equal(t, "010000002a455344545472616e73666572403534346634623435346532643631363236333634363536364030313030b4bbcc32826fc24506e0e7527a690464fdd6ca4f3958bee22973978ecbfd65a3012122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40000c544f4b454e2d61626364656601000201004142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80000000070100000000000004d28182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0000000000000006400000000000000c8000000000000012c0000000000000190", hex.EncodeToString(encodedEnvelope))

	encodedOpenEffect, err := EncodeOpenEffect(artifacts.OpenEffect)
	require.NoError(t, err)
	require.Equal(t, "02b4bbcc32826fc24506e0e7527a690464fdd6ca4f3958bee22973978ecbfd65a301000c544f4b454e2d616263646566012122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60000000078182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa022f2f3d65b09dde3aa8acb55732c00077d082cee913dc89994be5edc8115ebbf0101", hex.EncodeToString(encodedOpenEffect))

	require.Equal(t, artifacts.Envelope.Context.EffectID, artifacts.OpenEffect.EffectID)
	require.Equal(t, artifacts.Envelope.Context.OriginExecutionIdentity, artifacts.OpenEffect.OriginExecutionIdentity)
	require.Equal(t, artifacts.Envelope.Context.RegulatedTokenID, artifacts.OpenEffect.RegulatedTokenID)
	require.Equal(t, artifacts.Envelope.Context.CEBEpoch, artifacts.OpenEffect.CEBEpoch)
	require.Equal(t, artifacts.Envelope.Context.GasScheduleIdentity, artifacts.OpenEffect.GasScheduleIdentity)
	require.Equal(t, artifacts.ContextHash, artifacts.OpenEffect.ContextHash)
	require.NoError(t, ValidateDirectValueOpenEffectContext(networkDomain, artifacts.OpenEffect, artifacts.Envelope.Context))
}

func TestDecodeDirectValueTransferPayloadAcceptsOnlyCanonicalCommittedShape(t *testing.T) {
	tokenID, quantity, err := DecodeDirectValueTransferPayload(
		[]byte("ESDTTransfer@544f4b454e2d616263646566@0100"),
	)
	require.NoError(t, err)
	require.Equal(t, []byte("TOKEN-abcdef"), tokenID)
	require.Equal(t, []byte{1, 0}, quantity)

	for _, malformed := range [][]byte{
		[]byte("ESDTTransfer@544F4B454E2D616263646566@0100"),
		[]byte("ESDTTransfer@544f4b454e2d616263646566@00"),
		[]byte("ESDTNFTTransfer@544f4b454e2d616263646566@0100"),
		[]byte("ESDTTransfer@544f4b454e2d616263646566@0100@00"),
	} {
		_, _, err = DecodeDirectValueTransferPayload(malformed)
		require.ErrorIs(t, err, ErrInvalidDirectValueIntent)
	}
}

func TestValidateDirectValueOpenEffectContextPrototypeRejectsEveryBindingMismatch(t *testing.T) {
	t.Parallel()

	networkDomain, originTxHash, intent := createDirectValueDerivationFixture()
	artifacts, err := BuildDirectValueArtifacts(networkDomain, originTxHash, intent)
	require.NoError(t, err)

	tests := []struct {
		name   string
		mutate func(effect *OpenEffect, context *ValueContext, domain *[prototypeDigestLength]byte)
	}{
		{name: "network domain", mutate: func(_ *OpenEffect, _ *ValueContext, domain *[prototypeDigestLength]byte) { domain[0] ^= 0xff }},
		{name: "effect ID", mutate: func(effect *OpenEffect, _ *ValueContext, _ *[prototypeDigestLength]byte) { effect.EffectID[0] ^= 0xff }},
		{name: "origin", mutate: func(effect *OpenEffect, _ *ValueContext, _ *[prototypeDigestLength]byte) {
			effect.OriginExecutionIdentity[0] ^= 0xff
		}},
		{name: "source", mutate: func(effect *OpenEffect, _ *ValueContext, _ *[prototypeDigestLength]byte) {
			effect.SourceSubject[0] ^= 0xff
		}},
		{name: "CEB epoch", mutate: func(effect *OpenEffect, _ *ValueContext, _ *[prototypeDigestLength]byte) { effect.CEBEpoch++ }},
		{name: "gas identity", mutate: func(effect *OpenEffect, _ *ValueContext, _ *[prototypeDigestLength]byte) {
			effect.GasScheduleIdentity[0] ^= 0xff
		}},
		{name: "context gas identity", mutate: func(_ *OpenEffect, context *ValueContext, _ *[prototypeDigestLength]byte) {
			context.GasScheduleIdentity[0] ^= 0xff
		}},
		{name: "context hash", mutate: func(effect *OpenEffect, _ *ValueContext, _ *[prototypeDigestLength]byte) {
			effect.ContextHash[0] ^= 0xff
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			effect := artifacts.OpenEffect
			effect.RegulatedTokenID = append([]byte(nil), artifacts.OpenEffect.RegulatedTokenID...)
			context := artifacts.Envelope.Context
			context.RegulatedTokenID = append([]byte(nil), artifacts.Envelope.Context.RegulatedTokenID...)
			context.Quantity = append([]byte(nil), artifacts.Envelope.Context.Quantity...)
			domain := networkDomain
			test.mutate(&effect, &context, &domain)
			require.ErrorIs(t, ValidateDirectValueOpenEffectContext(domain, effect, context), ErrOpenEffectContextMismatch)
		})
	}
}

func TestBuildDirectValueArtifactsPrototypeArchitectureFormulaRecomputation(t *testing.T) {
	t.Parallel()

	networkDomain, originTxHash, intent := createDirectValueDerivationFixture()
	artifacts, err := BuildDirectValueArtifacts(networkDomain, originTxHash, intent)
	require.NoError(t, err)

	effectPreimage := []byte("DRWA/EFFECT/DIRECT/v1")
	effectPreimage = append(effectPreimage, networkDomain[:]...)
	effectPreimage = append(effectPreimage, originTxHash[:]...)
	effectPreimage = binary.BigEndian.AppendUint32(effectPreimage, 0)
	effectPreimage = append(effectPreimage, artifacts.NormalizedEffectDigest[:]...)
	effectPreimage = binary.BigEndian.AppendUint32(effectPreimage, intent.CEBEpoch)
	recomputedEffectID := sha256.Sum256(effectPreimage)
	require.Equal(t, recomputedEffectID, artifacts.Envelope.Context.EffectID)

	contextBytes, err := EncodeValueContext(artifacts.Envelope.Context)
	require.NoError(t, err)
	contextPreimage := []byte("DRWA/VALUE_CONTEXT/v1")
	contextPreimage = append(contextPreimage, networkDomain[:]...)
	contextPreimage = append(contextPreimage, contextBytes...)
	recomputedContextHash := sha256.Sum256(contextPreimage)
	require.Equal(t, recomputedContextHash, artifacts.ContextHash)
}

func TestBuildDirectValueArtifactsPrototypeRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(networkDomain *[prototypeDigestLength]byte, originTxHash *[prototypeDigestLength]byte, intent *DirectValueIntent)
	}{
		{
			name: "zero network domain",
			mutate: func(networkDomain *[prototypeDigestLength]byte, _ *[prototypeDigestLength]byte, _ *DirectValueIntent) {
				clear(networkDomain[:])
			},
		},
		{
			name: "zero origin transaction hash",
			mutate: func(_ *[prototypeDigestLength]byte, originTxHash *[prototypeDigestLength]byte, _ *DirectValueIntent) {
				clear(originTxHash[:])
			},
		},
		{
			name: "empty token identifier",
			mutate: func(_ *[prototypeDigestLength]byte, _ *[prototypeDigestLength]byte, intent *DirectValueIntent) {
				intent.RegulatedTokenID = nil
			},
		},
		{
			name: "malformed token identifier",
			mutate: func(_ *[prototypeDigestLength]byte, _ *[prototypeDigestLength]byte, intent *DirectValueIntent) {
				intent.RegulatedTokenID = []byte("not-a-token")
			},
		},
		{
			name: "empty quantity",
			mutate: func(_ *[prototypeDigestLength]byte, _ *[prototypeDigestLength]byte, intent *DirectValueIntent) {
				intent.Quantity = nil
			},
		},
		{
			name: "non-minimal quantity",
			mutate: func(_ *[prototypeDigestLength]byte, _ *[prototypeDigestLength]byte, intent *DirectValueIntent) {
				intent.Quantity = []byte{0, 1}
			},
		},
		{
			name: "quantity above limit",
			mutate: func(_ *[prototypeDigestLength]byte, _ *[prototypeDigestLength]byte, intent *DirectValueIntent) {
				intent.Quantity = make([]byte, prototypeQuantityLimit+1)
				intent.Quantity[0] = 1
			},
		},
		{
			name: "zero settlement expiry",
			mutate: func(_ *[prototypeDigestLength]byte, _ *[prototypeDigestLength]byte, intent *DirectValueIntent) {
				intent.SettlementExpiry = 0
			},
		},
		{
			name: "zero gas schedule identity",
			mutate: func(_ *[prototypeDigestLength]byte, _ *[prototypeDigestLength]byte, intent *DirectValueIntent) {
				clear(intent.GasScheduleIdentity[:])
			},
		},
		{
			name: "zero destination gate budget",
			mutate: func(_ *[prototypeDigestLength]byte, _ *[prototypeDigestLength]byte, intent *DirectValueIntent) {
				intent.DestinationGateGasLimit = 0
			},
		},
		{
			name: "zero success receipt budget",
			mutate: func(_ *[prototypeDigestLength]byte, _ *[prototypeDigestLength]byte, intent *DirectValueIntent) {
				intent.SuccessReceiptGasLimit = 0
			},
		},
		{
			name: "zero refund generation budget",
			mutate: func(_ *[prototypeDigestLength]byte, _ *[prototypeDigestLength]byte, intent *DirectValueIntent) {
				intent.RefundGenerationGasLimit = 0
			},
		},
		{
			name: "zero source completion budget",
			mutate: func(_ *[prototypeDigestLength]byte, _ *[prototypeDigestLength]byte, intent *DirectValueIntent) {
				intent.SourceCompletionGasLimit = 0
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			networkDomain, originTxHash, intent := createDirectValueDerivationFixture()
			test.mutate(&networkDomain, &originTxHash, &intent)
			artifacts, err := BuildDirectValueArtifacts(networkDomain, originTxHash, intent)
			require.Nil(t, artifacts)
			require.ErrorIs(t, err, ErrInvalidDirectValueIntent)
		})
	}
}

func TestBuildDirectValueArtifactsPrototypeNormalizedDigestCommitsEveryIntentField(t *testing.T) {
	t.Parallel()

	networkDomain, originTxHash, baseIntent := createDirectValueDerivationFixture()
	baseArtifacts, err := BuildDirectValueArtifacts(networkDomain, originTxHash, baseIntent)
	require.NoError(t, err)

	mutations := []struct {
		name   string
		mutate func(intent *DirectValueIntent)
	}{
		{name: "token", mutate: func(intent *DirectValueIntent) { intent.RegulatedTokenID = []byte("OTHER-abcdef") }},
		{name: "quantity", mutate: func(intent *DirectValueIntent) { intent.Quantity = []byte{2} }},
		{name: "source", mutate: func(intent *DirectValueIntent) { intent.SourceHolder[0] ^= 0xff }},
		{name: "destination", mutate: func(intent *DirectValueIntent) { intent.DestinationHolder[0] ^= 0xff }},
		{name: "CEB epoch", mutate: func(intent *DirectValueIntent) { intent.CEBEpoch++ }},
		{name: "expiry", mutate: func(intent *DirectValueIntent) { intent.SettlementExpiry++ }},
		{name: "gas identity", mutate: func(intent *DirectValueIntent) { intent.GasScheduleIdentity[0] ^= 0xff }},
		{name: "destination gate budget", mutate: func(intent *DirectValueIntent) { intent.DestinationGateGasLimit++ }},
		{name: "success receipt budget", mutate: func(intent *DirectValueIntent) { intent.SuccessReceiptGasLimit++ }},
		{name: "refund generation budget", mutate: func(intent *DirectValueIntent) { intent.RefundGenerationGasLimit++ }},
		{name: "source completion budget", mutate: func(intent *DirectValueIntent) { intent.SourceCompletionGasLimit++ }},
	}

	for _, mutation := range mutations {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			t.Parallel()

			intent := cloneDirectValueIntent(baseIntent)
			mutation.mutate(&intent)
			artifacts, buildErr := BuildDirectValueArtifacts(networkDomain, originTxHash, intent)
			require.NoError(t, buildErr)
			require.NotEqual(t, baseArtifacts.NormalizedEffectDigest, artifacts.NormalizedEffectDigest)
		})
	}
}

func TestBuildDirectValueArtifactsPrototypeSeparatesOriginAndNetworkBindings(t *testing.T) {
	t.Parallel()

	networkDomain, originTxHash, intent := createDirectValueDerivationFixture()
	base, err := BuildDirectValueArtifacts(networkDomain, originTxHash, intent)
	require.NoError(t, err)

	changedOrigin := originTxHash
	changedOrigin[0] ^= 0xff
	withChangedOrigin, err := BuildDirectValueArtifacts(networkDomain, changedOrigin, intent)
	require.NoError(t, err)
	require.Equal(t, base.NormalizedEffectDigest, withChangedOrigin.NormalizedEffectDigest)
	require.NotEqual(t, base.Envelope.Context.EffectID, withChangedOrigin.Envelope.Context.EffectID)
	require.NotEqual(t, base.ContextHash, withChangedOrigin.ContextHash)

	changedDomain := networkDomain
	changedDomain[0] ^= 0xff
	withChangedDomain, err := BuildDirectValueArtifacts(changedDomain, originTxHash, intent)
	require.NoError(t, err)
	require.Equal(t, base.NormalizedEffectDigest, withChangedDomain.NormalizedEffectDigest)
	require.NotEqual(t, base.Envelope.Context.EffectID, withChangedDomain.Envelope.Context.EffectID)
	require.NotEqual(t, base.ContextHash, withChangedDomain.ContextHash)
}

func TestBuildDirectValueArtifactsPrototypeDoesNotAliasInputOrOutputSlices(t *testing.T) {
	t.Parallel()

	networkDomain, originTxHash, intent := createDirectValueDerivationFixture()
	originalToken := append([]byte(nil), intent.RegulatedTokenID...)
	originalQuantity := append([]byte(nil), intent.Quantity...)
	artifacts, err := BuildDirectValueArtifacts(networkDomain, originTxHash, intent)
	require.NoError(t, err)

	intent.RegulatedTokenID[0] ^= 0xff
	intent.Quantity[0] ^= 0xff
	require.Equal(t, originalToken, artifacts.Envelope.Context.RegulatedTokenID)
	require.Equal(t, originalToken, artifacts.OpenEffect.RegulatedTokenID)
	require.Equal(t, originalQuantity, artifacts.Envelope.Context.Quantity)

	artifacts.Envelope.Context.RegulatedTokenID[0] ^= 0xff
	require.Equal(t, originalToken, artifacts.OpenEffect.RegulatedTokenID)
}

func createDirectValueDerivationFixture() ([prototypeDigestLength]byte, [prototypeDigestLength]byte, DirectValueIntent) {
	networkDomain := sequentialPrototypeDigest(1)
	originTxHash := sequentialPrototypeDigest(33)
	intent := DirectValueIntent{
		RegulatedTokenID:         []byte("TOKEN-abcdef"),
		Quantity:                 []byte{1, 0},
		SourceHolder:             sequentialPrototypeDigest(65),
		DestinationHolder:        sequentialPrototypeDigest(97),
		CEBEpoch:                 7,
		SettlementExpiry:         1234,
		GasScheduleIdentity:      sequentialPrototypeDigest(129),
		DestinationGateGasLimit:  100,
		SuccessReceiptGasLimit:   200,
		RefundGenerationGasLimit: 300,
		SourceCompletionGasLimit: 400,
	}

	return networkDomain, originTxHash, intent
}

func sequentialPrototypeDigest(first byte) [prototypeDigestLength]byte {
	result := [prototypeDigestLength]byte{}
	for index := range result {
		result[index] = first + byte(index)
	}

	return result
}

func cloneDirectValueIntent(intent DirectValueIntent) DirectValueIntent {
	intent.RegulatedTokenID = append([]byte(nil), intent.RegulatedTokenID...)
	intent.Quantity = append([]byte(nil), intent.Quantity...)
	return intent
}
