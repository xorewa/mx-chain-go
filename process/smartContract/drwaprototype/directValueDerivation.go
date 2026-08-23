package drwaprototype

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B
//
// The hash function, normalization grammar, integer widths and single-effect restriction in this
// file exist only for the S1 semantic prototype. They are not production protocol commitments.

const (
	prototypeNormalizedDirectVersion = byte(1)
	prototypeDirectOriginEffectIndex = uint32(0)

	prototypeNormalizedDirectDomain = "DRWA/PROTOTYPE/NORMALIZED_DIRECT/v1"
	prototypeDirectEffectDomain     = "DRWA/EFFECT/DIRECT/v1"
	prototypeValueContextDomain     = "DRWA/VALUE_CONTEXT/v1"
)

// ErrInvalidDirectValueIntent signals an invalid S1 prototype direct-value intent.
var ErrInvalidDirectValueIntent = errors.New("invalid non-normative DRWA prototype direct-value intent")

// DirectValueIntent is the caller-independent input to the pure S1 direct-value derivation.
type DirectValueIntent struct {
	RegulatedTokenID         []byte
	Quantity                 []byte
	SourceHolder             [prototypeAddressLength]byte
	DestinationHolder        [prototypeAddressLength]byte
	CEBEpoch                 uint32
	SettlementExpiry         uint64
	GasScheduleIdentity      [prototypeDigestLength]byte
	DestinationGateGasLimit  uint64
	SuccessReceiptGasLimit   uint64
	RefundGenerationGasLimit uint64
	SourceCompletionGasLimit uint64
}

// DirectValueArtifacts are the mutually bound pure values derived for one S1 direct effect.
type DirectValueArtifacts struct {
	NormalizedEffectDigest [prototypeDigestLength]byte
	ContextHash            [prototypeDigestLength]byte
	Envelope               ValueEnvelope
	OpenEffect             OpenEffect
}

// BuildDirectValueArtifacts deterministically derives one replaceable S1 direct-value prototype.
// It performs no account read, account mutation, gas reservation or message emission.
func BuildDirectValueArtifacts(
	networkDomain [prototypeDigestLength]byte,
	originTxHash [prototypeDigestLength]byte,
	intent DirectValueIntent,
) (*DirectValueArtifacts, error) {
	err := validateDirectValueIntent(networkDomain, originTxHash, intent)
	if err != nil {
		return nil, err
	}

	intent.RegulatedTokenID = append([]byte(nil), intent.RegulatedTokenID...)
	intent.Quantity = append([]byte(nil), intent.Quantity...)
	transferPayload := buildPrototypeESDTTransferPayload(intent.RegulatedTokenID, intent.Quantity)
	normalizedBytes := encodePrototypeNormalizedDirectIntent(intent, transferPayload)
	normalizedDigest := sha256.Sum256(appendDomain(prototypeNormalizedDirectDomain, normalizedBytes))

	effectPreimage := make([]byte, 0, len(prototypeDirectEffectDomain)+3*prototypeDigestLength+8)
	effectPreimage = append(effectPreimage, prototypeDirectEffectDomain...)
	effectPreimage = append(effectPreimage, networkDomain[:]...)
	effectPreimage = append(effectPreimage, originTxHash[:]...)
	effectPreimage = binary.BigEndian.AppendUint32(effectPreimage, prototypeDirectOriginEffectIndex)
	effectPreimage = append(effectPreimage, normalizedDigest[:]...)
	effectPreimage = binary.BigEndian.AppendUint32(effectPreimage, intent.CEBEpoch)
	effectID := sha256.Sum256(effectPreimage)

	context := ValueContext{
		EffectID:                 effectID,
		EffectKind:               ValueEffectKindDirectTransfer,
		OriginExecutionIdentity:  originTxHash,
		RegulatedTokenID:         append([]byte(nil), intent.RegulatedTokenID...),
		RegulatedTokenType:       TokenTypeFungible,
		Quantity:                 append([]byte(nil), intent.Quantity...),
		SourceHolder:             intent.SourceHolder,
		DestinationHolder:        intent.DestinationHolder,
		CEBEpoch:                 intent.CEBEpoch,
		TransferMode:             TransferModeGatedDirect,
		SettlementExpiry:         intent.SettlementExpiry,
		GasScheduleIdentity:      intent.GasScheduleIdentity,
		DestinationGateGasLimit:  intent.DestinationGateGasLimit,
		SuccessReceiptGasLimit:   intent.SuccessReceiptGasLimit,
		RefundGenerationGasLimit: intent.RefundGenerationGasLimit,
		SourceCompletionGasLimit: intent.SourceCompletionGasLimit,
	}
	contextBytes, err := EncodeValueContext(context)
	if err != nil {
		return nil, fmt.Errorf("encode prototype direct-value context: %w", err)
	}
	contextPreimage := make([]byte, 0, len(prototypeValueContextDomain)+prototypeDigestLength+len(contextBytes))
	contextPreimage = append(contextPreimage, prototypeValueContextDomain...)
	contextPreimage = append(contextPreimage, networkDomain[:]...)
	contextPreimage = append(contextPreimage, contextBytes...)
	contextHash := sha256.Sum256(contextPreimage)

	envelope := ValueEnvelope{
		OriginalTransferPayload: transferPayload,
		Context:                 context,
	}
	openEffect := OpenEffect{
		EffectID:                effectID,
		EffectKind:              ValueEffectKindDirectTransfer,
		RegulatedTokenID:        append([]byte(nil), intent.RegulatedTokenID...),
		RegulatedTokenType:      TokenTypeFungible,
		OriginExecutionIdentity: originTxHash,
		SourceSubject:           intent.SourceHolder,
		CEBEpoch:                intent.CEBEpoch,
		ContextHash:             contextHash,
		TerminalKind:            OpenEffectTerminalKindValueResult,
		State:                   OpenEffectStatePendingDestination,
	}

	return &DirectValueArtifacts{
		NormalizedEffectDigest: normalizedDigest,
		ContextHash:            contextHash,
		Envelope:               envelope,
		OpenEffect:             openEffect,
	}, nil
}

func validateDirectValueIntent(
	networkDomain [prototypeDigestLength]byte,
	originTxHash [prototypeDigestLength]byte,
	intent DirectValueIntent,
) error {
	if isZeroPrototypeDigest(networkDomain) {
		return fmt.Errorf("%w: zero network domain", ErrInvalidDirectValueIntent)
	}
	if isZeroPrototypeDigest(originTxHash) {
		return fmt.Errorf("%w: zero origin transaction hash", ErrInvalidDirectValueIntent)
	}
	if !vmcommon.ValidateToken(intent.RegulatedTokenID) || len(intent.RegulatedTokenID) > prototypeTokenIDLimit {
		return fmt.Errorf("%w: regulated token identifier", ErrInvalidDirectValueIntent)
	}
	if len(intent.Quantity) == 0 || len(intent.Quantity) > prototypeQuantityLimit || intent.Quantity[0] == 0 {
		return fmt.Errorf("%w: quantity encoding", ErrInvalidDirectValueIntent)
	}
	if intent.SettlementExpiry == 0 {
		return fmt.Errorf("%w: zero settlement expiry", ErrInvalidDirectValueIntent)
	}
	if isZeroPrototypeDigest(intent.GasScheduleIdentity) {
		return fmt.Errorf("%w: zero gas-schedule identity", ErrInvalidDirectValueIntent)
	}
	if intent.DestinationGateGasLimit == 0 ||
		intent.SuccessReceiptGasLimit == 0 ||
		intent.RefundGenerationGasLimit == 0 ||
		intent.SourceCompletionGasLimit == 0 {
		return fmt.Errorf("%w: zero work budget", ErrInvalidDirectValueIntent)
	}

	return nil
}

func encodePrototypeNormalizedDirectIntent(intent DirectValueIntent, transferPayload []byte) []byte {
	encoded := make([]byte, 0, prototypeContextMaximumLength()+len(transferPayload))
	encoded = append(encoded, prototypeNormalizedDirectVersion)
	encoded = append(encoded, byte(ValueEffectKindDirectTransfer))
	encoded = appendUint16Bytes(encoded, intent.RegulatedTokenID)
	encoded = append(encoded, byte(TokenTypeFungible))
	encoded = appendUint16Bytes(encoded, intent.Quantity)
	encoded = append(encoded, intent.SourceHolder[:]...)
	encoded = append(encoded, intent.DestinationHolder[:]...)
	encoded = binary.BigEndian.AppendUint32(encoded, intent.CEBEpoch)
	encoded = append(encoded, byte(TransferModeGatedDirect))
	encoded = binary.BigEndian.AppendUint64(encoded, intent.SettlementExpiry)
	encoded = append(encoded, intent.GasScheduleIdentity[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, intent.DestinationGateGasLimit)
	encoded = binary.BigEndian.AppendUint64(encoded, intent.SuccessReceiptGasLimit)
	encoded = binary.BigEndian.AppendUint64(encoded, intent.RefundGenerationGasLimit)
	encoded = binary.BigEndian.AppendUint64(encoded, intent.SourceCompletionGasLimit)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(transferPayload)))
	return append(encoded, transferPayload...)
}

func buildPrototypeESDTTransferPayload(tokenID []byte, quantity []byte) []byte {
	functionName := []byte(core.BuiltInFunctionESDTTransfer)
	encodedLength := len(functionName) + 2 + hex.EncodedLen(len(tokenID)) + hex.EncodedLen(len(quantity))
	payload := make([]byte, encodedLength)
	offset := copy(payload, functionName)
	payload[offset] = '@'
	offset++
	hex.Encode(payload[offset:], tokenID)
	offset += hex.EncodedLen(len(tokenID))
	payload[offset] = '@'
	offset++
	hex.Encode(payload[offset:], quantity)

	return payload
}

func appendDomain(domain string, value []byte) []byte {
	result := make([]byte, 0, len(domain)+len(value))
	result = append(result, domain...)
	return append(result, value...)
}

func isZeroPrototypeDigest(value [prototypeDigestLength]byte) bool {
	return value == [prototypeDigestLength]byte{}
}
