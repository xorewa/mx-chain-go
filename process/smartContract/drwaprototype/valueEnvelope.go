package drwaprototype

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B
//
// Every type, value and limit in this file exists only for the S1 semantic prototype. None is a
// production wire-format, discriminator or numeric-bound commitment.

const (
	prototypeEnvelopeVersion = byte(1)

	prototypeDigestLength  = 32
	prototypeAddressLength = 32

	prototypePayloadLimit  = 4096
	prototypeTokenIDLimit  = 64
	prototypeQuantityLimit = 32
)

// ErrInvalidValueEnvelope signals a malformed or unsupported S1 prototype value envelope.
var ErrInvalidValueEnvelope = errors.New("invalid non-normative DRWA prototype value envelope")

// ValueEffectKind identifies the semantic value-effect kind exercised by the S1 prototype.
type ValueEffectKind byte

const (
	// ValueEffectKindDirectTransfer is the only effect kind supported by this S1 slice.
	ValueEffectKindDirectTransfer ValueEffectKind = 1
)

// TokenType identifies the token family exercised by the S1 prototype.
type TokenType byte

const (
	// TokenTypeFungible is the only token family supported by this S1 slice.
	TokenTypeFungible TokenType = 1
)

// TransferMode identifies the transfer mode exercised by the S1 prototype.
type TransferMode byte

const (
	// TransferModeGatedDirect is the only transfer mode supported by this S1 slice.
	TransferModeGatedDirect TransferMode = 1
)

// ValueContext contains the semantic fields needed by the first S1 direct-fungible exercise.
type ValueContext struct {
	EffectID                 [prototypeDigestLength]byte
	EffectKind               ValueEffectKind
	OriginExecutionIdentity  [prototypeDigestLength]byte
	RegulatedTokenID         []byte
	RegulatedTokenType       TokenType
	Quantity                 []byte
	SourceHolder             [prototypeAddressLength]byte
	DestinationHolder        [prototypeAddressLength]byte
	CEBEpoch                 uint32
	TransferMode             TransferMode
	SettlementExpiry         uint64
	GasScheduleIdentity      [prototypeDigestLength]byte
	DestinationGateGasLimit  uint64
	SuccessReceiptGasLimit   uint64
	RefundGenerationGasLimit uint64
	SourceCompletionGasLimit uint64
}

// ValueEnvelope carries one baseline transfer payload and its S1 prototype semantic context.
type ValueEnvelope struct {
	OriginalTransferPayload []byte
	Context                 ValueContext
}

// PrototypeValueEnvelopeMaximumLength returns the replaceable S1 test-only envelope byte limit.
func PrototypeValueEnvelopeMaximumLength() int {
	return prototypeEnvelopeMaximumLength()
}

// EncodeValueContext returns deterministic S1 prototype bytes for the supplied context.
func EncodeValueContext(context ValueContext) ([]byte, error) {
	err := validateValueContext(context)
	if err != nil {
		return nil, err
	}

	encoded := make([]byte, 0, prototypeContextMaximumLength())
	encoded = append(encoded, context.EffectID[:]...)
	encoded = append(encoded, byte(context.EffectKind))
	encoded = append(encoded, context.OriginExecutionIdentity[:]...)
	encoded = appendUint16Bytes(encoded, context.RegulatedTokenID)
	encoded = append(encoded, byte(context.RegulatedTokenType))
	encoded = appendUint16Bytes(encoded, context.Quantity)
	encoded = append(encoded, context.SourceHolder[:]...)
	encoded = append(encoded, context.DestinationHolder[:]...)
	encoded = binary.BigEndian.AppendUint32(encoded, context.CEBEpoch)
	encoded = append(encoded, byte(context.TransferMode))
	encoded = binary.BigEndian.AppendUint64(encoded, context.SettlementExpiry)
	encoded = append(encoded, context.GasScheduleIdentity[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, context.DestinationGateGasLimit)
	encoded = binary.BigEndian.AppendUint64(encoded, context.SuccessReceiptGasLimit)
	encoded = binary.BigEndian.AppendUint64(encoded, context.RefundGenerationGasLimit)
	encoded = binary.BigEndian.AppendUint64(encoded, context.SourceCompletionGasLimit)

	return encoded, nil
}

// EncodeValueEnvelope returns deterministic S1 prototype bytes for the supplied envelope.
func EncodeValueEnvelope(envelope ValueEnvelope) ([]byte, error) {
	if len(envelope.OriginalTransferPayload) == 0 || len(envelope.OriginalTransferPayload) > prototypePayloadLimit {
		return nil, fmt.Errorf("%w: original transfer payload length", ErrInvalidValueEnvelope)
	}

	contextBytes, err := EncodeValueContext(envelope.Context)
	if err != nil {
		return nil, err
	}

	encoded := make([]byte, 0, 1+4+len(envelope.OriginalTransferPayload)+len(contextBytes))
	encoded = append(encoded, prototypeEnvelopeVersion)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(envelope.OriginalTransferPayload)))
	encoded = append(encoded, envelope.OriginalTransferPayload...)
	encoded = append(encoded, contextBytes...)

	return encoded, nil
}

// DecodeValueEnvelope decodes and validates deterministic S1 prototype bytes.
func DecodeValueEnvelope(encoded []byte) (*ValueEnvelope, error) {
	if len(encoded) == 0 || len(encoded) > prototypeEnvelopeMaximumLength() {
		return nil, fmt.Errorf("%w: total length", ErrInvalidValueEnvelope)
	}

	reader := prototypeReader{data: encoded}
	version, err := reader.readByte()
	if err != nil || version != prototypeEnvelopeVersion {
		return nil, fmt.Errorf("%w: envelope version", ErrInvalidValueEnvelope)
	}

	payload, err := reader.readUint32Bytes(prototypePayloadLimit)
	if err != nil || len(payload) == 0 {
		return nil, fmt.Errorf("%w: original transfer payload", ErrInvalidValueEnvelope)
	}

	context, err := reader.readValueContext()
	if err != nil {
		return nil, err
	}
	if reader.remaining() != 0 {
		return nil, fmt.Errorf("%w: trailing bytes", ErrInvalidValueEnvelope)
	}

	envelope := &ValueEnvelope{
		OriginalTransferPayload: payload,
		Context:                 context,
	}
	reencoded, err := EncodeValueEnvelope(*envelope)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(encoded, reencoded) {
		return nil, fmt.Errorf("%w: alternate encoding", ErrInvalidValueEnvelope)
	}

	return envelope, nil
}

func validateValueContext(context ValueContext) error {
	if context.EffectKind != ValueEffectKindDirectTransfer {
		return fmt.Errorf("%w: unsupported effect kind", ErrInvalidValueEnvelope)
	}
	if len(context.RegulatedTokenID) == 0 || len(context.RegulatedTokenID) > prototypeTokenIDLimit {
		return fmt.Errorf("%w: regulated token identifier length", ErrInvalidValueEnvelope)
	}
	if context.RegulatedTokenType != TokenTypeFungible {
		return fmt.Errorf("%w: unsupported token type", ErrInvalidValueEnvelope)
	}
	if len(context.Quantity) == 0 || len(context.Quantity) > prototypeQuantityLimit || context.Quantity[0] == 0 {
		return fmt.Errorf("%w: quantity encoding", ErrInvalidValueEnvelope)
	}
	if context.TransferMode != TransferModeGatedDirect {
		return fmt.Errorf("%w: unsupported transfer mode", ErrInvalidValueEnvelope)
	}
	if context.SettlementExpiry == 0 {
		return fmt.Errorf("%w: zero settlement expiry", ErrInvalidValueEnvelope)
	}
	if context.DestinationGateGasLimit == 0 ||
		context.SuccessReceiptGasLimit == 0 ||
		context.RefundGenerationGasLimit == 0 ||
		context.SourceCompletionGasLimit == 0 {
		return fmt.Errorf("%w: zero work budget", ErrInvalidValueEnvelope)
	}

	return nil
}

func appendUint16Bytes(destination []byte, value []byte) []byte {
	destination = binary.BigEndian.AppendUint16(destination, uint16(len(value)))
	return append(destination, value...)
}

func prototypeContextMaximumLength() int {
	return prototypeDigestLength + 1 + prototypeDigestLength +
		2 + prototypeTokenIDLimit + 1 + 2 + prototypeQuantityLimit +
		2*prototypeAddressLength + 4 + 1 + 8 + prototypeDigestLength + 4*8
}

func prototypeEnvelopeMaximumLength() int {
	return 1 + 4 + prototypePayloadLimit + prototypeContextMaximumLength()
}

type prototypeReader struct {
	data   []byte
	offset int
}

func (reader *prototypeReader) readValueContext() (ValueContext, error) {
	context := ValueContext{}

	err := reader.readFixed(context.EffectID[:])
	if err != nil {
		return ValueContext{}, err
	}
	effectKind, err := reader.readByte()
	if err != nil {
		return ValueContext{}, err
	}
	context.EffectKind = ValueEffectKind(effectKind)
	err = reader.readFixed(context.OriginExecutionIdentity[:])
	if err != nil {
		return ValueContext{}, err
	}
	context.RegulatedTokenID, err = reader.readUint16Bytes(prototypeTokenIDLimit)
	if err != nil {
		return ValueContext{}, err
	}
	tokenType, err := reader.readByte()
	if err != nil {
		return ValueContext{}, err
	}
	context.RegulatedTokenType = TokenType(tokenType)
	context.Quantity, err = reader.readUint16Bytes(prototypeQuantityLimit)
	if err != nil {
		return ValueContext{}, err
	}
	err = reader.readFixed(context.SourceHolder[:])
	if err != nil {
		return ValueContext{}, err
	}
	err = reader.readFixed(context.DestinationHolder[:])
	if err != nil {
		return ValueContext{}, err
	}
	context.CEBEpoch, err = reader.readUint32()
	if err != nil {
		return ValueContext{}, err
	}
	transferMode, err := reader.readByte()
	if err != nil {
		return ValueContext{}, err
	}
	context.TransferMode = TransferMode(transferMode)
	context.SettlementExpiry, err = reader.readUint64()
	if err != nil {
		return ValueContext{}, err
	}
	err = reader.readFixed(context.GasScheduleIdentity[:])
	if err != nil {
		return ValueContext{}, err
	}
	context.DestinationGateGasLimit, err = reader.readUint64()
	if err != nil {
		return ValueContext{}, err
	}
	context.SuccessReceiptGasLimit, err = reader.readUint64()
	if err != nil {
		return ValueContext{}, err
	}
	context.RefundGenerationGasLimit, err = reader.readUint64()
	if err != nil {
		return ValueContext{}, err
	}
	context.SourceCompletionGasLimit, err = reader.readUint64()
	if err != nil {
		return ValueContext{}, err
	}

	err = validateValueContext(context)
	if err != nil {
		return ValueContext{}, err
	}

	return context, nil
}

func (reader *prototypeReader) readByte() (byte, error) {
	if reader.remaining() < 1 {
		return 0, fmt.Errorf("%w: truncated byte", ErrInvalidValueEnvelope)
	}
	value := reader.data[reader.offset]
	reader.offset++
	return value, nil
}

func (reader *prototypeReader) readUint16Bytes(maximum int) ([]byte, error) {
	if reader.remaining() < 2 {
		return nil, fmt.Errorf("%w: truncated uint16 length", ErrInvalidValueEnvelope)
	}
	length := int(binary.BigEndian.Uint16(reader.data[reader.offset:]))
	reader.offset += 2
	return reader.readCopiedBytes(length, maximum)
}

func (reader *prototypeReader) readUint32Bytes(maximum int) ([]byte, error) {
	if reader.remaining() < 4 {
		return nil, fmt.Errorf("%w: truncated uint32 length", ErrInvalidValueEnvelope)
	}
	length := binary.BigEndian.Uint32(reader.data[reader.offset:])
	reader.offset += 4
	if length > uint32(maximum) {
		return nil, fmt.Errorf("%w: variable field limit", ErrInvalidValueEnvelope)
	}
	return reader.readCopiedBytes(int(length), maximum)
}

func (reader *prototypeReader) readCopiedBytes(length int, maximum int) ([]byte, error) {
	if length < 0 || length > maximum || reader.remaining() < length {
		return nil, fmt.Errorf("%w: variable field length", ErrInvalidValueEnvelope)
	}
	value := make([]byte, length)
	copy(value, reader.data[reader.offset:reader.offset+length])
	reader.offset += length
	return value, nil
}

func (reader *prototypeReader) readFixed(destination []byte) error {
	if reader.remaining() < len(destination) {
		return fmt.Errorf("%w: truncated fixed field", ErrInvalidValueEnvelope)
	}
	copy(destination, reader.data[reader.offset:reader.offset+len(destination)])
	reader.offset += len(destination)
	return nil
}

func (reader *prototypeReader) readUint32() (uint32, error) {
	if reader.remaining() < 4 {
		return 0, fmt.Errorf("%w: truncated uint32", ErrInvalidValueEnvelope)
	}
	value := binary.BigEndian.Uint32(reader.data[reader.offset:])
	reader.offset += 4
	return value, nil
}

func (reader *prototypeReader) readUint64() (uint64, error) {
	if reader.remaining() < 8 {
		return 0, fmt.Errorf("%w: truncated uint64", ErrInvalidValueEnvelope)
	}
	value := binary.BigEndian.Uint64(reader.data[reader.offset:])
	reader.offset += 8
	return value, nil
}

func (reader *prototypeReader) remaining() int {
	return len(reader.data) - reader.offset
}
