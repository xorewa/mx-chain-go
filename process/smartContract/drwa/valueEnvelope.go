package drwa

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
	drwaEnvelopeVersion = byte(1)

	drwaDigestLength  = 32
	drwaAddressLength = 32

	drwaPayloadLimit  = 4096
	drwaTokenIDLimit  = 64
	drwaQuantityLimit = 32
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
	EffectID                 [drwaDigestLength]byte
	EffectKind               ValueEffectKind
	OriginExecutionIdentity  [drwaDigestLength]byte
	RegulatedTokenID         []byte
	RegulatedTokenType       TokenType
	Quantity                 []byte
	SourceHolder             [drwaAddressLength]byte
	DestinationHolder        [drwaAddressLength]byte
	CEBEpoch                 uint32
	TransferMode             TransferMode
	SettlementExpiry         uint64
	GasScheduleIdentity      [drwaDigestLength]byte
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
func DRWAValueEnvelopeMaximumLength() int {
	return drwaEnvelopeMaximumLength()
}

// EncodeValueContext returns deterministic S1 prototype bytes for the supplied context.
func EncodeValueContext(context ValueContext) ([]byte, error) {
	err := validateValueContext(context)
	if err != nil {
		return nil, err
	}

	encoded := make([]byte, 0, drwaContextMaximumLength())
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
	if len(envelope.OriginalTransferPayload) == 0 || len(envelope.OriginalTransferPayload) > drwaPayloadLimit {
		return nil, fmt.Errorf("%w: original transfer payload length", ErrInvalidValueEnvelope)
	}

	contextBytes, err := EncodeValueContext(envelope.Context)
	if err != nil {
		return nil, err
	}

	encoded := make([]byte, 0, 1+4+len(envelope.OriginalTransferPayload)+len(contextBytes))
	encoded = append(encoded, drwaEnvelopeVersion)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(envelope.OriginalTransferPayload)))
	encoded = append(encoded, envelope.OriginalTransferPayload...)
	encoded = append(encoded, contextBytes...)

	return encoded, nil
}

// DecodeValueEnvelope decodes and validates deterministic S1 prototype bytes.
func DecodeValueEnvelope(encoded []byte) (*ValueEnvelope, error) {
	if len(encoded) == 0 || len(encoded) > drwaEnvelopeMaximumLength() {
		return nil, fmt.Errorf("%w: total length", ErrInvalidValueEnvelope)
	}

	reader := drwaReader{data: encoded, invalidError: ErrInvalidValueEnvelope}
	version, err := reader.readByte()
	if err != nil || version != drwaEnvelopeVersion {
		return nil, fmt.Errorf("%w: envelope version", ErrInvalidValueEnvelope)
	}

	payload, err := reader.readUint32Bytes(drwaPayloadLimit)
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
	if len(context.RegulatedTokenID) == 0 || len(context.RegulatedTokenID) > drwaTokenIDLimit {
		return fmt.Errorf("%w: regulated token identifier length", ErrInvalidValueEnvelope)
	}
	if context.RegulatedTokenType != TokenTypeFungible {
		return fmt.Errorf("%w: unsupported token type", ErrInvalidValueEnvelope)
	}
	if len(context.Quantity) == 0 || len(context.Quantity) > drwaQuantityLimit || context.Quantity[0] == 0 {
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

func drwaContextMaximumLength() int {
	return drwaDigestLength + 1 + drwaDigestLength +
		2 + drwaTokenIDLimit + 1 + 2 + drwaQuantityLimit +
		2*drwaAddressLength + 4 + 1 + 8 + drwaDigestLength + 4*8
}

func drwaEnvelopeMaximumLength() int {
	return 1 + 4 + drwaPayloadLimit + drwaContextMaximumLength()
}

type drwaReader struct {
	data         []byte
	offset       int
	invalidError error
}

func (reader *drwaReader) readValueContext() (ValueContext, error) {
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
	context.RegulatedTokenID, err = reader.readUint16Bytes(drwaTokenIDLimit)
	if err != nil {
		return ValueContext{}, err
	}
	tokenType, err := reader.readByte()
	if err != nil {
		return ValueContext{}, err
	}
	context.RegulatedTokenType = TokenType(tokenType)
	context.Quantity, err = reader.readUint16Bytes(drwaQuantityLimit)
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

func (reader *drwaReader) readByte() (byte, error) {
	if reader.remaining() < 1 {
		return 0, reader.invalid("truncated byte")
	}
	value := reader.data[reader.offset]
	reader.offset++
	return value, nil
}

func (reader *drwaReader) readUint16Bytes(maximum int) ([]byte, error) {
	if reader.remaining() < 2 {
		return nil, reader.invalid("truncated uint16 length")
	}
	length := int(binary.BigEndian.Uint16(reader.data[reader.offset:]))
	reader.offset += 2
	return reader.readCopiedBytes(length, maximum)
}

func (reader *drwaReader) readUint32Bytes(maximum int) ([]byte, error) {
	if reader.remaining() < 4 {
		return nil, reader.invalid("truncated uint32 length")
	}
	length := binary.BigEndian.Uint32(reader.data[reader.offset:])
	reader.offset += 4
	if length > uint32(maximum) {
		return nil, reader.invalid("variable field limit")
	}
	return reader.readCopiedBytes(int(length), maximum)
}

func (reader *drwaReader) readCopiedBytes(length int, maximum int) ([]byte, error) {
	if length < 0 || length > maximum || reader.remaining() < length {
		return nil, reader.invalid("variable field length")
	}
	value := make([]byte, length)
	copy(value, reader.data[reader.offset:reader.offset+length])
	reader.offset += length
	return value, nil
}

func (reader *drwaReader) readFixed(destination []byte) error {
	if reader.remaining() < len(destination) {
		return reader.invalid("truncated fixed field")
	}
	copy(destination, reader.data[reader.offset:reader.offset+len(destination)])
	reader.offset += len(destination)
	return nil
}

func (reader *drwaReader) readUint32() (uint32, error) {
	if reader.remaining() < 4 {
		return 0, reader.invalid("truncated uint32")
	}
	value := binary.BigEndian.Uint32(reader.data[reader.offset:])
	reader.offset += 4
	return value, nil
}

func (reader *drwaReader) readUint64() (uint64, error) {
	if reader.remaining() < 8 {
		return 0, reader.invalid("truncated uint64")
	}
	value := binary.BigEndian.Uint64(reader.data[reader.offset:])
	reader.offset += 8
	return value, nil
}

func (reader *drwaReader) remaining() int {
	return len(reader.data) - reader.offset
}

func (reader *drwaReader) invalid(reason string) error {
	return fmt.Errorf("%w: %s", reader.invalidError, reason)
}
