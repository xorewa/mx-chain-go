package drwaprototype

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

const (
	prototypeSettlementReceiptVersion = byte(1)
	prototypeRefundEnvelopeVersion    = byte(1)

	prototypeDestinationResultDomain = "DRWA/PROTOTYPE/DESTINATION_RESULT/v1"
	prototypeSettledStatusBytes      = "SETTLED"
)

var (
	// ErrInvalidSettlementReceipt signals malformed or unsupported S1 success-result bytes.
	ErrInvalidSettlementReceipt = errors.New("invalid non-normative DRWA prototype settlement receipt")
	// ErrInvalidRefundEnvelope signals malformed or unsupported S1 refund bytes.
	ErrInvalidRefundEnvelope = errors.New("invalid non-normative DRWA prototype refund envelope")
)

// SettlementStatus identifies the only success state in this S1 slice.
type SettlementStatus byte

const (
	// SettlementStatusSettled is the canonical successful destination outcome.
	SettlementStatusSettled SettlementStatus = 1
)

// SettlementReceipt is the replaceable S1 success-result representation.
type SettlementReceipt struct {
	EffectID                     [prototypeDigestLength]byte
	ContextHash                  [prototypeDigestLength]byte
	DestinationExecutionIdentity [prototypeDigestLength]byte
	DestinationResultIdentity    [prototypeDigestLength]byte
	Status                       SettlementStatus
}

// RefundEnvelope is the replaceable S1 denial-result representation.
type RefundEnvelope struct {
	EffectID                     [prototypeDigestLength]byte
	ContextHash                  [prototypeDigestLength]byte
	DestinationExecutionIdentity [prototypeDigestLength]byte
	OriginalTransferPayload      []byte
	RefundTo                     [prototypeAddressLength]byte
}

// BuildSettlementReceipt derives the approved non-circular destination result identity.
func BuildSettlementReceipt(
	networkDomain [prototypeDigestLength]byte,
	effectID [prototypeDigestLength]byte,
	contextHash [prototypeDigestLength]byte,
	destinationExecutionIdentity [prototypeDigestLength]byte,
) (SettlementReceipt, error) {
	if isZeroPrototypeDigest(networkDomain) ||
		isZeroPrototypeDigest(effectID) ||
		isZeroPrototypeDigest(contextHash) ||
		isZeroPrototypeDigest(destinationExecutionIdentity) {
		return SettlementReceipt{}, fmt.Errorf("%w: zero identity", ErrInvalidSettlementReceipt)
	}

	preimage := make([]byte, 0, len(prototypeDestinationResultDomain)+4*prototypeDigestLength+len(prototypeSettledStatusBytes))
	preimage = append(preimage, prototypeDestinationResultDomain...)
	preimage = append(preimage, networkDomain[:]...)
	preimage = append(preimage, effectID[:]...)
	preimage = append(preimage, contextHash[:]...)
	preimage = append(preimage, destinationExecutionIdentity[:]...)
	preimage = append(preimage, prototypeSettledStatusBytes...)

	return SettlementReceipt{
		EffectID:                     effectID,
		ContextHash:                  contextHash,
		DestinationExecutionIdentity: destinationExecutionIdentity,
		DestinationResultIdentity:    sha256.Sum256(preimage),
		Status:                       SettlementStatusSettled,
	}, nil
}

// EncodeSettlementReceipt returns deterministic S1 prototype bytes.
func EncodeSettlementReceipt(receipt SettlementReceipt) ([]byte, error) {
	if err := validateSettlementReceipt(receipt); err != nil {
		return nil, err
	}

	encoded := make([]byte, 0, 1+4*prototypeDigestLength+1)
	encoded = append(encoded, prototypeSettlementReceiptVersion)
	encoded = append(encoded, receipt.EffectID[:]...)
	encoded = append(encoded, receipt.ContextHash[:]...)
	encoded = append(encoded, receipt.DestinationExecutionIdentity[:]...)
	encoded = append(encoded, receipt.DestinationResultIdentity[:]...)
	encoded = append(encoded, byte(receipt.Status))

	return encoded, nil
}

// DecodeSettlementReceipt decodes and validates deterministic S1 prototype bytes.
func DecodeSettlementReceipt(encoded []byte) (*SettlementReceipt, error) {
	const encodedLength = 1 + 4*prototypeDigestLength + 1
	if len(encoded) != encodedLength || encoded[0] != prototypeSettlementReceiptVersion {
		return nil, fmt.Errorf("%w: length or version", ErrInvalidSettlementReceipt)
	}

	reader := prototypeReader{data: encoded[1:], invalidError: ErrInvalidSettlementReceipt}
	receipt := &SettlementReceipt{}
	if err := reader.readFixed(receipt.EffectID[:]); err != nil {
		return nil, err
	}
	if err := reader.readFixed(receipt.ContextHash[:]); err != nil {
		return nil, err
	}
	if err := reader.readFixed(receipt.DestinationExecutionIdentity[:]); err != nil {
		return nil, err
	}
	if err := reader.readFixed(receipt.DestinationResultIdentity[:]); err != nil {
		return nil, err
	}
	status, err := reader.readByte()
	if err != nil || reader.remaining() != 0 {
		return nil, fmt.Errorf("%w: status or trailing bytes", ErrInvalidSettlementReceipt)
	}
	receipt.Status = SettlementStatus(status)
	if err = validateSettlementReceipt(*receipt); err != nil {
		return nil, err
	}

	return receipt, nil
}

// EncodeRefundEnvelope returns deterministic S1 prototype bytes.
func EncodeRefundEnvelope(refund RefundEnvelope) ([]byte, error) {
	if err := validateRefundEnvelope(refund); err != nil {
		return nil, err
	}

	encoded := make([]byte, 0, 1+3*prototypeDigestLength+4+len(refund.OriginalTransferPayload)+prototypeAddressLength)
	encoded = append(encoded, prototypeRefundEnvelopeVersion)
	encoded = append(encoded, refund.EffectID[:]...)
	encoded = append(encoded, refund.ContextHash[:]...)
	encoded = append(encoded, refund.DestinationExecutionIdentity[:]...)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(refund.OriginalTransferPayload)))
	encoded = append(encoded, refund.OriginalTransferPayload...)
	encoded = append(encoded, refund.RefundTo[:]...)

	return encoded, nil
}

// DecodeRefundEnvelope decodes and validates deterministic S1 prototype bytes.
func DecodeRefundEnvelope(encoded []byte) (*RefundEnvelope, error) {
	maximumLength := 1 + 3*prototypeDigestLength + 4 + prototypePayloadLimit + prototypeAddressLength
	if len(encoded) == 0 || len(encoded) > maximumLength || encoded[0] != prototypeRefundEnvelopeVersion {
		return nil, fmt.Errorf("%w: length or version", ErrInvalidRefundEnvelope)
	}

	reader := prototypeReader{data: encoded[1:], invalidError: ErrInvalidRefundEnvelope}
	refund := &RefundEnvelope{}
	if err := reader.readFixed(refund.EffectID[:]); err != nil {
		return nil, err
	}
	if err := reader.readFixed(refund.ContextHash[:]); err != nil {
		return nil, err
	}
	if err := reader.readFixed(refund.DestinationExecutionIdentity[:]); err != nil {
		return nil, err
	}
	payload, err := reader.readUint32Bytes(prototypePayloadLimit)
	if err != nil {
		return nil, err
	}
	refund.OriginalTransferPayload = payload
	if err = reader.readFixed(refund.RefundTo[:]); err != nil {
		return nil, err
	}
	if reader.remaining() != 0 {
		return nil, fmt.Errorf("%w: trailing bytes", ErrInvalidRefundEnvelope)
	}
	if err = validateRefundEnvelope(*refund); err != nil {
		return nil, err
	}
	reencoded, err := EncodeRefundEnvelope(*refund)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		return nil, fmt.Errorf("%w: alternate encoding", ErrInvalidRefundEnvelope)
	}

	return refund, nil
}

func validateSettlementReceipt(receipt SettlementReceipt) error {
	if isZeroPrototypeDigest(receipt.EffectID) ||
		isZeroPrototypeDigest(receipt.ContextHash) ||
		isZeroPrototypeDigest(receipt.DestinationExecutionIdentity) ||
		isZeroPrototypeDigest(receipt.DestinationResultIdentity) ||
		receipt.Status != SettlementStatusSettled {
		return ErrInvalidSettlementReceipt
	}
	return nil
}

func validateRefundEnvelope(refund RefundEnvelope) error {
	if isZeroPrototypeDigest(refund.EffectID) ||
		isZeroPrototypeDigest(refund.ContextHash) ||
		isZeroPrototypeDigest(refund.DestinationExecutionIdentity) ||
		len(refund.OriginalTransferPayload) == 0 ||
		len(refund.OriginalTransferPayload) > prototypePayloadLimit ||
		refund.RefundTo == ([prototypeAddressLength]byte{}) {
		return ErrInvalidRefundEnvelope
	}
	return nil
}
