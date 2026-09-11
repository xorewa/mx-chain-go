package drwa

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B
//
// This record is the S1 value-result replay barrier. It shares the source account journal
// with the corresponding OpenEffect and is not a public transport or production storage format.

const (
	drwaTerminalValueEvidenceVersion = byte(1)
	drwaTerminalValueKeySuffix       = "drwa/terminal-value/"
	drwaTerminalValueResultDomain    = "DRWA/PROTOTYPE/TERMINAL_VALUE_RESULT/v1"
)

var (
	// ErrInvalidTerminalValueEvidence signals malformed or mismatched retained terminal state.
	ErrInvalidTerminalValueEvidence = errors.New("invalid non-normative DRWA prototype terminal value evidence")
	// ErrTerminalValueEvidenceNotFound signals absence of retained terminal state for one effect.
	ErrTerminalValueEvidenceNotFound = errors.New("non-normative DRWA prototype terminal value evidence not found")
	// ErrTerminalValueEvidenceAlreadyExists signals that an effect identifier is already terminal.
	ErrTerminalValueEvidenceAlreadyExists = errors.New("non-normative DRWA prototype terminal value evidence already exists")
)

// TerminalValueOutcome identifies the source-side terminal value mutation.
type TerminalValueOutcome byte

const (
	// TerminalValueOutcomeSettled records removal of a settled value effect without source credit.
	TerminalValueOutcomeSettled TerminalValueOutcome = 1
	// TerminalValueOutcomeRefunded records the single source refund credit and effect removal.
	TerminalValueOutcomeRefunded TerminalValueOutcome = 2
)

// TerminalValueEvidence binds one terminal result to the immutable identity of its former OpenEffect.
type TerminalValueEvidence struct {
	EffectID                [drwaDigestLength]byte
	ContextHash             [drwaDigestLength]byte
	OriginExecutionIdentity [drwaDigestLength]byte
	SourceSubject           [drwaAddressLength]byte
	CEBEpoch                uint32
	GasScheduleIdentity     [drwaDigestLength]byte
	Outcome                 TerminalValueOutcome
	ResultHash              [drwaDigestLength]byte
}

// BuildTerminalValueEvidence derives retained terminal state from one live effect and canonical result payload.
func BuildTerminalValueEvidence(
	effect OpenEffect,
	outcome TerminalValueOutcome,
	encodedResult []byte,
) (TerminalValueEvidence, error) {
	if err := validateOpenEffect(effect); err != nil {
		return TerminalValueEvidence{}, fmt.Errorf("%w: OpenEffect: %w", ErrInvalidTerminalValueEvidence, err)
	}
	resultHash, err := terminalValueResultHash(outcome, encodedResult)
	if err != nil {
		return TerminalValueEvidence{}, err
	}
	evidence := TerminalValueEvidence{
		EffectID:                effect.EffectID,
		ContextHash:             effect.ContextHash,
		OriginExecutionIdentity: effect.OriginExecutionIdentity,
		SourceSubject:           effect.SourceSubject,
		CEBEpoch:                effect.CEBEpoch,
		GasScheduleIdentity:     effect.GasScheduleIdentity,
		Outcome:                 outcome,
		ResultHash:              resultHash,
	}
	if err = validateTerminalValueEvidence(evidence); err != nil {
		return TerminalValueEvidence{}, err
	}

	return evidence, nil
}

// ValidateTerminalValueEvidenceResult binds a replayed result to exact retained terminal state.
func ValidateTerminalValueEvidenceResult(
	evidence TerminalValueEvidence,
	effectID [drwaDigestLength]byte,
	contextHash [drwaDigestLength]byte,
	outcome TerminalValueOutcome,
	encodedResult []byte,
) error {
	if err := validateTerminalValueEvidence(evidence); err != nil {
		return err
	}
	resultHash, err := terminalValueResultHash(outcome, encodedResult)
	if err != nil {
		return err
	}
	if evidence.EffectID != effectID || evidence.ContextHash != contextHash ||
		evidence.Outcome != outcome || evidence.ResultHash != resultHash {
		return fmt.Errorf("%w: result binding", ErrInvalidTerminalValueEvidence)
	}

	return nil
}

// EncodeTerminalValueEvidence returns deterministic, replaceable S1 prototype bytes.
func EncodeTerminalValueEvidence(evidence TerminalValueEvidence) ([]byte, error) {
	if err := validateTerminalValueEvidence(evidence); err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, terminalValueEvidenceEncodedLength())
	encoded = append(encoded, drwaTerminalValueEvidenceVersion)
	encoded = append(encoded, evidence.EffectID[:]...)
	encoded = append(encoded, evidence.ContextHash[:]...)
	encoded = append(encoded, evidence.OriginExecutionIdentity[:]...)
	encoded = append(encoded, evidence.SourceSubject[:]...)
	encoded = binary.BigEndian.AppendUint32(encoded, evidence.CEBEpoch)
	encoded = append(encoded, evidence.GasScheduleIdentity[:]...)
	encoded = append(encoded, byte(evidence.Outcome))
	encoded = append(encoded, evidence.ResultHash[:]...)

	return encoded, nil
}

// DecodeTerminalValueEvidence decodes and validates deterministic retained terminal state.
func DecodeTerminalValueEvidence(encoded []byte) (*TerminalValueEvidence, error) {
	if len(encoded) != terminalValueEvidenceEncodedLength() || encoded[0] != drwaTerminalValueEvidenceVersion {
		return nil, fmt.Errorf("%w: record length or version", ErrInvalidTerminalValueEvidence)
	}
	reader := drwaReader{data: encoded[1:], invalidError: ErrInvalidTerminalValueEvidence}
	evidence := &TerminalValueEvidence{}
	if err := reader.readFixed(evidence.EffectID[:]); err != nil {
		return nil, err
	}
	if err := reader.readFixed(evidence.ContextHash[:]); err != nil {
		return nil, err
	}
	if err := reader.readFixed(evidence.OriginExecutionIdentity[:]); err != nil {
		return nil, err
	}
	if err := reader.readFixed(evidence.SourceSubject[:]); err != nil {
		return nil, err
	}
	cebEpoch, err := reader.readUint32()
	if err != nil {
		return nil, err
	}
	evidence.CEBEpoch = cebEpoch
	if err = reader.readFixed(evidence.GasScheduleIdentity[:]); err != nil {
		return nil, err
	}
	outcome, err := reader.readByte()
	if err != nil {
		return nil, err
	}
	evidence.Outcome = TerminalValueOutcome(outcome)
	if err = reader.readFixed(evidence.ResultHash[:]); err != nil {
		return nil, err
	}
	if reader.remaining() != 0 {
		return nil, fmt.Errorf("%w: trailing bytes", ErrInvalidTerminalValueEvidence)
	}
	if err = validateTerminalValueEvidence(*evidence); err != nil {
		return nil, err
	}
	reencoded, err := EncodeTerminalValueEvidence(*evidence)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		return nil, fmt.Errorf("%w: alternate encoding", ErrInvalidTerminalValueEvidence)
	}

	return evidence, nil
}

// TerminalValueEvidenceStorageKey returns the protected replay-barrier key for one effect.
func TerminalValueEvidenceStorageKey(effectID [drwaDigestLength]byte) []byte {
	key := make([]byte, 0, len(core.ProtectedKeyPrefix)+len(drwaTerminalValueKeySuffix)+len(effectID))
	key = append(key, core.ProtectedKeyPrefix...)
	key = append(key, drwaTerminalValueKeySuffix...)
	return append(key, effectID[:]...)
}

// LoadTerminalValueEvidence loads one retained replay barrier and binds it to its storage key.
func LoadTerminalValueEvidence(
	dataHandler vmcommon.AccountDataHandler,
	effectID [drwaDigestLength]byte,
) (*TerminalValueEvidence, error) {
	if check.IfNil(dataHandler) {
		return nil, ErrNilOpenEffectDataHandler
	}
	encoded, _, err := dataHandler.RetrieveValue(TerminalValueEvidenceStorageKey(effectID))
	if err != nil {
		return nil, fmt.Errorf("retrieve prototype terminal value evidence: %w", err)
	}
	if len(encoded) == 0 {
		return nil, ErrTerminalValueEvidenceNotFound
	}
	evidence, err := DecodeTerminalValueEvidence(encoded)
	if err != nil {
		return nil, err
	}
	if evidence.EffectID != effectID {
		return nil, fmt.Errorf("%w: storage key effect identifier mismatch", ErrInvalidTerminalValueEvidence)
	}

	return evidence, nil
}

// FinalizeOpenEffect atomically orders the terminal replay barrier before OpenEffect removal.
// The caller must include both writes and any value mutation in one enclosing account journal.
func FinalizeOpenEffect(
	dataHandler vmcommon.AccountDataHandler,
	effect OpenEffect,
	evidence TerminalValueEvidence,
) error {
	if check.IfNil(dataHandler) {
		return ErrNilOpenEffectDataHandler
	}
	if err := validateTerminalEvidenceForEffect(effect, evidence); err != nil {
		return err
	}
	terminalKey := TerminalValueEvidenceStorageKey(effect.EffectID)
	existingTerminal, _, err := dataHandler.RetrieveValue(terminalKey)
	if err != nil {
		return fmt.Errorf("retrieve prototype terminal value evidence: %w", err)
	}
	if len(existingTerminal) != 0 {
		return ErrTerminalValueEvidenceAlreadyExists
	}
	storedEffect, err := LoadOpenEffect(dataHandler, effect.EffectID)
	if err != nil {
		return err
	}
	expectedOpenBytes, err := EncodeOpenEffect(effect)
	if err != nil {
		return err
	}
	storedOpenBytes, err := EncodeOpenEffect(*storedEffect)
	if err != nil || !bytes.Equal(expectedOpenBytes, storedOpenBytes) {
		return fmt.Errorf("%w: live OpenEffect mismatch", ErrInvalidTerminalValueEvidence)
	}
	encodedEvidence, err := EncodeTerminalValueEvidence(evidence)
	if err != nil {
		return err
	}
	if err = dataHandler.SaveKeyValue(terminalKey, encodedEvidence); err != nil {
		return fmt.Errorf("save prototype terminal value evidence: %w", err)
	}
	if err = dataHandler.SaveKeyValue(OpenEffectStorageKey(effect.EffectID), nil); err != nil {
		return fmt.Errorf("remove prototype OpenEffect after terminal value evidence: %w", err)
	}

	return nil
}

func validateTerminalEvidenceForEffect(effect OpenEffect, evidence TerminalValueEvidence) error {
	if err := validateOpenEffect(effect); err != nil {
		return fmt.Errorf("%w: OpenEffect: %w", ErrInvalidTerminalValueEvidence, err)
	}
	if err := validateTerminalValueEvidence(evidence); err != nil {
		return err
	}
	if evidence.EffectID != effect.EffectID || evidence.ContextHash != effect.ContextHash ||
		evidence.OriginExecutionIdentity != effect.OriginExecutionIdentity ||
		evidence.SourceSubject != effect.SourceSubject || evidence.CEBEpoch != effect.CEBEpoch ||
		evidence.GasScheduleIdentity != effect.GasScheduleIdentity {
		return fmt.Errorf("%w: OpenEffect binding", ErrInvalidTerminalValueEvidence)
	}

	return nil
}

func validateTerminalValueEvidence(evidence TerminalValueEvidence) error {
	if isZeroDRWADigest(evidence.EffectID) || isZeroDRWADigest(evidence.ContextHash) ||
		isZeroDRWADigest(evidence.OriginExecutionIdentity) || evidence.SourceSubject == ([drwaAddressLength]byte{}) ||
		evidence.CEBEpoch == 0 || isZeroDRWADigest(evidence.GasScheduleIdentity) ||
		(evidence.Outcome != TerminalValueOutcomeSettled && evidence.Outcome != TerminalValueOutcomeRefunded) ||
		isZeroDRWADigest(evidence.ResultHash) {
		return ErrInvalidTerminalValueEvidence
	}

	return nil
}

func terminalValueResultHash(outcome TerminalValueOutcome, encodedResult []byte) ([drwaDigestLength]byte, error) {
	if (outcome != TerminalValueOutcomeSettled && outcome != TerminalValueOutcomeRefunded) ||
		len(encodedResult) == 0 || len(encodedResult) > DRWAValueEnvelopeMaximumLength() {
		return [drwaDigestLength]byte{}, fmt.Errorf("%w: terminal result", ErrInvalidTerminalValueEvidence)
	}
	preimage := make([]byte, 0, len(drwaTerminalValueResultDomain)+1+4+len(encodedResult))
	preimage = append(preimage, drwaTerminalValueResultDomain...)
	preimage = append(preimage, byte(outcome))
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(encodedResult)))
	preimage = append(preimage, encodedResult...)
	return sha256.Sum256(preimage), nil
}

func terminalValueEvidenceEncodedLength() int {
	return 1 + 5*drwaDigestLength + drwaAddressLength + 4 + 1
}
