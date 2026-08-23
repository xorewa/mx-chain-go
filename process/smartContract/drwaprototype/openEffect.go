package drwaprototype

import (
	"bytes"
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
// The bytes, key suffix, enum values and limits in this file exist only for the S1 direct-value
// prototype. None is a production state-layout, wire-format or numeric-bound commitment.

const (
	prototypeOpenEffectVersion = byte(1)

	prototypeOpenEffectKeySuffix = "drwa/open-effect/"
)

var (
	// ErrInvalidOpenEffect signals a malformed or unsupported S1 prototype OpenEffect.
	ErrInvalidOpenEffect = errors.New("invalid non-normative DRWA prototype OpenEffect")
	// ErrNilOpenEffectDataHandler signals that typed prototype storage has no account-data handler.
	ErrNilOpenEffectDataHandler = errors.New("nil non-normative DRWA prototype OpenEffect data handler")
	// ErrOpenEffectAlreadyExists signals duplicate creation for one prototype effect ID.
	ErrOpenEffectAlreadyExists = errors.New("non-normative DRWA prototype OpenEffect already exists")
	// ErrOpenEffectNotFound signals absence of the requested prototype effect ID.
	ErrOpenEffectNotFound = errors.New("non-normative DRWA prototype OpenEffect not found")
)

// OpenEffectTerminalKind identifies the terminal-policy family used by the S1 prototype.
type OpenEffectTerminalKind byte

const (
	// OpenEffectTerminalKindValueResult accepts one matching value success or refund result.
	OpenEffectTerminalKindValueResult OpenEffectTerminalKind = 1
)

// OpenEffectState identifies the lifecycle state used by the S1 prototype.
type OpenEffectState byte

const (
	// OpenEffectStatePendingDestination is the initial state of an asynchronous value effect.
	OpenEffectStatePendingDestination OpenEffectState = 1
)

// OpenEffect is the first, direct-fungible S1 prototype record.
type OpenEffect struct {
	EffectID                [prototypeDigestLength]byte
	EffectKind              ValueEffectKind
	RegulatedTokenID        []byte
	RegulatedTokenType      TokenType
	OriginExecutionIdentity [prototypeDigestLength]byte
	SourceSubject           [prototypeAddressLength]byte
	CEBEpoch                uint32
	ContextHash             [prototypeDigestLength]byte
	TerminalKind            OpenEffectTerminalKind
	State                   OpenEffectState
}

// EncodeOpenEffect returns deterministic, replaceable S1 prototype bytes.
func EncodeOpenEffect(effect OpenEffect) ([]byte, error) {
	err := validateOpenEffect(effect)
	if err != nil {
		return nil, err
	}

	encoded := make([]byte, 0, prototypeOpenEffectMaximumLength())
	encoded = append(encoded, prototypeOpenEffectVersion)
	encoded = append(encoded, effect.EffectID[:]...)
	encoded = append(encoded, byte(effect.EffectKind))
	encoded = appendUint16Bytes(encoded, effect.RegulatedTokenID)
	encoded = append(encoded, byte(effect.RegulatedTokenType))
	encoded = append(encoded, effect.OriginExecutionIdentity[:]...)
	encoded = append(encoded, effect.SourceSubject[:]...)
	encoded = binary.BigEndian.AppendUint32(encoded, effect.CEBEpoch)
	encoded = append(encoded, effect.ContextHash[:]...)
	encoded = append(encoded, byte(effect.TerminalKind))
	encoded = append(encoded, byte(effect.State))

	return encoded, nil
}

// DecodeOpenEffect decodes and validates deterministic S1 prototype bytes.
func DecodeOpenEffect(encoded []byte) (*OpenEffect, error) {
	if len(encoded) == 0 || len(encoded) > prototypeOpenEffectMaximumLength() {
		return nil, fmt.Errorf("%w: total length", ErrInvalidOpenEffect)
	}

	reader := prototypeReader{data: encoded, invalidError: ErrInvalidOpenEffect}
	version, err := reader.readByte()
	if err != nil || version != prototypeOpenEffectVersion {
		return nil, fmt.Errorf("%w: record version", ErrInvalidOpenEffect)
	}

	effect := &OpenEffect{}
	err = reader.readFixed(effect.EffectID[:])
	if err != nil {
		return nil, err
	}
	effectKind, err := reader.readByte()
	if err != nil {
		return nil, err
	}
	effect.EffectKind = ValueEffectKind(effectKind)
	effect.RegulatedTokenID, err = reader.readUint16Bytes(prototypeTokenIDLimit)
	if err != nil {
		return nil, err
	}
	tokenType, err := reader.readByte()
	if err != nil {
		return nil, err
	}
	effect.RegulatedTokenType = TokenType(tokenType)
	err = reader.readFixed(effect.OriginExecutionIdentity[:])
	if err != nil {
		return nil, err
	}
	err = reader.readFixed(effect.SourceSubject[:])
	if err != nil {
		return nil, err
	}
	effect.CEBEpoch, err = reader.readUint32()
	if err != nil {
		return nil, err
	}
	err = reader.readFixed(effect.ContextHash[:])
	if err != nil {
		return nil, err
	}
	terminalKind, err := reader.readByte()
	if err != nil {
		return nil, err
	}
	effect.TerminalKind = OpenEffectTerminalKind(terminalKind)
	state, err := reader.readByte()
	if err != nil {
		return nil, err
	}
	effect.State = OpenEffectState(state)

	if reader.remaining() != 0 {
		return nil, fmt.Errorf("%w: trailing bytes", ErrInvalidOpenEffect)
	}
	err = validateOpenEffect(*effect)
	if err != nil {
		return nil, err
	}
	reencoded, err := EncodeOpenEffect(*effect)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(encoded, reencoded) {
		return nil, fmt.Errorf("%w: alternate encoding", ErrInvalidOpenEffect)
	}

	return effect, nil
}

// OpenEffectStorageKey returns a fresh fixed-size protected prototype key for one effect ID.
func OpenEffectStorageKey(effectID [prototypeDigestLength]byte) []byte {
	key := make([]byte, 0, len(core.ProtectedKeyPrefix)+len(prototypeOpenEffectKeySuffix)+len(effectID))
	key = append(key, core.ProtectedKeyPrefix...)
	key = append(key, prototypeOpenEffectKeySuffix...)
	return append(key, effectID[:]...)
}

// CreateOpenEffect creates exactly one protected prototype record for the embedded effect ID.
func CreateOpenEffect(dataHandler vmcommon.AccountDataHandler, effect OpenEffect) error {
	if check.IfNil(dataHandler) {
		return ErrNilOpenEffectDataHandler
	}
	encoded, err := EncodeOpenEffect(effect)
	if err != nil {
		return err
	}
	key := OpenEffectStorageKey(effect.EffectID)
	existing, _, err := dataHandler.RetrieveValue(key)
	if err != nil {
		return fmt.Errorf("retrieve prototype OpenEffect: %w", err)
	}
	if len(existing) != 0 {
		return ErrOpenEffectAlreadyExists
	}
	err = dataHandler.SaveKeyValue(key, encoded)
	if err != nil {
		return fmt.Errorf("save prototype OpenEffect: %w", err)
	}

	return nil
}

// LoadOpenEffect loads one protected prototype record and binds its embedded ID to the requested key.
func LoadOpenEffect(dataHandler vmcommon.AccountDataHandler, effectID [prototypeDigestLength]byte) (*OpenEffect, error) {
	if check.IfNil(dataHandler) {
		return nil, ErrNilOpenEffectDataHandler
	}
	encoded, _, err := dataHandler.RetrieveValue(OpenEffectStorageKey(effectID))
	if err != nil {
		return nil, fmt.Errorf("retrieve prototype OpenEffect: %w", err)
	}
	if len(encoded) == 0 {
		return nil, ErrOpenEffectNotFound
	}
	effect, err := DecodeOpenEffect(encoded)
	if err != nil {
		return nil, err
	}
	if effect.EffectID != effectID {
		return nil, fmt.Errorf("%w: storage key effect identifier mismatch", ErrInvalidOpenEffect)
	}

	return effect, nil
}

func validateOpenEffect(effect OpenEffect) error {
	if effect.EffectKind != ValueEffectKindDirectTransfer {
		return fmt.Errorf("%w: unsupported effect kind", ErrInvalidOpenEffect)
	}
	if len(effect.RegulatedTokenID) == 0 || len(effect.RegulatedTokenID) > prototypeTokenIDLimit {
		return fmt.Errorf("%w: regulated token identifier length", ErrInvalidOpenEffect)
	}
	if effect.RegulatedTokenType != TokenTypeFungible {
		return fmt.Errorf("%w: unsupported token type", ErrInvalidOpenEffect)
	}
	if effect.TerminalKind != OpenEffectTerminalKindValueResult {
		return fmt.Errorf("%w: unsupported terminal kind", ErrInvalidOpenEffect)
	}
	if effect.State != OpenEffectStatePendingDestination {
		return fmt.Errorf("%w: unsupported state", ErrInvalidOpenEffect)
	}

	return nil
}

func prototypeOpenEffectMaximumLength() int {
	return 1 + prototypeDigestLength + 1 + 2 + prototypeTokenIDLimit + 1 +
		prototypeDigestLength + prototypeAddressLength + 4 + prototypeDigestLength + 1 + 1
}
