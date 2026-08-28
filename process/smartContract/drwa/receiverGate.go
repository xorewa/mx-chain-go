package drwa

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

const (
	drwaReceiverGateVersion   = byte(1)
	drwaReceiverGateKeySuffix = "drwa/receiver-gate/v1/"
)

var (
	// ErrInvalidReceiverGate signals malformed or unsupported S1 receiver state.
	ErrInvalidReceiverGate = errors.New("invalid non-normative DRWA prototype receiver gate")
	// ErrReceiverGateNotFound signals absence of the S1 receiver binding.
	ErrReceiverGateNotFound = errors.New("non-normative DRWA prototype receiver gate not found")
	// ErrNilReceiverGateDataHandler signals an unavailable destination account data trie.
	ErrNilReceiverGateDataHandler = errors.New("nil non-normative DRWA prototype receiver gate data handler")
)

// ReceiverGateRecord is the typed, protected S1-only receiver qualification stand-in.
type ReceiverGateRecord struct {
	Holder            [drwaAddressLength]byte
	CEBEpoch          uint32
	Admitted          bool
	ValidThroughRound uint64
}

// ReceiverGateStorageKey returns the protected token- and version-bound key.
func ReceiverGateStorageKey(tokenID []byte) []byte {
	key := make([]byte, 0, len(core.ProtectedKeyPrefix)+len(drwaReceiverGateKeySuffix)+len(tokenID))
	key = append(key, core.ProtectedKeyPrefix...)
	key = append(key, drwaReceiverGateKeySuffix...)
	return append(key, tokenID...)
}

// EncodeReceiverGateRecord returns deterministic S1 prototype bytes.
func EncodeReceiverGateRecord(record ReceiverGateRecord) ([]byte, error) {
	if record.Holder == ([drwaAddressLength]byte{}) || record.CEBEpoch == 0 || record.ValidThroughRound == 0 {
		return nil, ErrInvalidReceiverGate
	}

	encoded := make([]byte, 0, 1+drwaAddressLength+4+1+8)
	encoded = append(encoded, drwaReceiverGateVersion)
	encoded = append(encoded, record.Holder[:]...)
	encoded = binary.BigEndian.AppendUint32(encoded, record.CEBEpoch)
	if record.Admitted {
		encoded = append(encoded, 1)
	} else {
		encoded = append(encoded, 0)
	}
	encoded = binary.BigEndian.AppendUint64(encoded, record.ValidThroughRound)

	return encoded, nil
}

// DecodeReceiverGateRecord decodes one exact typed receiver record.
func DecodeReceiverGateRecord(encoded []byte) (*ReceiverGateRecord, error) {
	const encodedLength = 1 + drwaAddressLength + 4 + 1 + 8
	if len(encoded) != encodedLength || encoded[0] != drwaReceiverGateVersion {
		return nil, ErrInvalidReceiverGate
	}
	record := &ReceiverGateRecord{}
	copy(record.Holder[:], encoded[1:1+drwaAddressLength])
	record.CEBEpoch = binary.BigEndian.Uint32(encoded[1+drwaAddressLength : 1+drwaAddressLength+4])
	admitted := encoded[1+drwaAddressLength+4]
	if admitted > 1 {
		return nil, ErrInvalidReceiverGate
	}
	record.Admitted = admitted == 1
	record.ValidThroughRound = binary.BigEndian.Uint64(encoded[1+drwaAddressLength+5:])
	if record.Holder == ([drwaAddressLength]byte{}) || record.CEBEpoch == 0 || record.ValidThroughRound == 0 {
		return nil, ErrInvalidReceiverGate
	}
	reencoded, err := EncodeReceiverGateRecord(*record)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		return nil, ErrInvalidReceiverGate
	}

	return record, nil
}

// LoadReceiverGateRecord reads the protected destination-account record. No public writer is
// provided by this prototype package.
func LoadReceiverGateRecord(dataHandler vmcommon.AccountDataHandler, tokenID []byte) (*ReceiverGateRecord, error) {
	if check.IfNil(dataHandler) {
		return nil, ErrNilReceiverGateDataHandler
	}
	if !vmcommon.ValidateToken(tokenID) || len(tokenID) > drwaTokenIDLimit {
		return nil, ErrInvalidReceiverGate
	}
	encoded, _, err := dataHandler.RetrieveValue(ReceiverGateStorageKey(tokenID))
	if err != nil {
		return nil, fmt.Errorf("retrieve prototype receiver gate: %w", err)
	}
	if len(encoded) == 0 {
		return nil, ErrReceiverGateNotFound
	}

	return DecodeReceiverGateRecord(encoded)
}
