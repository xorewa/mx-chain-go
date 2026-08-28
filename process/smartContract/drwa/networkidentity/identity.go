package networkidentity

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

// ErrInvalid is returned for every malformed or unsupported prototype identity record.
var ErrInvalid = errors.New("invalid non-normative DRWA prototype network identity")

const (
	// Version is the only accepted full-tuple identity schema.
	Version byte = 2

	chainIDLengthOffset = 4 + 1 + 4 + 1
	chainIDOffset       = chainIDLengthOffset + 4
	fixedFieldsLength   = 4 + 1 + 4 + 1 + 4 + 32 + 32 + 4
)

var (
	magic           = [4]byte{'D', 'R', 'W', 'A'}
	keyPrefix       = []byte("DRWA/NETWORK-IDENTITY/v2/epoch/")
	legacyKeyPrefix = []byte("DRWA/NETWORK-IDENTITY/v1/epoch/")
)

// Provenance is the closed source classification retained with the canonical header.
type Provenance byte

const (
	// LocalCanonicalGenesis means the node derived and stored the header in its own canonical genesis path.
	LocalCanonicalGenesis Provenance = 1
	// EmergencyMigration means a separately authorized restoration tool installed the verified header.
	EmergencyMigration Provenance = 2
)

// String returns the stable evidence label for a provenance value.
func (provenance Provenance) String() string {
	switch provenance {
	case LocalCanonicalGenesis:
		return "LOCAL_CANONICAL_GENESIS"
	case EmergencyMigration:
		return "EMERGENCY_MIGRATION"
	default:
		return fmt.Sprintf("UNKNOWN_%d", byte(provenance))
	}
}

// Record is the decoded closed identity envelope.
type Record struct {
	SchemaVersion byte
	Epoch         uint32
	Provenance    Provenance
	ChainID       []byte
	CanonicalHash [32]byte
	NetworkDomain [32]byte
	HeaderBytes   []byte
}

// Key returns the schema- and epoch-separated storage key.
func Key(epoch uint32) []byte {
	key := make([]byte, len(keyPrefix)+4)
	copy(key, keyPrefix)
	binary.BigEndian.PutUint32(key[len(keyPrefix):], epoch)
	return key
}

// LegacyKey returns the version-1 key solely for migration evidence and coexistence checks.
// Node startup never reads this key as protocol identity.
func LegacyKey(epoch uint32) []byte {
	key := make([]byte, len(legacyKeyPrefix)+4)
	copy(key, legacyKeyPrefix)
	binary.BigEndian.PutUint32(key[len(legacyKeyPrefix):], epoch)
	return key
}

// Encode emits the one accepted envelope representation.
func Encode(record Record) ([]byte, error) {
	if record.SchemaVersion != Version {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalid, record.SchemaVersion)
	}
	if record.Provenance != LocalCanonicalGenesis && record.Provenance != EmergencyMigration {
		return nil, fmt.Errorf("%w: unknown provenance %d", ErrInvalid, record.Provenance)
	}
	if len(record.ChainID) == 0 || len(record.ChainID) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: invalid chain ID length %d", ErrInvalid, len(record.ChainID))
	}
	if len(record.HeaderBytes) == 0 || len(record.HeaderBytes) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: invalid header length %d", ErrInvalid, len(record.HeaderBytes))
	}

	totalLength := uint64(fixedFieldsLength) + uint64(len(record.ChainID)) + uint64(len(record.HeaderBytes))
	maxInt := int(^uint(0) >> 1)
	if totalLength > uint64(maxInt) {
		return nil, fmt.Errorf("%w: envelope length %d overflows int", ErrInvalid, totalLength)
	}

	envelope := make([]byte, int(totalLength))
	copy(envelope[0:4], magic[:])
	envelope[4] = Version
	binary.BigEndian.PutUint32(envelope[5:9], record.Epoch)
	envelope[9] = byte(record.Provenance)
	binary.BigEndian.PutUint32(envelope[chainIDLengthOffset:chainIDOffset], uint32(len(record.ChainID)))
	chainIDEnd := chainIDOffset + len(record.ChainID)
	copy(envelope[chainIDOffset:chainIDEnd], record.ChainID)
	canonicalHashEnd := chainIDEnd + len(record.CanonicalHash)
	copy(envelope[chainIDEnd:canonicalHashEnd], record.CanonicalHash[:])
	networkDomainEnd := canonicalHashEnd + len(record.NetworkDomain)
	copy(envelope[canonicalHashEnd:networkDomainEnd], record.NetworkDomain[:])
	headerLengthEnd := networkDomainEnd + 4
	binary.BigEndian.PutUint32(envelope[networkDomainEnd:headerLengthEnd], uint32(len(record.HeaderBytes)))
	copy(envelope[headerLengthEnd:], record.HeaderBytes)
	return envelope, nil
}

// Decode accepts only the exact closed envelope representation for expectedChainID.
// ChainID and HeaderBytes are borrowed views into envelope and are valid only while the caller
// synchronously owns and keeps envelope immutable. They must not be retained or used asynchronously.
func Decode(envelope []byte, expectedChainID []byte) (Record, error) {
	if len(expectedChainID) == 0 || len(expectedChainID) > math.MaxUint32 {
		return Record{}, fmt.Errorf("%w: invalid expected chain ID length %d", ErrInvalid, len(expectedChainID))
	}
	if len(envelope) < fixedFieldsLength+2 {
		return Record{}, fmt.Errorf("%w: truncated envelope", ErrInvalid)
	}
	if !bytes.Equal(envelope[0:4], magic[:]) {
		return Record{}, fmt.Errorf("%w: wrong magic", ErrInvalid)
	}
	if envelope[4] != Version {
		return Record{}, fmt.Errorf("%w: unsupported version %d", ErrInvalid, envelope[4])
	}

	epoch := binary.BigEndian.Uint32(envelope[5:9])
	provenance := Provenance(envelope[9])
	if provenance != LocalCanonicalGenesis && provenance != EmergencyMigration {
		return Record{}, fmt.Errorf("%w: unknown provenance %d", ErrInvalid, provenance)
	}
	chainIDLength := binary.BigEndian.Uint32(envelope[chainIDLengthOffset:chainIDOffset])
	if uint64(chainIDLength) != uint64(len(expectedChainID)) {
		return Record{}, fmt.Errorf(
			"%w: chain ID length %d, expected %d",
			ErrInvalid,
			chainIDLength,
			len(expectedChainID),
		)
	}
	chainIDEnd64 := uint64(chainIDOffset) + uint64(chainIDLength)
	fixedTailLength := uint64(32 + 32 + 4)
	if chainIDEnd64+fixedTailLength > uint64(len(envelope)) {
		return Record{}, fmt.Errorf("%w: truncated chain ID or tuple", ErrInvalid)
	}
	chainIDEnd := int(chainIDEnd64)
	chainID := envelope[chainIDOffset:chainIDEnd]
	if !bytes.Equal(chainID, expectedChainID) {
		return Record{}, fmt.Errorf("%w: chain ID mismatch", ErrInvalid)
	}

	canonicalHashEnd := chainIDEnd + 32
	networkDomainEnd := canonicalHashEnd + 32
	headerLengthEnd := networkDomainEnd + 4
	headerLength := binary.BigEndian.Uint32(envelope[networkDomainEnd:headerLengthEnd])
	expectedLength := uint64(fixedFieldsLength) + uint64(chainIDLength) + uint64(headerLength)
	if headerLength == 0 || expectedLength != uint64(len(envelope)) {
		return Record{}, fmt.Errorf(
			"%w: declared header length %d, envelope length %d",
			ErrInvalid,
			headerLength,
			len(envelope),
		)
	}

	canonicalHash := [32]byte{}
	copy(canonicalHash[:], envelope[chainIDEnd:canonicalHashEnd])
	networkDomain := [32]byte{}
	copy(networkDomain[:], envelope[canonicalHashEnd:networkDomainEnd])

	return Record{
		SchemaVersion: Version,
		Epoch:         epoch,
		Provenance:    provenance,
		ChainID:       chainID,
		CanonicalHash: canonicalHash,
		NetworkDomain: networkDomain,
		HeaderBytes:   envelope[headerLengthEnd:],
	}, nil
}
