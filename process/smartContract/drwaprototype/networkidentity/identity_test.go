package networkidentity

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecordV2ExactRoundTripAndBorrowedViews(t *testing.T) {
	t.Parallel()

	record := testRecord()
	envelope, err := Encode(record)
	require.NoError(t, err)
	require.Equal(t, []byte("DRWA"), envelope[:4])
	require.Equal(t, Version, envelope[4])
	require.Equal(t, record.Epoch, binary.BigEndian.Uint32(envelope[5:9]))
	require.Equal(t, byte(record.Provenance), envelope[9])
	require.Equal(t, uint32(len(record.ChainID)), binary.BigEndian.Uint32(envelope[10:14]))

	decoded, err := Decode(envelope, record.ChainID)
	require.NoError(t, err)
	require.Equal(t, record, decoded)
	chainOffset := chainIDOffset
	headerOffset := fixedFieldsLength + len(record.ChainID)
	require.Same(t, &envelope[chainOffset], &decoded.ChainID[0])
	require.Same(t, &envelope[headerOffset], &decoded.HeaderBytes[0])
}

func TestDecodeRejectsEveryTruncationAndStructuralAlternate(t *testing.T) {
	t.Parallel()

	record := testRecord()
	envelope, err := Encode(record)
	require.NoError(t, err)
	for end := 0; end < len(envelope); end++ {
		_, decodeErr := Decode(envelope[:end], record.ChainID)
		require.ErrorIsf(t, decodeErr, ErrInvalid, "truncation at byte %d", end)
	}

	headerLengthOffset := fixedFieldsLength + len(record.ChainID) - 4
	tests := map[string]func([]byte) []byte{
		"wrong magic":        func(value []byte) []byte { value[0] ^= 0xff; return value },
		"wrong version":      func(value []byte) []byte { value[4] = 1; return value },
		"unknown provenance": func(value []byte) []byte { value[9] = 0xff; return value },
		"zero chain length": func(value []byte) []byte {
			binary.BigEndian.PutUint32(value[chainIDLengthOffset:chainIDOffset], 0)
			return value
		},
		"maximum chain length in bounded envelope": func(value []byte) []byte {
			binary.BigEndian.PutUint32(value[chainIDLengthOffset:chainIDOffset], ^uint32(0))
			return value
		},
		"wrong chain bytes": func(value []byte) []byte { value[chainIDOffset] ^= 0xff; return value },
		"zero header length": func(value []byte) []byte {
			binary.BigEndian.PutUint32(value[headerLengthOffset:headerLengthOffset+4], 0)
			return value
		},
		"maximum header length in bounded envelope": func(value []byte) []byte {
			binary.BigEndian.PutUint32(value[headerLengthOffset:headerLengthOffset+4], ^uint32(0))
			return value
		},
		"trailing alternate encoding": func(value []byte) []byte { return append(value, 0) },
		"leading alternate encoding":  func(value []byte) []byte { return append([]byte{0}, value...) },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, decodeErr := Decode(mutate(append([]byte(nil), envelope...)), record.ChainID)
			require.ErrorIs(t, decodeErr, ErrInvalid)
		})
	}

	_, err = Decode(envelope, nil)
	require.ErrorIs(t, err, ErrInvalid)
	_, err = Decode(envelope, []byte("wrong-chain"))
	require.ErrorIs(t, err, ErrInvalid)
}

func TestEncodeRejectsInvalidFields(t *testing.T) {
	t.Parallel()

	tests := map[string]func(Record) Record{
		"wrong schema":       func(record Record) Record { record.SchemaVersion = 1; return record },
		"unknown provenance": func(record Record) Record { record.Provenance = 99; return record },
		"empty chain":        func(record Record) Record { record.ChainID = nil; return record },
		"empty header":       func(record Record) Record { record.HeaderBytes = nil; return record },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Encode(mutate(testRecord()))
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
}

func TestDecodeSuccessfulPathHasNoAllocations(t *testing.T) {
	record := testRecord()
	envelope, err := Encode(record)
	require.NoError(t, err)

	allocations := testing.AllocsPerRun(1000, func() {
		decoded, decodeErr := Decode(envelope, record.ChainID)
		if decodeErr != nil || len(decoded.HeaderBytes) != len(record.HeaderBytes) {
			panic("unexpected decode result")
		}
	})
	require.Zero(t, allocations, "successful decode must not allocate a second header-sized buffer")
}

func TestVersionedKeysAreEpochSeparatedAndDoNotAlias(t *testing.T) {
	t.Parallel()

	v2Epoch0 := Key(0)
	v2Epoch1 := Key(1)
	v1Epoch0 := LegacyKey(0)
	require.NotEqual(t, v2Epoch0, v2Epoch1)
	require.NotEqual(t, v2Epoch0, v1Epoch0)
	require.NotEqual(t, string(v2Epoch0), string(v1Epoch0))

	v2Epoch0[0] ^= 0xff
	require.Equal(t, []byte("DRWA/NETWORK-IDENTITY/v2/epoch/\x00\x00\x00\x00"), Key(0))
}

func TestErrInvalidRemainsTypedThroughAllCodecFailures(t *testing.T) {
	t.Parallel()

	_, err := Decode([]byte("short"), []byte("chain"))
	require.True(t, errors.Is(err, ErrInvalid))
}

func testRecord() Record {
	canonicalHash := [32]byte{}
	networkDomain := [32]byte{}
	for index := range canonicalHash {
		canonicalHash[index] = byte(index + 1)
		networkDomain[index] = byte(index + 33)
	}
	return Record{
		SchemaVersion: Version,
		Epoch:         17,
		Provenance:    EmergencyMigration,
		ChainID:       []byte("local-testnet"),
		CanonicalHash: canonicalHash,
		NetworkDomain: networkDomain,
		HeaderBytes:   []byte("canonical-metachain-header"),
	}
}
