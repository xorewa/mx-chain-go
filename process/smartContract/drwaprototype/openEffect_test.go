package drwaprototype

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

func TestOpenEffectPrototypeDeterministicFixture(t *testing.T) {
	t.Parallel()

	fixture := createOpenEffectFixture()
	encoded, err := EncodeOpenEffect(fixture)
	require.NoError(t, err)

	require.Equal(t, "020102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001000c544f4b454e2d616263646566012122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60000000078182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa06162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f800101", hex.EncodeToString(encoded))
	digest := sha256.Sum256(encoded)
	require.Equal(t, "cc8f0747dde4774d3f5a79db9078f34ab8e41094842f3166ea1d4f5196c86aa4", hex.EncodeToString(digest[:]))

	decoded, err := DecodeOpenEffect(encoded)
	require.NoError(t, err)
	require.Equal(t, fixture, *decoded)

	reencoded, err := EncodeOpenEffect(*decoded)
	require.NoError(t, err)
	require.Equal(t, encoded, reencoded)
}

func TestOpenEffectPrototypeDoesNotAliasCallerOrEncodedSlices(t *testing.T) {
	t.Parallel()

	fixture := createOpenEffectFixture()
	encoded, err := EncodeOpenEffect(fixture)
	require.NoError(t, err)
	encodedBeforeMutation := append([]byte(nil), encoded...)

	fixture.RegulatedTokenID[0] ^= 0xff
	require.Equal(t, encodedBeforeMutation, encoded)

	decoded, err := DecodeOpenEffect(encoded)
	require.NoError(t, err)
	decodedTokenID := append([]byte(nil), decoded.RegulatedTokenID...)
	for index := range encoded {
		encoded[index] ^= 0xff
	}
	require.Equal(t, decodedTokenID, decoded.RegulatedTokenID)
}

func TestEncodeOpenEffectPrototypeRejectsUnsupportedFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(effect *OpenEffect)
	}{
		{
			name: "unsupported effect kind",
			mutate: func(effect *OpenEffect) {
				effect.EffectKind = ValueEffectKind(2)
			},
		},
		{
			name: "empty token identifier",
			mutate: func(effect *OpenEffect) {
				effect.RegulatedTokenID = nil
			},
		},
		{
			name: "token identifier above prototype limit",
			mutate: func(effect *OpenEffect) {
				effect.RegulatedTokenID = make([]byte, prototypeTokenIDLimit+1)
			},
		},
		{
			name: "unsupported token type",
			mutate: func(effect *OpenEffect) {
				effect.RegulatedTokenType = TokenType(2)
			},
		},
		{
			name: "zero gas schedule identity",
			mutate: func(effect *OpenEffect) {
				clear(effect.GasScheduleIdentity[:])
			},
		},
		{
			name: "unsupported terminal kind",
			mutate: func(effect *OpenEffect) {
				effect.TerminalKind = OpenEffectTerminalKind(2)
			},
		},
		{
			name: "unsupported state",
			mutate: func(effect *OpenEffect) {
				effect.State = OpenEffectState(2)
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := createOpenEffectFixture()
			test.mutate(&fixture)
			_, err := EncodeOpenEffect(fixture)
			require.ErrorIs(t, err, ErrInvalidOpenEffect)
		})
	}
}

func TestDecodeOpenEffectPrototypeRejectsMalformedBytes(t *testing.T) {
	t.Parallel()

	fixture := createOpenEffectFixture()
	encoded, err := EncodeOpenEffect(fixture)
	require.NoError(t, err)
	offsets := openEffectFixtureOffsets(fixture)
	require.Equal(t, byte(fixture.EffectKind), encoded[offsets.effectKind])
	require.Equal(t, byte(fixture.RegulatedTokenType), encoded[offsets.tokenType])
	require.Equal(t, byte(fixture.TerminalKind), encoded[offsets.terminalKind])
	require.Equal(t, byte(fixture.State), encoded[offsets.state])

	tests := []struct {
		name   string
		mutate func(value []byte) []byte
	}{
		{
			name: "unsupported version",
			mutate: func(value []byte) []byte {
				value[0] = 3
				return value
			},
		},
		{
			name: "trailing byte",
			mutate: func(value []byte) []byte {
				return append(value, 0)
			},
		},
		{
			name: "token length above prototype limit",
			mutate: func(value []byte) []byte {
				value[offsets.tokenLength] = 0xff
				value[offsets.tokenLength+1] = 0xff
				return value
			},
		},
		{
			name: "empty token identifier",
			mutate: func(value []byte) []byte {
				value[offsets.tokenLength] = 0
				value[offsets.tokenLength+1] = 0
				tokenStart := offsets.tokenLength + 2
				return append(value[:tokenStart], value[tokenStart+len(fixture.RegulatedTokenID):]...)
			},
		},
		{
			name: "unsupported effect kind",
			mutate: func(value []byte) []byte {
				value[offsets.effectKind] = 2
				return value
			},
		},
		{
			name: "unsupported token type",
			mutate: func(value []byte) []byte {
				value[offsets.tokenType] = 2
				return value
			},
		},
		{
			name: "zero gas schedule identity",
			mutate: func(value []byte) []byte {
				clear(value[offsets.gasScheduleIdentity : offsets.gasScheduleIdentity+prototypeDigestLength])
				return value
			},
		},
		{
			name: "unsupported terminal kind",
			mutate: func(value []byte) []byte {
				value[offsets.terminalKind] = 2
				return value
			},
		},
		{
			name: "unsupported state",
			mutate: func(value []byte) []byte {
				value[offsets.state] = 2
				return value
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			mutated := test.mutate(append([]byte(nil), encoded...))
			_, err := DecodeOpenEffect(mutated)
			require.ErrorIs(t, err, ErrInvalidOpenEffect)
		})
	}
}

func TestDecodeOpenEffectPrototypeRejectsInputAboveTotalLimit(t *testing.T) {
	t.Parallel()

	_, err := DecodeOpenEffect(make([]byte, prototypeOpenEffectMaximumLength()+1))
	require.ErrorIs(t, err, ErrInvalidOpenEffect)
}

func TestDecodeOpenEffectPrototypeRejectsEveryTruncatedPrefix(t *testing.T) {
	t.Parallel()

	encoded, err := EncodeOpenEffect(createOpenEffectFixture())
	require.NoError(t, err)

	for prefixLength := 0; prefixLength < len(encoded); prefixLength++ {
		_, err = DecodeOpenEffect(encoded[:prefixLength])
		require.ErrorIsf(t, err, ErrInvalidOpenEffect, "prefix length %d", prefixLength)
	}
}

func TestOpenEffectStorageKeyIsFixedProtectedAndFresh(t *testing.T) {
	t.Parallel()

	fixture := createOpenEffectFixture()
	key := OpenEffectStorageKey(fixture.EffectID)
	expectedPrefix := core.ProtectedKeyPrefix + prototypeOpenEffectKeySuffix
	require.Equal(t, append([]byte(expectedPrefix), fixture.EffectID[:]...), key)
	require.Len(t, key, len(expectedPrefix)+prototypeDigestLength)
	require.False(t, vmcommon.IsAllowedToSaveUnderKey(key))

	key[0] ^= 0xff
	require.Equal(t, []byte(expectedPrefix), OpenEffectStorageKey(fixture.EffectID)[:len(expectedPrefix)])
}

func TestCreateAndLoadOpenEffectPrototype(t *testing.T) {
	t.Parallel()

	handler, stored := newOpenEffectMemoryHandler()
	fixture := createOpenEffectFixture()
	expected := createOpenEffectFixture()
	require.NoError(t, CreateOpenEffect(handler, fixture))

	fixture.RegulatedTokenID[0] ^= 0xff
	loaded, err := LoadOpenEffect(handler, expected.EffectID)
	require.NoError(t, err)
	require.Equal(t, expected, *loaded)

	storedBytes := stored[string(OpenEffectStorageKey(expected.EffectID))]
	loaded.RegulatedTokenID[0] ^= 0xff
	reloaded, err := LoadOpenEffect(handler, expected.EffectID)
	require.NoError(t, err)
	require.Equal(t, expected, *reloaded)
	require.NotEmpty(t, storedBytes)
}

func TestRemoveOpenEffectRequiresExistingExactRecord(t *testing.T) {
	t.Parallel()

	handler, _ := newOpenEffectMemoryHandler()
	fixture := createOpenEffectFixture()
	require.NoError(t, CreateOpenEffect(handler, fixture))
	require.NoError(t, RemoveOpenEffect(handler, fixture.EffectID))
	_, err := LoadOpenEffect(handler, fixture.EffectID)
	require.ErrorIs(t, err, ErrOpenEffectNotFound)
	require.ErrorIs(t, RemoveOpenEffect(handler, fixture.EffectID), ErrOpenEffectNotFound)
}

func TestCreateOpenEffectPrototypeRejectsDuplicateAndStorageFailures(t *testing.T) {
	t.Parallel()

	fixture := createOpenEffectFixture()
	handler, _ := newOpenEffectMemoryHandler()
	require.NoError(t, CreateOpenEffect(handler, fixture))
	require.ErrorIs(t, CreateOpenEffect(handler, fixture), ErrOpenEffectAlreadyExists)

	injectedRetrieve := errors.New("injected retrieve failure")
	retrieveFailure := &trieMock.DataTrieTrackerStub{
		RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
			return nil, 0, injectedRetrieve
		},
	}
	require.ErrorIs(t, CreateOpenEffect(retrieveFailure, fixture), injectedRetrieve)
	_, err := LoadOpenEffect(retrieveFailure, fixture.EffectID)
	require.ErrorIs(t, err, injectedRetrieve)

	injectedSave := errors.New("injected save failure")
	saveFailure := &trieMock.DataTrieTrackerStub{
		SaveKeyValueCalled: func(_ []byte, _ []byte) error {
			return injectedSave
		},
	}
	require.ErrorIs(t, CreateOpenEffect(saveFailure, fixture), injectedSave)

	var nilHandler *trieMock.DataTrieTrackerStub
	require.ErrorIs(t, CreateOpenEffect(nilHandler, fixture), ErrNilOpenEffectDataHandler)
	_, err = LoadOpenEffect(nilHandler, fixture.EffectID)
	require.ErrorIs(t, err, ErrNilOpenEffectDataHandler)
}

func TestLoadOpenEffectPrototypeRejectsAbsenceMalformedAndKeyMismatch(t *testing.T) {
	t.Parallel()

	fixture := createOpenEffectFixture()
	handler, stored := newOpenEffectMemoryHandler()
	_, err := LoadOpenEffect(handler, fixture.EffectID)
	require.ErrorIs(t, err, ErrOpenEffectNotFound)

	key := string(OpenEffectStorageKey(fixture.EffectID))
	stored[key] = []byte{0}
	_, err = LoadOpenEffect(handler, fixture.EffectID)
	require.ErrorIs(t, err, ErrInvalidOpenEffect)

	other := createOpenEffectFixture()
	other.EffectID[0] ^= 0xff
	stored[key], err = EncodeOpenEffect(other)
	require.NoError(t, err)
	_, err = LoadOpenEffect(handler, fixture.EffectID)
	require.ErrorIs(t, err, ErrInvalidOpenEffect)
}

type openEffectOffsets struct {
	effectKind          int
	tokenLength         int
	tokenType           int
	gasScheduleIdentity int
	terminalKind        int
	state               int
}

func openEffectFixtureOffsets(fixture OpenEffect) openEffectOffsets {
	effectKind := 1 + prototypeDigestLength
	tokenLength := effectKind + 1
	tokenType := tokenLength + 2 + len(fixture.RegulatedTokenID)
	gasScheduleIdentity := tokenType + 1 + prototypeDigestLength + prototypeAddressLength + 4
	terminalKind := gasScheduleIdentity + 2*prototypeDigestLength

	return openEffectOffsets{
		effectKind:          effectKind,
		tokenLength:         tokenLength,
		tokenType:           tokenType,
		gasScheduleIdentity: gasScheduleIdentity,
		terminalKind:        terminalKind,
		state:               terminalKind + 1,
	}
}

func createOpenEffectFixture() OpenEffect {
	effect := OpenEffect{
		EffectKind:         ValueEffectKindDirectTransfer,
		RegulatedTokenID:   []byte("TOKEN-abcdef"),
		RegulatedTokenType: TokenTypeFungible,
		CEBEpoch:           7,
		TerminalKind:       OpenEffectTerminalKindValueResult,
		State:              OpenEffectStatePendingDestination,
	}
	for index := range effect.EffectID {
		effect.EffectID[index] = byte(index + 1)
		effect.OriginExecutionIdentity[index] = byte(index + 33)
		effect.SourceSubject[index] = byte(index + 65)
		effect.ContextHash[index] = byte(index + 97)
		effect.GasScheduleIdentity[index] = byte(index + 129)
	}

	return effect
}

func newOpenEffectMemoryHandler() (*trieMock.DataTrieTrackerStub, map[string][]byte) {
	stored := make(map[string][]byte)
	handler := &trieMock.DataTrieTrackerStub{
		RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
			return append([]byte(nil), stored[string(key)]...), 0, nil
		},
		SaveKeyValueCalled: func(key []byte, value []byte) error {
			stored[string(append([]byte(nil), key...))] = append([]byte(nil), value...)
			return nil
		},
	}

	return handler, stored
}
