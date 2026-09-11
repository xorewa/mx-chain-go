package drwa

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestTerminalValueEvidenceRoundTripAndFinalizationCreatesReplayBarrier(t *testing.T) {
	effect := createOpenEffectFixture()
	result := []byte("canonical-terminal-result")
	evidence, err := BuildTerminalValueEvidence(effect, TerminalValueOutcomeSettled, result)
	require.NoError(t, err)

	encoded, err := EncodeTerminalValueEvidence(evidence)
	require.NoError(t, err)
	decoded, err := DecodeTerminalValueEvidence(encoded)
	require.NoError(t, err)
	require.Equal(t, evidence, *decoded)
	require.Len(t, encoded, 198)
	require.NoError(t, ValidateTerminalValueEvidenceResult(
		evidence,
		effect.EffectID,
		effect.ContextHash,
		TerminalValueOutcomeSettled,
		result,
	))
	require.ErrorIs(t, ValidateTerminalValueEvidenceResult(
		evidence,
		effect.EffectID,
		effect.ContextHash,
		TerminalValueOutcomeSettled,
		[]byte("different-result"),
	), ErrInvalidTerminalValueEvidence)

	handler, _ := newOpenEffectMemoryHandler()
	require.NoError(t, CreateOpenEffect(handler, effect))
	require.NoError(t, FinalizeOpenEffect(handler, effect, evidence))

	_, err = LoadOpenEffect(handler, effect.EffectID)
	require.ErrorIs(t, err, ErrOpenEffectNotFound)
	loaded, err := LoadTerminalValueEvidence(handler, effect.EffectID)
	require.NoError(t, err)
	require.Equal(t, evidence, *loaded)
	require.ErrorIs(t, CreateOpenEffect(handler, effect), ErrTerminalValueEvidenceAlreadyExists)
	require.ErrorIs(t, FinalizeOpenEffect(handler, effect, evidence), ErrTerminalValueEvidenceAlreadyExists)
}

func TestTerminalValueEvidenceDecodeAndKeyRejectMalformedState(t *testing.T) {
	effect := createOpenEffectFixture()
	evidence, err := BuildTerminalValueEvidence(effect, TerminalValueOutcomeSettled, []byte("result"))
	require.NoError(t, err)
	encoded, err := EncodeTerminalValueEvidence(evidence)
	require.NoError(t, err)

	for prefixLength := 0; prefixLength < len(encoded); prefixLength++ {
		_, err = DecodeTerminalValueEvidence(encoded[:prefixLength])
		require.ErrorIsf(t, err, ErrInvalidTerminalValueEvidence, "prefix length %d", prefixLength)
	}
	_, err = DecodeTerminalValueEvidence(append(append([]byte(nil), encoded...), 0))
	require.ErrorIs(t, err, ErrInvalidTerminalValueEvidence)

	mutations := []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "version", mutate: func(value []byte) { value[0]++ }},
		{name: "effect ID", mutate: func(value []byte) { clear(value[1 : 1+drwaDigestLength]) }},
		{name: "context hash", mutate: func(value []byte) { clear(value[33 : 33+drwaDigestLength]) }},
		{name: "origin identity", mutate: func(value []byte) { clear(value[65 : 65+drwaDigestLength]) }},
		{name: "source subject", mutate: func(value []byte) { clear(value[97 : 97+drwaAddressLength]) }},
		{name: "CEB epoch", mutate: func(value []byte) { clear(value[129:133]) }},
		{name: "gas identity", mutate: func(value []byte) { clear(value[133 : 133+drwaDigestLength]) }},
		{name: "outcome", mutate: func(value []byte) { value[165] = 0 }},
		{name: "result hash", mutate: func(value []byte) { clear(value[166 : 166+drwaDigestLength]) }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := append([]byte(nil), encoded...)
			mutation.mutate(mutated)
			_, decodeErr := DecodeTerminalValueEvidence(mutated)
			require.ErrorIs(t, decodeErr, ErrInvalidTerminalValueEvidence)
		})
	}

	key := TerminalValueEvidenceStorageKey(effect.EffectID)
	expectedPrefix := core.ProtectedKeyPrefix + drwaTerminalValueKeySuffix
	require.True(t, bytes.HasPrefix(key, []byte(expectedPrefix)))
	require.False(t, vmcommon.IsAllowedToSaveUnderKey(key))
	key[0] ^= 0xff
	require.Equal(t, []byte(expectedPrefix), TerminalValueEvidenceStorageKey(effect.EffectID)[:len(expectedPrefix)])
}

func TestTerminalValueEvidenceRejectsMismatchAndMalformedState(t *testing.T) {
	effect := createOpenEffectFixture()
	evidence, err := BuildTerminalValueEvidence(effect, TerminalValueOutcomeRefunded, []byte("refund"))
	require.NoError(t, err)

	t.Run("context mismatch", func(t *testing.T) {
		handler, _ := newOpenEffectMemoryHandler()
		require.NoError(t, CreateOpenEffect(handler, effect))
		mismatched := evidence
		mismatched.ContextHash[0] ^= 0xff
		require.ErrorIs(t, FinalizeOpenEffect(handler, effect, mismatched), ErrInvalidTerminalValueEvidence)
		_, err = LoadOpenEffect(handler, effect.EffectID)
		require.NoError(t, err)
	})

	t.Run("malformed retained barrier fails closed", func(t *testing.T) {
		stored := map[string][]byte{
			string(TerminalValueEvidenceStorageKey(effect.EffectID)): {0xff},
		}
		handler := &trieMock.DataTrieTrackerStub{
			RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
				return append([]byte(nil), stored[string(key)]...), 0, nil
			},
			SaveKeyValueCalled: func(key []byte, value []byte) error {
				stored[string(key)] = append([]byte(nil), value...)
				return nil
			},
		}
		require.ErrorIs(t, CreateOpenEffect(handler, effect), ErrTerminalValueEvidenceAlreadyExists)
		_, err = LoadTerminalValueEvidence(handler, effect.EffectID)
		require.ErrorIs(t, err, ErrInvalidTerminalValueEvidence)
	})
}
