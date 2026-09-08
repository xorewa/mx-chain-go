package drwa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestDRWAReceiverGateRoundTripAndProtectedTokenKey(t *testing.T) {
	record := ReceiverGateRecord{
		Holder:            [32]byte{1},
		CEBEpoch:          9,
		Admitted:          true,
		ValidThroughRound: 100,
	}
	encoded, err := EncodeReceiverGateRecord(record)
	require.NoError(t, err)
	decoded, err := DecodeReceiverGateRecord(encoded)
	require.NoError(t, err)
	require.Equal(t, record, *decoded)

	tokenID := []byte("TOKEN-abcdef")
	key := ReceiverGateStorageKey(tokenID)
	require.True(t, bytes.HasPrefix(key, []byte(core.ProtectedKeyPrefix)))
	require.True(t, bytes.HasSuffix(key, tokenID))
	handler := &trieMock.DataTrieTrackerStub{RetrieveValueCalled: func(actual []byte) ([]byte, uint32, error) {
		require.Equal(t, key, actual)
		return encoded, 0, nil
	}}
	loaded, err := LoadReceiverGateRecord(handler, tokenID)
	require.NoError(t, err)
	require.Equal(t, record, *loaded)
}

func TestDRWAReceiverGateFailsClosed(t *testing.T) {
	_, err := DecodeReceiverGateRecord(make([]byte, 46))
	require.ErrorIs(t, err, ErrInvalidReceiverGate)
	handler := &trieMock.DataTrieTrackerStub{RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
		return nil, 0, nil
	}}
	_, err = LoadReceiverGateRecord(handler, []byte("TOKEN-abcdef"))
	require.ErrorIs(t, err, ErrReceiverGateNotFound)
}

func TestDRWAReceiverGateKeyIsDomainSeparatedAndInputBounded(t *testing.T) {
	tokenA := []byte("TOKEN-abcdef")
	tokenB := []byte("TOKEN-fedcba")
	keyA := ReceiverGateStorageKey(tokenA)
	keyB := ReceiverGateStorageKey(tokenB)
	require.NotEqual(t, keyA, keyB)
	require.NotEqual(t, keyA, OpenEffectStorageKey([32]byte{1}))
	require.NotEqual(t, keyA, append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenA...))
	require.False(t, vmcommon.IsAllowedToSaveUnderKey(keyA))

	called := false
	handler := &trieMock.DataTrieTrackerStub{RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
		called = true
		return nil, 0, nil
	}}
	_, err := LoadReceiverGateRecord(handler, []byte("invalid token"))
	require.ErrorIs(t, err, ErrInvalidReceiverGate)
	require.False(t, called)
}

func TestDRWAReceiverGatePreservesStorageFailure(t *testing.T) {
	injected := errors.New("receiver trie unavailable")
	handler := &trieMock.DataTrieTrackerStub{RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
		return nil, 0, injected
	}}
	_, err := LoadReceiverGateRecord(handler, []byte("TOKEN-abcdef"))
	require.ErrorIs(t, err, injected)
}
