package drwaprototype

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/stretchr/testify/require"
)

func TestPrototypeReceiverGateRoundTripAndProtectedTokenKey(t *testing.T) {
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

func TestPrototypeReceiverGateFailsClosed(t *testing.T) {
	_, err := DecodeReceiverGateRecord(make([]byte, 46))
	require.ErrorIs(t, err, ErrInvalidReceiverGate)
	handler := &trieMock.DataTrieTrackerStub{RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
		return nil, 0, nil
	}}
	_, err = LoadReceiverGateRecord(handler, []byte("TOKEN-abcdef"))
	require.ErrorIs(t, err, ErrReceiverGateNotFound)
}
