package state_test

import (
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/stretchr/testify/require"
)

// An unpopulated local DTO must preserve the journal constructor's ordinary
// argument error. Only inert callbacks are used; no database is opened.
func TestQualSP281COrdinarySaveAccountMissingAddress(t *testing.T) {
	writes := 0
	adb := generateAccountDBFromTrie(&trieMock.TrieStub{
		GetCalled: func([]byte) ([]byte, uint32, error) { return nil, 0, nil },
		UpdateCalled: func(_, _ []byte) error {
			writes++
			return nil
		},
		GetStorageManagerCalled: func() common.StorageManager {
			return &storageManager.StorageManagerStub{}
		},
	})
	require.NotNil(t, adb)
	require.ErrorIs(t, adb.SaveAccount(stateMock.NewAccountWrapMock(nil)), state.ErrInvalidAddressLength)
	require.Zero(t, writes)
	require.Zero(t, adb.JournalLen())
}
