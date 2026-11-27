package sync

import (
	"io"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/multiversx/mx-chain-go/update"
	"github.com/multiversx/mx-chain-go/update/genesis"
	"github.com/multiversx/mx-chain-go/update/mock"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinarySyncLifecycle(t *testing.T) {
	root := []byte("ordinary-synthetic-root")
	const shard = uint32(0)
	id := genesis.CreateTrieIdentifier(shard, genesis.UserAccount)
	newHandler := func(t *testing.T, get func(string) (update.AccountsDBSyncer, error)) *syncAccountsDBs {
		t.Helper()
		h, err := NewSyncAccountsDBsHandler(ArgsNewSyncAccountsDBsHandler{AccountsDBsSyncers: &mock.AccountsDBSyncersStub{GetCalled: get}})
		require.NoError(t, err)
		return h
	}
	t.Run("cached ordinary fixture", func(t *testing.T) {
		h := newHandler(t, func(string) (update.AccountsDBSyncer, error) {
			t.Fatal("cached ordinary fixture must not request another syncer")
			return nil, nil
		})
		cached := &trieMock.TrieStub{RootCalled: func() ([]byte, error) { return root, nil }}
		h.tries.setTrie(id, cached)
		require.NoError(t, h.syncAccountsOfType(genesis.UserAccount, state.UserAccountsState, shard, root))
		got, ok := h.tries.getTrie(id)
		require.True(t, ok)
		require.Same(t, cached, got)
	})
	t.Run("ordinary container read error", func(t *testing.T) {
		h := newHandler(t, func(key string) (update.AccountsDBSyncer, error) {
			require.Equal(t, id, key)
			return nil, io.ErrUnexpectedEOF
		})
		require.ErrorIs(t, h.syncAccountsOfType(genesis.UserAccount, state.UserAccountsState, shard, root), io.ErrUnexpectedEOF)
		_, ok := h.tries.getTrie(id)
		require.False(t, ok)
	})
	t.Run("ordinary syncer read error", func(t *testing.T) {
		h := newHandler(t, func(key string) (update.AccountsDBSyncer, error) {
			require.Equal(t, id, key)
			return &mock.AccountsDBSyncerStub{
				SyncAccountsCalled: func(got []byte, _ common.StorageMarker) error {
					require.Equal(t, root, got)
					return io.ErrUnexpectedEOF
				},
				GetSyncedTriesCalled: func() map[string]common.Trie {
					t.Fatal("failed ordinary read must not publish mock results")
					return nil
				},
			}, nil
		})
		require.ErrorIs(t, h.syncAccountsOfType(genesis.UserAccount, state.UserAccountsState, shard, root), io.ErrUnexpectedEOF)
		_, ok := h.tries.getTrie(id)
		require.False(t, ok)
	})
	t.Run("ordinary mock result", func(t *testing.T) {
		result := &trieMock.TrieStub{}
		h := newHandler(t, func(key string) (update.AccountsDBSyncer, error) {
			require.Equal(t, id, key)
			return &mock.AccountsDBSyncerStub{
				SyncAccountsCalled: func(got []byte, _ common.StorageMarker) error {
					require.Equal(t, root, got)
					return nil
				},
				GetSyncedTriesCalled: func() map[string]common.Trie { return map[string]common.Trie{string(root): result} },
			}, nil
		})
		require.NoError(t, h.syncAccountsOfType(genesis.UserAccount, state.UserAccountsState, shard, root))
		got, ok := h.tries.getTrie(id)
		require.True(t, ok)
		require.Same(t, result, got)
	})
	t.Run("ordinary in-memory recreation", func(t *testing.T) {
		h := newHandler(t, func(string) (update.AccountsDBSyncer, error) {
			t.Fatal("successful in-memory fixture must not request another syncer")
			return nil, nil
		})
		commits := 0
		result := &trieMock.TrieStub{CommitCalled: func() error { commits++; return nil }}
		h.activeAccountsDBs[state.UserAccountsState] = &stateMock.AccountsStub{
			RecreateAllTriesCalled: func(got []byte) (map[string]common.Trie, error) {
				require.Equal(t, root, got)
				return map[string]common.Trie{string(root): result}, nil
			},
		}
		require.NoError(t, h.syncAccountsOfType(genesis.UserAccount, state.UserAccountsState, shard, root))
		require.Equal(t, 1, commits)
		got, ok := h.tries.getTrie(id)
		require.True(t, ok)
		require.Same(t, result, got)
	})
}
