package state_test

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/accounts"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// These are observations of the native AccountsDB lifecycle, not a DRWA
// projection implementation or proof of cross-shard membership delivery.
func TestQualDRWARecreateJournalBoundary(t *testing.T) {
	for _, kind := range []string{"equal_root", "different_root", "recreate_error", "nil_recreated_trie", "root_error"} {
		t.Run(kind, func(t *testing.T) {
			nativeErr := errors.New("injected trie boundary error")
			current, selected := []byte("current"), []byte("selected")
			if kind == "equal_root" {
				selected = current
			}
			var roots [][]byte
			resets, undos := 0, 0
			tr := &trieMock.TrieStub{}
			tr.RootCalled = func() ([]byte, error) {
				if kind == "root_error" {
					return nil, nativeErr
				}
				return current, nil
			}
			tr.RecreateCalled = func(h common.RootHashHolder) (common.Trie, error) {
				roots = append(roots, append([]byte(nil), h.GetRootHash()...))
				if kind == "recreate_error" {
					return nil, nativeErr
				}
				if kind == "nil_recreated_trie" {
					return nil, nil
				}
				return tr, nil
			}
			args := createMockAccountsDBArgs()
			tr.GetStorageManagerCalled = args.Trie.GetStorageManager
			args.Trie = tr
			args.StateAccessesCollector = &stateMock.StateAccessesCollectorStub{ResetCalled: func() { resets++ }}
			adb, err := state.NewAccountsDB(args)
			require.NoError(t, err)
			adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) { undos++; return nil, nil }})
			err = adb.RecreateTrieIfNeeded(holders.NewDefaultRootHashesHolder(selected))
			switch kind {
			case "recreate_error", "root_error":
				require.ErrorIs(t, err, nativeErr)
			case "nil_recreated_trie":
				require.ErrorIs(t, err, state.ErrNilTrie)
			default:
				require.NoError(t, err)
			}
			require.Zero(t, undos, "recreation does not execute individual journal undo entries")
			if kind == "equal_root" || kind == "root_error" {
				require.Equal(t, 1, adb.JournalLen())
				require.Zero(t, resets)
				require.Empty(t, roots)
			} else {
				require.Zero(t, adb.JournalLen())
				require.Equal(t, 1, resets)
				require.Equal(t, [][]byte{selected}, roots)
			}
			if kind == "equal_root" {
				// Equal-root success still installs lastRootHash. Snapshot zero takes the
				// unconditional recreation route and clears the previously retained journal.
				require.NoError(t, adb.RevertToSnapshot(0))
				require.Equal(t, [][]byte{current}, roots)
				require.Zero(t, adb.JournalLen())
				require.Equal(t, 1, resets)
				require.Zero(t, undos)
			}
		})
	}
}

func TestQualDRWACollectorRollbackAfterJournalUndo(t *testing.T) {
	nativeErr := errors.New("injected collector rollback error")
	var order []string
	collectorCalls := 0
	args := createMockAccountsDBArgs()
	args.StateAccessesCollector = &stateMock.StateAccessesCollectorStub{RevertToIndexCalled: func(index int) error {
		require.Equal(t, 1, index)
		order = append(order, "collector")
		collectorCalls++
		if collectorCalls == 1 {
			return nativeErr
		}
		return nil
	}}
	adb, err := state.NewAccountsDB(args)
	require.NoError(t, err)
	adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) { t.Fatal("earlier entry must survive"); return nil, nil }})
	adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) { order = append(order, "undo"); return nil, nil }})
	require.ErrorIs(t, adb.RevertToSnapshot(1), nativeErr)
	require.Equal(t, 1, adb.JournalLen())
	require.Equal(t, []string{"undo", "collector"}, order)
	require.NoError(t, adb.RevertToSnapshot(1))
	require.Equal(t, 1, adb.JournalLen())
	require.Equal(t, []string{"undo", "collector", "collector"}, order)
}

func TestQualDRWACommitJournalAndLastRootBoundary(t *testing.T) {
	for _, kind := range []string{"trie_error", "root_error", "collector_error", "success"} {
		t.Run(kind, func(t *testing.T) {
			nativeErr := errors.New("injected commit boundary error")
			oldRoot, newRoot := []byte("old"), []byte("new")
			var order []string
			var recreated [][]byte
			tr := &trieMock.TrieStub{}
			tr.RecreateCalled = func(h common.RootHashHolder) (common.Trie, error) {
				recreated = append(recreated, append([]byte(nil), h.GetRootHash()...))
				return tr, nil
			}
			tr.CommitCalled = func() error {
				order = append(order, "trie")
				if kind == "trie_error" {
					return nativeErr
				}
				return nil
			}
			tr.RootCalled = func() ([]byte, error) {
				order = append(order, "root")
				if kind == "root_error" {
					return nil, nativeErr
				}
				return newRoot, nil
			}
			args := createMockAccountsDBArgs()
			tr.GetStorageManagerCalled = args.Trie.GetStorageManager
			args.Trie = tr
			args.StateAccessesCollector = &stateMock.StateAccessesCollectorStub{CommitCollectedAccessesCalled: func(root []byte) error {
				require.Equal(t, newRoot, root)
				order = append(order, "collector")
				if kind == "collector_error" {
					return nativeErr
				}
				return nil
			}}
			adb, err := state.NewAccountsDB(args)
			require.NoError(t, err)
			require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(oldRoot)))
			adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) {
				t.Fatal("commit cleared individual undo entries")
				return nil, nil
			}})
			root, err := adb.Commit()
			if kind == "success" {
				require.NoError(t, err)
				require.Equal(t, newRoot, root)
			} else {
				require.ErrorIs(t, err, nativeErr)
				require.Nil(t, root)
			}
			require.Zero(t, adb.JournalLen(), "empty journal is not proof of commit success")
			expected := []string{"trie"}
			if kind != "trie_error" {
				expected = append(expected, "root")
			}
			if kind == "collector_error" || kind == "success" {
				expected = append(expected, "collector")
			}
			require.Equal(t, expected, order)
			require.NoError(t, adb.RevertToSnapshot(0))
			last := oldRoot
			if kind == "success" {
				last = newRoot
			}
			require.Equal(t, [][]byte{oldRoot, last}, recreated, "failed commit cannot advance lastRootHash")
		})
	}
}

// The native TrieStub does not expose a dirty-hash error callback. Keep this
// override in the qualification file instead of adding a production test seam.
type qualDirtyHashTrie struct {
	*trieMock.TrieStub
	dirty func() (common.ModifiedHashes, error)
}

func (q *qualDirtyHashTrie) GetDirtyHashes() (common.ModifiedHashes, error) { return q.dirty() }

func TestQualDRWACommitDataTrieAndEvictionFailures(t *testing.T) {
	for _, kind := range []string{"data_hash_error", "data_commit_error", "main_hash_error", "eviction_error", "success"} {
		t.Run(kind, func(t *testing.T) {
			nativeErr := errors.New("injected additional commit error")
			oldRoot, newRoot, dataRoot := []byte("old"), []byte("new"), []byte("data")
			var order []string
			var recreated [][]byte
			main := &qualDirtyHashTrie{TrieStub: &trieMock.TrieStub{}}
			child := &qualDirtyHashTrie{TrieStub: &trieMock.TrieStub{}}
			main.dirty = func() (common.ModifiedHashes, error) {
				order = append(order, "main_hash")
				if kind == "main_hash_error" {
					return nil, nativeErr
				}
				return common.ModifiedHashes{"main": {}}, nil
			}
			child.dirty = func() (common.ModifiedHashes, error) {
				order = append(order, "data_hash")
				if kind == "data_hash_error" {
					return nil, nativeErr
				}
				return common.ModifiedHashes{"data": {}}, nil
			}
			child.CommitCalled = func() error {
				order = append(order, "data_commit")
				if kind == "data_commit_error" {
					return nativeErr
				}
				return nil
			}
			main.CommitCalled = func() error { order = append(order, "main_commit"); return nil }
			main.RootCalled = func() ([]byte, error) { order = append(order, "root"); return newRoot, nil }
			main.GetOldRootCalled = func() []byte { return oldRoot }
			main.RecreateCalled = func(h common.RootHashHolder) (common.Trie, error) {
				if string(h.GetRootHash()) == string(dataRoot) {
					return child, nil
				}
				recreated = append(recreated, append([]byte(nil), h.GetRootHash()...))
				return main, nil
			}
			args := createMockAccountsDBArgs()
			main.GetStorageManagerCalled = args.Trie.GetStorageManager
			args.Trie = main
			args.PruningEnabled = true
			args.StoragePruningManager = &stateMock.StoragePruningManagerStub{MarkForEvictionCalled: func(old, next []byte, _, changed common.ModifiedHashes) error {
				order = append(order, "eviction")
				require.Equal(t, oldRoot, old)
				require.Equal(t, newRoot, next)
				require.Equal(t, common.ModifiedHashes{"main": {}, "data": {}}, changed)
				if kind == "eviction_error" {
					return nativeErr
				}
				return nil
			}}
			args.StateAccessesCollector = &stateMock.StateAccessesCollectorStub{CommitCollectedAccessesCalled: func(root []byte) error {
				require.Equal(t, newRoot, root)
				order = append(order, "collector")
				return nil
			}}
			adb, err := state.NewAccountsDB(args)
			require.NoError(t, err)
			require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(oldRoot)))
			account, err := accounts.NewUserAccount([]byte("account"), &trieMock.DataTrieTrackerStub{}, &trieMock.TrieLeafParserStub{})
			require.NoError(t, err)
			account.SetRootHash(dataRoot)
			require.NoError(t, adb.LoadDataTrieConcurrentSafe(account))
			require.Same(t, child, account.DataTrie())
			adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) { t.Fatal("commit must clear journal"); return nil, nil }})
			root, err := adb.Commit()
			if kind == "success" {
				require.NoError(t, err)
				require.Equal(t, newRoot, root)
			} else {
				require.ErrorIs(t, err, nativeErr)
				require.Nil(t, root)
			}
			require.Zero(t, adb.JournalLen())
			expected := map[string][]string{
				"data_hash_error":   {"data_hash"},
				"data_commit_error": {"data_hash", "data_commit"},
				"main_hash_error":   {"data_hash", "data_commit", "main_hash"},
				"eviction_error":    {"data_hash", "data_commit", "main_hash", "main_commit", "root", "collector", "eviction"},
				"success":           {"data_hash", "data_commit", "main_hash", "main_commit", "root", "collector", "eviction"},
			}
			require.Equal(t, expected[kind], order)
			require.NoError(t, adb.RevertToSnapshot(0))
			last := oldRoot
			if kind == "success" {
				last = newRoot
			}
			require.Equal(t, [][]byte{oldRoot, last}, recreated)
		})
	}
}
