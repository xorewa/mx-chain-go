package state_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/factory"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	testStorage "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/multiversx/mx-chain-go/trie/keyBuilder"
	storageFactory "github.com/multiversx/mx-chain-storage-go/factory"
	"github.com/stretchr/testify/require"
)

func qualA19OpenAccounts(t *testing.T, path string, decode state.ProtectedChildRoot, wrap func(common.BaseStorer) common.BaseStorer, checkpoints ...*state.ProtectedChildCheckpoints) (*state.AccountsDB, common.Trie, func()) {
	t.Helper()
	disk, err := storageunit.NewDB(storageFactory.ArgDB{
		DBType: storageunit.LvlDBSerial, Path: path,
		BatchDelaySeconds: 1, MaxBatchSize: 10, MaxOpenFiles: 10,
	})
	require.NoError(t, err)
	var store common.BaseStorer = disk
	if wrap != nil {
		store = wrap(disk)
	}
	adb, tr, _, closeState := qualA19AccountsOnStore(t, store, decode, checkpoints...)
	return adb, tr, closeState
}

func qualA19AccountsOnStore(t *testing.T, store common.BaseStorer, decode state.ProtectedChildRoot, checkpoints ...*state.ProtectedChildCheckpoints) (*state.AccountsDB, common.Trie, state.SnapshotsManager, func()) {
	t.Helper()
	args := createMockAccountsDBArgs()
	storageArgs := testStorage.GetStorageManagerArgs()
	storageArgs.MainStorer, storageArgs.Marshalizer, storageArgs.Hasher = store, args.Marshaller, args.Hasher
	storage, err := trie.NewTrieStorageManager(storageArgs)
	require.NoError(t, err)
	flags := &enableEpochsHandlerMock.EnableEpochsHandlerStub{}
	tr, err := trie.NewTrie(storage, args.Marshaller, args.Hasher, flags, 5)
	require.NoError(t, err)
	args.Trie = tr
	args.AccountFactory, err = factory.NewAccountCreator(factory.ArgsAccountCreator{
		Hasher: args.Hasher, Marshaller: args.Marshaller, EnableEpochsHandler: flags,
		StateAccessesCollector: args.StateAccessesCollector,
	})
	require.NoError(t, err)
	snapshotArgs := getDefaultSnapshotManagerArgs()
	snapshotArgs.ProcessingMode = common.ImportDb
	snapshotArgs.AccountFactory = args.AccountFactory
	snapshotArgs.Marshaller = args.Marshaller
	args.SnapshotsManager, err = state.NewSnapshotsManager(snapshotArgs)
	require.NoError(t, err)
	args.ProtectedChildRoot = decode
	if len(checkpoints) != 0 {
		owned := *checkpoints[0]
		owned.ReadNode = func(hash []byte, db common.TrieStorageInteractor) ([]common.TrieNodeData, error) {
			return trie.GetNodeDataFromHash(hash, keyBuilder.NewKeyBuilder(), db, args.Marshaller, args.Hasher)
		}
		args.ProtectedChildCheckpoints = &owned
	}
	adb, err := state.NewAccountsDB(args)
	require.NoError(t, err)
	closeState := func() {
		if !storage.IsClosed() {
			require.NoError(t, adb.Close())
			require.NoError(t, storage.Close())
		}
	}
	t.Cleanup(closeState)
	return adb, tr, args.SnapshotsManager, closeState
}

func TestQualDRWAA19CheckpointDiscoversProtectedChild(t *testing.T) {
	address := bytes.Repeat([]byte{1}, 32)
	key := []byte(core.ProtectedKeyPrefix + "fixture/a19/nonce-root")
	leaf := core.TrieData{Key: []byte("fixture-nonce"), Value: []byte("issued=5/live=0"), Version: core.NotSpecified}
	decode := func(owner, recordKey, record []byte) ([]byte, error) {
		if !bytes.Equal(owner, address) || !bytes.Equal(recordKey, key) || len(record) != 32 {
			return nil, errors.New("unavailable synthetic child locator")
		}
		return record, nil
	}
	var committed, committedChild []byte
	retention := &state.ProtectedChildCheckpoints{
		Locate: func(checkpoint common.RootHashHolder) ([]state.ProtectedChildLocator, error) {
			if !bytes.Equal(checkpoint.GetRootHash(), committed) {
				return nil, errors.New("unselected fixture checkpoint")
			}
			return []state.ProtectedChildLocator{{Address: address, Key: key, Record: committedChild}}, nil
		},
		Retained: func() ([]common.RootHashHolder, error) {
			return []common.RootHashHolder{holders.NewDefaultRootHashesHolder(committed)}, nil
		},
		MaxLocators: 1, MaxCheckpoints: 1, MaxBytes: 4096,
	}
	db := testscommon.NewSnapshotPruningStorerMock()
	adb, main, snapshots, _ := qualA19AccountsOnStore(t, db, decode, retention)
	require.NoError(t, snapshots.SetSyncer(&mock.AccountsDBSyncerStub{SyncAccountsCalled: func([]byte, common.StorageMarker) error {
		return errors.New("no fixture node transport")
	}}))
	account, err := adb.LoadAccount(address)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, common.EmptyTrieHash))
	require.NoError(t, adb.SaveAccount(account))
	_, err = adb.Commit()
	require.NoError(t, err)
	expected, err := main.Recreate(holders.NewDefaultRootHashesHolder(common.EmptyTrieHash))
	require.NoError(t, err)
	require.NoError(t, expected.Update(leaf.Key, leaf.Value))
	childRoot, err := expected.RootHash()
	require.NoError(t, err)
	committedChild = bytes.Clone(childRoot)
	require.NoError(t, adb.StageProtectedChildTrie(address, key, common.EmptyTrieHash, childRoot, []core.TrieData{leaf}))
	committed, err = adb.Commit()
	require.NoError(t, err)
	tries, err := adb.RecreateAllTries(committed)
	require.NoError(t, err)
	require.Contains(t, tries, string(childRoot), "the checkpoint walker must discover the protected child")
	got, _, err := tries[string(childRoot)].Get(leaf.Key)
	require.NoError(t, err)
	require.Equal(t, leaf.Value, got)

	adb.SnapshotState(committed, 0)
	require.Eventually(t, func() bool { return !snapshots.IsSnapshotInProgress() }, time.Second, time.Millisecond)
	active, err := db.Get([]byte(common.ActiveDBKey))
	require.NoError(t, err)
	require.Equal(t, []byte(common.ActiveDBVal), active)

	// Replacing the data under the same digest must fail independently of
	// native decoder validity. The protecting record itself stays unchanged.
	storage := main.GetStorageManager()
	node, err := storage.Get(childRoot)
	require.NoError(t, err)
	corrupt := bytes.Clone(node)
	corrupt[0] ^= 1
	require.NoError(t, storage.Put(childRoot, corrupt))
	_, err = adb.RecreateAllTries(committed)
	require.ErrorContains(t, err, "invalid protected child trie")
	require.NoError(t, storage.Remove(childRoot))
	_, err = adb.RecreateAllTries(committed)
	require.Error(t, err, "the same checkpoint with missing child data is unavailable")
	// Advance the native main checkpoint without changing the protected record,
	// then require the native snapshot readiness marker to stay absent.
	ordinary, err := adb.LoadAccount(bytes.Repeat([]byte{2}, 32))
	require.NoError(t, err)
	require.NoError(t, ordinary.(state.UserAccountHandler).SaveKeyValue([]byte("ordinary"), []byte("unchanged path")))
	require.NoError(t, adb.SaveAccount(ordinary))
	committed, err = adb.Commit()
	require.NoError(t, err)
	require.NoError(t, db.Remove([]byte(common.ActiveDBKey)))
	adb.SnapshotState(committed, 0)
	require.Eventually(t, func() bool { return !snapshots.IsSnapshotInProgress() }, time.Second, time.Millisecond)
	_, err = db.Get([]byte(common.ActiveDBKey))
	require.Error(t, err, "missing child must prevent the native active marker")
	require.NoError(t, storage.Put(childRoot, node))
	_, err = adb.RecreateAllTries(committed)
	require.NoError(t, err)
}

func TestQualDRWAA19ProtectedChildReopensFromNativeCommit(t *testing.T) {
	address := bytes.Repeat([]byte{1}, 32)
	recordKey := []byte(core.ProtectedKeyPrefix + "fixture/a19/nonce-root")
	childKey, history := []byte("fixture-nonce"), []byte("issued=5/live=0")
	if path := os.Getenv("DRWA_QUAL_A19_REOPEN"); path != "" {
		checkpoint, err := hex.DecodeString(os.Getenv("DRWA_QUAL_A19_CHECKPOINT"))
		require.NoError(t, err)
		childRoot, err := hex.DecodeString(os.Getenv("DRWA_QUAL_A19_CHILD"))
		require.NoError(t, err)
		laterRoot, err := hex.DecodeString(os.Getenv("DRWA_QUAL_A19_ROLLED_BACK"))
		require.NoError(t, err)
		cold, _, _ := qualA19OpenAccounts(t, path, nil, nil)
		require.NoError(t, cold.RecreateTrie(holders.NewDefaultRootHashesHolder(checkpoint)))
		loaded, err := cold.GetExistingAccount(address)
		require.NoError(t, err)
		root, _, err := loaded.(state.UserAccountHandler).RetrieveValue(recordKey)
		require.NoError(t, err)
		require.Equal(t, childRoot, root, "the protected reference was persisted")
		reopened, err := cold.GetTrie(root)
		require.NoError(t, err, "the same native commit must persist the referenced child nodes")
		got, _, err := reopened.Get(childKey)
		require.NoError(t, err)
		require.Equal(t, history, got)
		_, err = cold.GetTrie(laterRoot)
		require.Error(t, err, "rolled-back root never reached durable storage")
		require.Error(t, cold.StageProtectedChildTrie(address, recordKey, childRoot, laterRoot,
			[]core.TrieData{{Key: childKey, Value: history, Version: core.NotSpecified}}), "unconfigured owner must reject")
		return
	}
	path := filepath.Join(t.TempDir(), "state")
	// This test-only record is a root by itself. It selects no protected
	// grammar, profile, or amount for production.
	decode := func(owner, key, record []byte) ([]byte, error) {
		if !bytes.Equal(owner, address) || !bytes.Equal(key, recordKey) || len(record) != 32 {
			return nil, errors.New("unavailable synthetic child locator")
		}
		return record, nil
	}
	adb, main, closeState := qualA19OpenAccounts(t, path, decode, nil)

	account, err := adb.LoadAccount(address)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(recordKey, common.EmptyTrieHash))
	require.NoError(t, adb.SaveAccount(account))
	_, err = adb.Commit()
	require.NoError(t, err)

	detached, err := main.Recreate(holders.NewDefaultRootHashesHolder(common.EmptyTrieHash))
	require.NoError(t, err)
	require.NoError(t, detached.Update(childKey, history))
	childRoot, err := detached.RootHash()
	require.NoError(t, err)
	require.NoError(t, adb.StageProtectedChildTrie(address, recordKey, common.EmptyTrieHash, childRoot,
		[]core.TrieData{{Key: childKey, Value: history, Version: core.NotSpecified}}))

	// Roll back a later update on the same staged child, while retaining the
	// first effect. The second operation has an independently computed root.
	journal := adb.JournalLen()
	more := []byte("issued=6/live=1")
	require.NoError(t, detached.Update(childKey, more))
	laterRoot, err := detached.RootHash()
	require.NoError(t, err)
	require.NoError(t, adb.StageProtectedChildTrie(address, recordKey, childRoot, laterRoot,
		[]core.TrieData{{Key: childKey, Value: more, Version: core.NotSpecified}}))
	require.NoError(t, adb.RevertToSnapshot(journal))

	checkpoint, err := adb.Commit()
	require.NoError(t, err)
	closeState()

	// A second copy of the same test binary opens the disk without inheriting
	// any cached trie, account or native database objects.
	exe, err := os.Executable()
	require.NoError(t, err)
	reopen := exec.CommandContext(t.Context(), exe, "-test.run=^TestQualDRWAA19ProtectedChildReopensFromNativeCommit$", "-test.timeout=30s")
	reopen.Env = append(os.Environ(),
		"DRWA_QUAL_A19_REOPEN="+path,
		"DRWA_QUAL_A19_CHECKPOINT="+hex.EncodeToString(checkpoint),
		"DRWA_QUAL_A19_CHILD="+hex.EncodeToString(childRoot),
		"DRWA_QUAL_A19_ROLLED_BACK="+hex.EncodeToString(laterRoot),
	)
	output, err := reopen.CombinedOutput()
	require.NoError(t, err, "%s", output)
}

func TestQualDRWAA19OrdinaryAccountIgnoresChildBinding(t *testing.T) {
	var baseline []byte
	for _, enabled := range []bool{false, true} {
		var binding state.ProtectedChildRoot
		if enabled {
			binding = func(_, _, _ []byte) ([]byte, error) {
				t.Fatal("ordinary account invoked the protected decoder")
				return nil, nil
			}
		}
		adb, _, _ := qualA19OpenAccounts(t, filepath.Join(t.TempDir(), "ordinary"), binding, nil)
		address := bytes.Repeat([]byte{2}, 32)
		owner, err := adb.LoadAccount(address)
		require.NoError(t, err)
		require.NoError(t, owner.(state.UserAccountHandler).SaveKeyValue([]byte("ordinary"), []byte("value")))
		require.NoError(t, adb.SaveAccount(owner))
		root, err := adb.Commit()
		require.NoError(t, err)
		if enabled {
			require.Equal(t, baseline, root)
		} else {
			baseline = bytes.Clone(root)
		}
		require.NoError(t, adb.RecreateTrieIfNeeded(holders.NewDefaultRootHashesHolder(root)))
		got, err := adb.GetExistingAccount(address)
		require.NoError(t, err)
		value, _, err := got.(state.UserAccountHandler).RetrieveValue([]byte("ordinary"))
		require.NoError(t, err)
		require.Equal(t, []byte("value"), value)
		require.Zero(t, adb.JournalLen())
	}
}

type qualA19FaultStore struct {
	common.BaseStorer
	failAt []byte
	err    error
}

func (s *qualA19FaultStore) Put(key, value []byte) error {
	if bytes.Equal(key, s.failAt) {
		return s.err
	}
	return s.BaseStorer.Put(key, value)
}

func TestQualDRWAA19ParentCommitFailureKeepsOriginalCause(t *testing.T) {
	address := bytes.Repeat([]byte{1}, 32)
	key := []byte(core.ProtectedKeyPrefix + "fixture/a19/nonce-root")
	leaf := core.TrieData{Key: []byte("fixture-nonce"), Value: []byte("issued=5/live=0"), Version: core.NotSpecified}
	decode := func(owner, recordKey, record []byte) ([]byte, error) {
		if !bytes.Equal(owner, address) || !bytes.Equal(recordKey, key) || len(record) != 32 {
			return nil, errors.New("unavailable synthetic child locator")
		}
		return record, nil
	}
	fault := &qualA19FaultStore{err: errors.New("synthetic disk error on main root")}
	adb, main, _ := qualA19OpenAccounts(t, filepath.Join(t.TempDir(), "fault"), decode, func(store common.BaseStorer) common.BaseStorer {
		fault.BaseStorer = store
		return fault
	})
	account, err := adb.LoadAccount(address)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, common.EmptyTrieHash))
	require.NoError(t, adb.SaveAccount(account))
	original, err := adb.Commit()
	require.NoError(t, err)

	detached, err := main.Recreate(holders.NewDefaultRootHashesHolder(common.EmptyTrieHash))
	require.NoError(t, err)
	require.NoError(t, detached.Update(leaf.Key, leaf.Value))
	childRoot, err := detached.RootHash()
	require.NoError(t, err)
	require.NoError(t, adb.StageProtectedChildTrie(address, key, common.EmptyTrieHash, childRoot, []core.TrieData{leaf}))
	proposed, err := adb.RootHash()
	require.NoError(t, err)
	fault.failAt = proposed
	root, err := adb.Commit()
	require.ErrorIs(t, err, fault.err)
	require.Nil(t, root)
	_, err = adb.GetTrie(childRoot)
	require.NoError(t, err, "the child reached the disk before main-state publication failed")
	_, err = adb.GetTrie(proposed)
	require.Error(t, err, "the proposed checkpoint is unavailable")
	fault.failAt = nil
	_, err = adb.Commit()
	require.ErrorIs(t, err, fault.err, "a second commit must not retry partial persistence")
	observed, err := adb.ReadProtectedChildLeaves(address, key, childRoot, [][]byte{leaf.Key})
	require.ErrorIs(t, err, fault.err, "persisted child bytes cannot authorize a read after the owning commit failed")
	require.Nil(t, observed)
	require.ErrorIs(t, adb.RevertToSnapshot(0), fault.err)
	require.NoError(t, adb.RecreateTrieIfNeeded(holders.NewDefaultRootHashesHolder(original)))
	restored, err := adb.GetExistingAccount(address)
	require.NoError(t, err)
	got, _, err := restored.(state.UserAccountHandler).RetrieveValue(key)
	require.NoError(t, err)
	require.Equal(t, common.EmptyTrieHash, got)
	require.Zero(t, adb.JournalLen())
}
