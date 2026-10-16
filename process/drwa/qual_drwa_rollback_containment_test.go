package drwa

import (
	"bytes"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/state"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/factory"
	"github.com/multiversx/mx-chain-go/state/storagePruningManager"
	pruningDisabled "github.com/multiversx/mx-chain-go/state/storagePruningManager/disabled"
	"github.com/multiversx/mx-chain-go/state/storagePruningManager/evictionWaitingList"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/multiversx/mx-chain-go/trie"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Faults replace only specified native boundaries. All other account semantics
// are the real pinned AccountsDB over a real trie and a memory backing store.
type qualNativeStore struct {
	state.AccountsAdapter
	backing                                    *testscommon.MemDbMock
	revertErr, recreateErr, commitErr, saveErr error
	reverts, recreates, commits                int
}

func (s *qualNativeStore) RevertToSnapshot(n int) error {
	s.reverts++
	if s.revertErr != nil {
		return s.revertErr
	}
	return s.AccountsAdapter.RevertToSnapshot(n)
}
func (s *qualNativeStore) RecreateTrie(root common.RootHashHolder) error {
	s.recreates++
	if s.recreateErr != nil {
		return s.recreateErr
	}
	return s.AccountsAdapter.RecreateTrie(root)
}
func (s *qualNativeStore) Commit() ([]byte, error) {
	s.commits++
	if s.commitErr != nil {
		return nil, s.commitErr
	}
	return s.AccountsAdapter.Commit()
}
func (s *qualNativeStore) SaveAccount(account vmcommon.AccountHandler) error {
	if err := s.AccountsAdapter.SaveAccount(account); err != nil {
		return err
	}
	return s.saveErr
}

func qualContainmentArgs(t *testing.T) (state.ArgsAccountsDB, *testscommon.MemDbMock) {
	t.Helper()
	db := testscommon.NewMemDbMock()
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	mar, hash := &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b()
	storage := &storageManager.StorageManagerStub{
		GetCalled: db.Get, GetFromCurrentEpochCalled: db.Get, PutCalled: db.Put,
		GetStateStatsHandlerCalled: db.GetStateStatsHandler, GetIdentifierCalled: db.GetIdentifier,
	}
	tr, err := trie.NewTrie(storage, mar, hash, flags, 5)
	require.NoError(t, err)
	collector := stateDisabled.NewDisabledStateAccessesCollector()
	f, err := factory.NewAccountCreator(factory.ArgsAccountCreator{
		Hasher: hash, Marshaller: mar, EnableEpochsHandler: flags, StateAccessesCollector: collector,
	})
	require.NoError(t, err)
	return state.ArgsAccountsDB{
		Trie: tr, Hasher: hash, Marshaller: mar, AccountFactory: f,
		StateAccessesCollector: collector,
		StoragePruningManager:  pruningDisabled.NewDisabledStoragePruningManager(),
		SnapshotsManager:       stateDisabled.NewDisabledSnapshotsManager(),
		AddressConverter:       &testscommon.PubkeyConverterMock{},
	}, db
}

func qualContainmentStore(t *testing.T) *qualNativeStore {
	t.Helper()
	args, db := qualContainmentArgs(t)
	adb, err := state.NewAccountsDB(args)
	require.NoError(t, err)
	s := &qualNativeStore{AccountsAdapter: adb, backing: db}
	require.NoError(t, qualContainmentBalance(s, 100))
	_, err = adb.Commit()
	require.NoError(t, err)
	return s
}

var qualContainmentAddress = bytes.Repeat([]byte{1}, 32)

func qualContainmentBalance(s *qualNativeStore, balance int64) error {
	account, err := s.LoadAccount(qualContainmentAddress)
	if err != nil {
		return err
	}
	user := account.(state.UserAccountHandler)
	if err = user.AddToBalance(new(big.Int).Sub(big.NewInt(balance), user.GetBalance())); err != nil {
		return err
	}
	if err = user.SaveKeyValue([]byte("fixture/protocol-record"), []byte{byte(balance)}); err != nil {
		return err
	}
	return s.SaveAccount(user)
}

func qualAssertContainmentBalance(t *testing.T, s *qualNativeStore, balance int64) {
	t.Helper()
	a, err := s.GetExistingAccount(qualContainmentAddress)
	require.NoError(t, err)
	user := a.(state.UserAccountHandler)
	require.Equal(t, big.NewInt(balance), user.GetBalance())
	v, _, err := user.RetrieveValue([]byte("fixture/protocol-record"))
	require.NoError(t, err)
	require.Equal(t, []byte{byte(balance)}, v)
}

func TestQualDRWANativeContainment(t *testing.T) {
	for _, boundary := range []string{"mutation", "sender_save", "receiver_save"} {
		for _, failedRollback := range []bool{false, true} {
			name := boundary + "/healthy_rollback"
			if failedRollback {
				name = boundary + "/failed_rollback"
			}
			t.Run(name, func(t *testing.T) {
				sender, receiver := qualContainmentStore(t), qualContainmentStore(t)
				c, err := NewRollbackContainment(sender, receiver)
				require.NoError(t, err)
				prior := &vmcommon.VMOutput{ReturnData: [][]byte{[]byte("prior")}}
				require.NoError(t, c.Execute(func() (*vmcommon.VMOutput, error) {
					require.NoError(t, qualContainmentBalance(sender, 90))
					return prior, nil
				}))
				original, rollback := errors.New("operation fault"), errors.New("rollback fault")
				if failedRollback {
					sender.revertErr = rollback
				}
				if boundary == "sender_save" {
					sender.saveErr = original
				}
				if boundary == "receiver_save" {
					receiver.saveErr = original
				}
				err = c.Execute(func() (*vmcommon.VMOutput, error) {
					if save := qualContainmentBalance(sender, 70); save != nil {
						return nil, save
					}
					if save := qualContainmentBalance(receiver, 130); save != nil {
						return nil, save
					}
					return &vmcommon.VMOutput{ReturnData: [][]byte{[]byte("must not leak")}}, original
				})
				require.ErrorIs(t, err, original)
				require.Equal(t, 1, sender.reverts)
				require.Equal(t, 1, receiver.reverts)
				if !failedRollback {
					require.Same(t, original, err)
					qualAssertContainmentBalance(t, sender, 90)
					qualAssertContainmentBalance(t, receiver, 100)
					sender.saveErr, receiver.saveErr = nil, nil
					_, outputs, commitErr := c.Commit()
					require.NoError(t, commitErr)
					require.Equal(t, []*vmcommon.VMOutput{prior}, outputs)
					return
				}
				require.ErrorIs(t, err, rollback)
				called := false
				require.ErrorIs(t, c.Execute(func() (*vmcommon.VMOutput, error) { called = true; return nil, nil }), rollback)
				require.False(t, called)
				roots, outputs, commitErr := c.Commit()
				require.ErrorIs(t, commitErr, rollback)
				require.Nil(t, roots)
				require.Nil(t, outputs)
				require.Zero(t, sender.commits)
				require.Zero(t, receiver.commits)
				recovery := errors.New("reconstruction fault")
				receiver.recreateErr = recovery
				require.ErrorIs(t, c.Recover(), recovery)
				require.Equal(t, 1, sender.recreates)
				require.Equal(t, 1, receiver.recreates)
				require.ErrorIs(t, c.Execute(func() (*vmcommon.VMOutput, error) { called = true; return nil, nil }), rollback)
				require.False(t, called)
				receiver.recreateErr = nil
				require.NoError(t, c.Recover())
				qualAssertContainmentBalance(t, sender, 100)
				qualAssertContainmentBalance(t, receiver, 100)
				require.ErrorIs(t, c.Execute(func() (*vmcommon.VMOutput, error) { called = true; return nil, nil }), ErrExecutionClosed)
				require.False(t, called)
				require.ErrorIs(t, func() error { _, _, e := c.Commit(); return e }(), ErrExecutionClosed)
			})
		}
	}
}

func TestQualDRWANativeContainmentZeroSnapshot(t *testing.T) {
	s := qualContainmentStore(t)
	c, err := NewRollbackContainment(s)
	require.NoError(t, err)
	original, rollback := errors.New("nested mutation fault"), errors.New("zero snapshot fault")
	s.revertErr = rollback
	err = c.Execute(func() (*vmcommon.VMOutput, error) {
		require.NoError(t, qualContainmentBalance(s, 60))
		// A nested native mutation shares the outer operation's journal scope.
		return func() (*vmcommon.VMOutput, error) {
			require.NoError(t, qualContainmentBalance(s, 50))
			return nil, original
		}()
	})
	require.ErrorIs(t, err, original)
	require.ErrorIs(t, err, rollback)
	qualAssertContainmentBalance(t, s, 50)
	require.NoError(t, c.Recover())
	qualAssertContainmentBalance(t, s, 100)
	require.Equal(t, 1, s.recreates)
	fresh, err := NewRollbackContainment(s)
	require.NoError(t, err)
	require.NoError(t, fresh.Execute(func() (*vmcommon.VMOutput, error) { return nil, qualContainmentBalance(s, 80) }))
	_, _, err = fresh.Commit()
	require.NoError(t, err)
	qualAssertContainmentBalance(t, s, 80)
}

func TestQualDRWANativeContainmentConcurrentAndPanic(t *testing.T) {
	s := qualContainmentStore(t)
	c, err := NewRollbackContainment(s)
	require.NoError(t, err)
	entered, finish := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = c.Execute(func() (*vmcommon.VMOutput, error) { close(entered); <-finish; return nil, nil })
	}()
	<-entered
	called := false
	require.ErrorIs(t, c.Execute(func() (*vmcommon.VMOutput, error) { called = true; return nil, nil }), ErrExecutionBusy)
	_, _, err = c.Commit()
	require.ErrorIs(t, err, ErrExecutionBusy)
	require.ErrorIs(t, c.Recover(), ErrExecutionBusy)
	require.False(t, called)
	close(finish)
	wg.Wait()
	require.PanicsWithValue(t, "native panic", func() {
		_ = c.Execute(func() (*vmcommon.VMOutput, error) { panic("native panic") })
	})
	_, outputs, err := c.Commit()
	require.ErrorIs(t, err, ErrExecutionInterrupted)
	require.Nil(t, outputs)
}

func TestQualDRWANativeContainmentInvalidAndCommitFailure(t *testing.T) {
	_, err := NewRollbackContainment()
	require.ErrorIs(t, err, state.ErrNilAccountsAdapter)
	_, err = NewRollbackContainment((*state.AccountsDB)(nil))
	require.ErrorIs(t, err, state.ErrNilAccountsAdapter)
	s := qualContainmentStore(t)
	require.NoError(t, qualContainmentBalance(s, 80))
	_, err = NewRollbackContainment(s)
	require.ErrorIs(t, err, ErrUncommittedState)
	_, err = s.AccountsAdapter.Commit()
	require.NoError(t, err)
	c, err := NewRollbackContainment(s)
	require.NoError(t, err)
	require.ErrorIs(t, c.Execute(nil), ErrInvalidOperation)
	commitErr := errors.New("commit fault")
	s.commitErr = commitErr
	_, outputs, err := c.Commit()
	require.Same(t, commitErr, err)
	require.Nil(t, outputs)
	called := false
	require.ErrorIs(t, c.Execute(func() (*vmcommon.VMOutput, error) { called = true; return nil, nil }), commitErr)
	require.False(t, called)
}

func TestQualDRWANativeContainmentEqualRootRecovery(t *testing.T) {
	s := qualContainmentStore(t)
	c, err := NewRollbackContainment(s)
	require.NoError(t, err)
	original, rollback := errors.New("operation fault"), errors.New("undo fault")
	s.revertErr = rollback
	err = c.Execute(func() (*vmcommon.VMOutput, error) {
		// An unchanged committed root does not imply an empty native journal.
		require.NoError(t, qualContainmentBalance(s, 100))
		return nil, original
	})
	require.ErrorIs(t, err, rollback)
	root, err := s.RootHash()
	require.NoError(t, err)
	require.Equal(t, c.roots[0], root)
	require.Positive(t, s.JournalLen())
	require.NoError(t, c.Recover())
	require.Zero(t, s.JournalLen())
	qualAssertContainmentBalance(t, s, 100)
}

func TestQualDRWANativeContainmentPartialNativeUndo(t *testing.T) {
	s := qualContainmentStore(t)
	c, err := NewRollbackContainment(s)
	require.NoError(t, err)
	require.NoError(t, c.Execute(func() (*vmcommon.VMOutput, error) { return nil, qualContainmentBalance(s, 90) }))
	snapshot := s.JournalLen()
	original, undoErr := errors.New("operation fault"), errors.New("native journal undo fault")
	undoCalls := 0
	journalBefore := 0
	err = c.Execute(func() (*vmcommon.VMOutput, error) {
		account, loadErr := s.LoadAccount(qualContainmentAddress)
		require.NoError(t, loadErr)
		user := account.(state.UserAccountHandler)
		require.NoError(t, user.SaveKeyValue([]byte("fixture/protocol-record"), []byte{70}))
		require.NoError(t, s.SaveAccount(user))
		native := user.DataTrie().(state.DataTrie)
		user.SetDataTrie(&trieMock.TrieStub{
			RootCalled:              native.RootHash,
			UpdateWithVersionCalled: func([]byte, []byte, core.TrieNodeVersion) error { undoCalls++; return undoErr },
		})
		other, loadErr := s.LoadAccount(bytes.Repeat([]byte{2}, 32))
		require.NoError(t, loadErr)
		require.NoError(t, s.SaveAccount(other))
		journalBefore = s.JournalLen()
		return nil, original
	})
	require.ErrorIs(t, err, original)
	require.ErrorIs(t, err, undoErr)
	require.Equal(t, 1, undoCalls)
	require.Greater(t, s.JournalLen(), snapshot)
	require.Less(t, s.JournalLen(), journalBefore, "later native entries were undone before the failing entry")
	called := false
	require.ErrorIs(t, c.Execute(func() (*vmcommon.VMOutput, error) { called = true; return nil, nil }), undoErr)
	require.False(t, called)
	_, _, err = c.Commit()
	require.ErrorIs(t, err, undoErr)
	require.Zero(t, s.commits)
	require.NoError(t, c.Recover())
	qualAssertContainmentBalance(t, s, 100)
}

func TestQualDRWANativeContainmentPartialCommitRecovery(t *testing.T) {
	for _, retained := range []bool{true, false} {
		name := "original_roots_retained"
		if !retained {
			name = "original_root_unavailable"
		}
		t.Run(name, func(t *testing.T) {
			first, second := qualContainmentStore(t), qualContainmentStore(t)
			c, err := NewRollbackContainment(first, second)
			require.NoError(t, err)
			originalRoots := [][]byte{bytes.Clone(c.roots[0]), bytes.Clone(c.roots[1])}
			originalNode, err := first.backing.Get(originalRoots[0])
			require.NoError(t, err)
			require.NoError(t, c.Execute(func() (*vmcommon.VMOutput, error) {
				if e := qualContainmentBalance(first, 70); e != nil {
					return nil, e
				}
				if e := qualContainmentBalance(second, 130); e != nil {
					return nil, e
				}
				return &vmcommon.VMOutput{ReturnData: [][]byte{[]byte("pending only")}}, nil
			}))
			commitFault := errors.New("second native store commit failed")
			second.commitErr = commitFault
			roots, outputs, err := c.Commit()
			require.Same(t, commitFault, err)
			require.Nil(t, roots)
			require.Nil(t, outputs)
			require.Equal(t, 1, first.commits)
			require.Equal(t, 1, second.commits)
			require.Zero(t, first.JournalLen(), "first store really persisted and cleared its journal")
			require.Positive(t, second.JournalLen(), "second store did not persist")
			persistedRoot, err := first.RootHash()
			require.NoError(t, err)
			require.NotEqual(t, originalRoots[0], persistedRoot)
			qualAssertContainmentBalance(t, first, 70)
			qualAssertContainmentBalance(t, second, 130)
			called := false
			require.ErrorIs(t, c.Execute(func() (*vmcommon.VMOutput, error) { called = true; return nil, nil }), commitFault)
			require.False(t, called)
			if !retained {
				// Real backing-store removal, not a RecreateTrie stub fault:
				// admission cannot assume recovery after native pruning/removal.
				require.NoError(t, first.backing.Remove(originalRoots[0]))
				require.ErrorIs(t, c.Recover(), commitFault)
				_, outputs, err = c.Commit()
				require.ErrorIs(t, err, commitFault)
				require.Nil(t, outputs)
				require.ErrorIs(t, c.Execute(func() (*vmcommon.VMOutput, error) { called = true; return nil, nil }), commitFault)
				require.False(t, called)
				qualAssertContainmentBalance(t, second, 100)
				require.NoError(t, first.backing.Put(originalRoots[0], originalNode))
			}
			require.NoError(t, c.Recover())
			for i, store := range []*qualNativeStore{first, second} {
				root, rootErr := store.RootHash()
				require.NoError(t, rootErr)
				require.Equal(t, originalRoots[i], root)
				require.Zero(t, store.JournalLen())
				qualAssertContainmentBalance(t, store, 100)
			}
			require.Equal(t, 1, first.commits, "recovery never retries native persistence")
			require.Equal(t, 1, second.commits)
			require.ErrorIs(t, c.Execute(func() (*vmcommon.VMOutput, error) { called = true; return nil, nil }), ErrExecutionClosed)
			require.False(t, called)
		})
	}
}

// This feasibility fixture replaces the earlier disabled pruning/stub storage
// with the actual native storage manager, pruning manager and eviction list.
// Persistence remains memory-backed; no snapshot, epoch deletion or canonical
// owner is simulated. The capacities are experimental values under R7.
func qualPruningContainmentStore(t *testing.T, retainInitialReference bool) (*qualNativeStore, common.StorageManager) {
	t.Helper()
	args, _ := qualContainmentArgs(t)
	db := testscommon.NewSnapshotPruningStorerMock()
	storage, err := trie.NewTrieStorageManager(trie.NewTrieStorageManagerArgs{
		MainStorer: db, Marshalizer: args.Marshaller, Hasher: args.Hasher,
		GeneralConfig: config.TrieStorageManagerConfig{
			SnapshotsBufferLen: 10, SnapshotsGoroutinesPerCore: 1,
		},
		IdleProvider: &testscommon.ProcessStatusHandlerStub{}, Identifier: "qual-drwa-root-retention",
		StatsCollector: db.GetStateStatsHandler(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, storage.Close()) })
	args.Trie, err = trie.NewTrie(storage, args.Marshaller, args.Hasher,
		enableEpochsHandlerMock.NewEnableEpochsHandlerStub(), 5)
	require.NoError(t, err)
	waiting, err := evictionWaitingList.NewMemoryEvictionWaitingList(evictionWaitingList.MemoryEvictionWaitingListArgs{
		RootHashesSize: 1000, HashesSize: 1000,
	})
	require.NoError(t, err)
	args.StoragePruningManager, err = storagePruningManager.NewStoragePruningManager(waiting, 1000)
	require.NoError(t, err)
	args.PruningEnabled = true
	adb, err := state.NewAccountsDB(args)
	require.NoError(t, err)
	s := &qualNativeStore{AccountsAdapter: adb, backing: db.MemDbMock}
	require.NoError(t, qualContainmentBalance(s, 100))
	root, err := adb.Commit()
	require.NoError(t, err)
	// The hostile pruning-lifetime experiment discards this native reference.
	// The reference-retention experiment keeps it; actual canonical header
	// admission and the native settled/executed-root ordering remain separate.
	if !retainInitialReference {
		s.CancelPrune(bytes.Clone(root), state.NewRoot)
	}
	require.True(t, s.IsPruningEnabled())
	require.False(t, storage.IsPruningBlocked())
	return s, storage
}

// P-05 needs roots to survive the entire recovery lifetime. Buffering is a
// native counter, not a pin: queued prune/cancel operations execute in order.
// ResetPruning is explored here only as a native feasibility alternative, not
// installed as a production policy for other owners' pending pruning work.
func TestQualDRWANativeContainmentPruningLifetime(t *testing.T) {
	for _, mode := range []string{
		"unbuffered_pruning_before_recovery",
		"buffered_late_cancel_after_recovery",
		"buffered_native_reset_before_release",
	} {
		t.Run(mode, func(t *testing.T) {
			first, storage := qualPruningContainmentStore(t, false)
			second := qualContainmentStore(t)
			buffered := mode != "unbuffered_pruning_before_recovery"
			if buffered {
				storage.EnterPruningBufferingMode()
				defer func() {
					if storage.IsPruningBlocked() {
						storage.ExitPruningBufferingMode()
					}
				}()
			}
			c, err := NewRollbackContainment(first, second)
			require.NoError(t, err)
			root := bytes.Clone(c.roots[0])
			account, err := first.GetExistingAccount(qualContainmentAddress)
			require.NoError(t, err)
			dataRoot := bytes.Clone(account.(state.UserAccountHandler).GetRootHash())
			for _, hash := range [][]byte{root, dataRoot} {
				value, readErr := first.backing.Get(hash)
				require.NoError(t, readErr)
				require.NotEmpty(t, value)
			}
			require.NoError(t, c.Execute(func() (*vmcommon.VMOutput, error) {
				if e := qualContainmentBalance(first, 70); e != nil {
					return nil, e
				}
				if e := qualContainmentBalance(second, 130); e != nil {
					return nil, e
				}
				return &vmcommon.VMOutput{ReturnData: [][]byte{[]byte("pending only")}}, nil
			}))
			commitFault := errors.New("second native store commit failed")
			second.commitErr = commitFault
			roots, outputs, err := c.Commit()
			require.Same(t, commitFault, err)
			require.Nil(t, roots)
			require.Nil(t, outputs)
			require.Zero(t, first.JournalLen())
			require.Positive(t, second.JournalLen())
			first.PruneTrie(bytes.Clone(root), state.OldRoot, state.NewPruningHandler(state.EnableDataRemoval))
			if !buffered {
				for _, hash := range [][]byte{root, dataRoot} {
					_, readErr := first.backing.Get(hash)
					require.Error(t, readErr)
				}
				require.ErrorIs(t, c.Recover(), commitFault)
				called := false
				require.ErrorIs(t, c.Execute(func() (*vmcommon.VMOutput, error) { called = true; return nil, nil }), commitFault)
				require.False(t, called)
				_, outputs, err = c.Commit()
				require.ErrorIs(t, err, commitFault)
				require.Nil(t, outputs)
				qualAssertContainmentBalance(t, second, 100)
			} else {
				// This cancellation queues behind the existing prune. Recreating
				// a trie before buffering ends does not reorder those requests.
				first.CancelPrune(bytes.Clone(root), state.OldRoot)
				require.NoError(t, c.Recover())
				qualAssertContainmentBalance(t, first, 100)
				qualAssertContainmentBalance(t, second, 100)
				reset := mode == "buffered_native_reset_before_release"
				if reset {
					first.ResetPruning()
				}
				storage.ExitPruningBufferingMode()
				require.False(t, storage.IsPruningBlocked())
				// An ordinary later pruning call drains the native queue.
				first.PruneTrie(bytes.Clone(root), state.OldRoot, state.NewPruningHandler(state.EnableDataRemoval))
				for _, hash := range [][]byte{root, dataRoot} {
					_, readErr := first.backing.Get(hash)
					if reset {
						require.NoError(t, readErr)
					} else {
						require.Error(t, readErr)
					}
				}
				// Force fresh main/data-trie reads; a cached recovered account
				// could otherwise hide backing-node removal after release.
				err = first.AccountsAdapter.RecreateTrie(holders.NewDefaultRootHashesHolder(bytes.Clone(root)))
				if reset {
					require.NoError(t, err)
					qualAssertContainmentBalance(t, first, 100)
				} else {
					require.Error(t, err)
				}
				called := false
				require.ErrorIs(t, c.Execute(func() (*vmcommon.VMOutput, error) { called = true; return nil, nil }), ErrExecutionClosed)
				require.False(t, called)
			}
			require.Equal(t, 1, first.commits)
			require.Equal(t, 1, second.commits)
		})
	}
}

// The native EWL already retains nodes referenced by an unconsumed NewRoot.
// Native rollback cancels the original OldRoot and prunes only the discarded
// NewRoot. Exercise both mechanisms with actual node removal, without adding
// buffering or ResetPruning. These direct calls do not authenticate a canonical
// header or install the eventual native DRWA owner.
func TestQualDRWANativeContainmentPruningReferences(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		name := "initial_NewRoot_reference_retained"
		if rollback {
			name = "native_rollback_cancel_OldRoot_prune_NewRoot"
		}
		t.Run(name, func(t *testing.T) {
			first, storage := qualPruningContainmentStore(t, true)
			second := qualContainmentStore(t)
			c, err := NewRollbackContainment(first, second)
			require.NoError(t, err)
			root := bytes.Clone(c.roots[0])
			account, err := first.GetExistingAccount(qualContainmentAddress)
			require.NoError(t, err)
			dataRoot := bytes.Clone(account.(state.UserAccountHandler).GetRootHash())
			require.NoError(t, c.Execute(func() (*vmcommon.VMOutput, error) {
				if e := qualContainmentBalance(first, 70); e != nil {
					return nil, e
				}
				return nil, qualContainmentBalance(second, 130)
			}))
			commitFault := errors.New("second native store commit failed")
			second.commitErr = commitFault
			roots, outputs, err := c.Commit()
			require.Same(t, commitFault, err)
			require.Nil(t, roots)
			require.Nil(t, outputs)
			candidateRoot, err := first.RootHash()
			require.NoError(t, err)
			require.NotEqual(t, root, candidateRoot)
			require.Zero(t, first.JournalLen())
			require.Positive(t, second.JournalLen())
			require.False(t, storage.IsPruningBlocked())
			if rollback {
				// Same cancellation/pruning order as native PruneStateOnRollback.
				first.CancelPrune(bytes.Clone(root), state.OldRoot)
				first.PruneTrie(bytes.Clone(candidateRoot), state.NewRoot, state.NewPruningHandler(state.EnableDataRemoval))
				_, readErr := first.backing.Get(candidateRoot)
				require.Error(t, readErr, "discarded candidate nodes were actually pruned")
			} else {
				first.PruneTrie(bytes.Clone(root), state.OldRoot, state.NewPruningHandler(state.EnableDataRemoval))
			}
			for _, hash := range [][]byte{root, dataRoot} {
				value, readErr := first.backing.Get(hash)
				require.NoError(t, readErr)
				require.NotEmpty(t, value)
			}
			require.NoError(t, c.Recover())
			qualAssertContainmentBalance(t, first, 100)
			qualAssertContainmentBalance(t, second, 100)
			// Recreate again to exclude a recovered account/data-trie cache
			// from the retained-node observation.
			require.NoError(t, first.AccountsAdapter.RecreateTrie(holders.NewDefaultRootHashesHolder(bytes.Clone(root))))
			qualAssertContainmentBalance(t, first, 100)
			require.Equal(t, 1, first.commits)
			require.Equal(t, 1, second.commits)
			called := false
			require.ErrorIs(t, c.Execute(func() (*vmcommon.VMOutput, error) { called = true; return nil, nil }), ErrExecutionClosed)
			require.False(t, called)
		})
	}
}
