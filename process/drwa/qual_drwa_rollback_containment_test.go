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
	"github.com/multiversx/mx-chain-go/state"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/factory"
	pruningDisabled "github.com/multiversx/mx-chain-go/state/storagePruningManager/disabled"
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

func qualContainmentStore(t *testing.T) *qualNativeStore {
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
	adb, err := state.NewAccountsDB(state.ArgsAccountsDB{
		Trie: tr, Hasher: hash, Marshaller: mar, AccountFactory: f,
		StateAccessesCollector: collector,
		StoragePruningManager:  pruningDisabled.NewDisabledStoragePruningManager(),
		SnapshotsManager:       stateDisabled.NewDisabledSnapshotsManager(),
		AddressConverter:       &testscommon.PubkeyConverterMock{},
	})
	require.NoError(t, err)
	s := &qualNativeStore{AccountsAdapter: adb}
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
