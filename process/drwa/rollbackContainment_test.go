package drwa

import (
	"bytes"
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
	"github.com/multiversx/mx-chain-go/trie"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

// Shared native-account fixture for ordinary unit tests and retained qualification scenarios.
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
