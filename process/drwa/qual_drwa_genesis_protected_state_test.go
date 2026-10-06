package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/factory"
	pruningDisabled "github.com/multiversx/mx-chain-go/state/storagePruningManager/disabled"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/trie"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Same concrete native constructor as the reader fixture, but no pre-existing
// accounts or test-only seed leaf. qualReaderArgs binds every storage callback
// reached here to its concrete MemDbMock; epoch flags use their healthy map.
func qualGenesisAccounts(t *testing.T, auto bool) *state.AccountsDB {
	t.Helper()
	a := qualReaderArgs(auto)
	tr, err := trie.NewTrie(a.StorageManager, a.Marshaller, a.Hasher, a.EnableEpochsHandler, 5)
	require.NoError(t, err)
	collector := stateDisabled.NewDisabledStateAccessesCollector()
	af, err := factory.NewAccountCreator(factory.ArgsAccountCreator{Hasher: a.Hasher,
		Marshaller: a.Marshaller, EnableEpochsHandler: a.EnableEpochsHandler, StateAccessesCollector: collector})
	require.NoError(t, err)
	db, err := state.NewAccountsDB(state.ArgsAccountsDB{Trie: tr, Hasher: a.Hasher,
		Marshaller: a.Marshaller, AccountFactory: af, StateAccessesCollector: collector,
		StoragePruningManager: pruningDisabled.NewDisabledStoragePruningManager(),
		SnapshotsManager:      stateDisabled.NewDisabledSnapshotsManager(), AddressConverter: &testscommon.PubkeyConverterMock{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return db
}

func TestQualDRWAGenesisProtectedLifecycle(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprint(auto), func(t *testing.T) {
			db := qualGenesisAccounts(t, auto)
			s, err := newProtectedState(db)
			require.NoError(t, err)
			owner, err := NewRollbackContainment(db)
			require.NoError(t, err)
			require.NoError(t, owner.Execute(func() (*vmcommon.VMOutput, error) { return nil, s.provisionGenesis() }))
			require.ErrorIs(t, s.provisionGenesis(), ErrUncommittedState)
			present, err := s.membership([]byte("TOKEN-000001"))
			require.NoError(t, err, "production provisioning supplies the real data trie")
			require.False(t, present)
			roots, _, err := owner.Commit()
			require.NoError(t, err)
			require.Len(t, roots, 1)
			require.NoError(t, db.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
			a, err := db.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			u := a.(state.UserAccountHandler)
			require.Equal(t, bytes.Repeat([]byte{0xff}, 32), u.AddressBytes())
			value, _, err := u.RetrieveValue([]byte(registryCountKey))
			require.NoError(t, err)
			require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0}, value)
			before, err := db.RootHash()
			require.NoError(t, err)
			require.ErrorIs(t, s.provisionGenesis(), errInvalidGenesisState)
			after, err := db.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Zero(t, db.JournalLen())
		})
	}
}

// These decorators have explicit methods, not nullable callbacks; unmodified
// methods delegate to the same concrete native store/account.
type qualGenesisFault struct {
	state.AccountsAdapter
	rootFault, loadFault, saveFault error
	load                            func([]byte) (vmcommon.AccountHandler, error)
}

func (a *qualGenesisFault) RootHash() ([]byte, error) {
	if a.rootFault != nil {
		return nil, a.rootFault
	}
	return a.AccountsAdapter.RootHash()
}
func (a *qualGenesisFault) LoadAccount(address []byte) (vmcommon.AccountHandler, error) {
	if a.loadFault != nil {
		return nil, a.loadFault
	}
	if a.load != nil {
		return a.load(address)
	}
	return a.AccountsAdapter.LoadAccount(address)
}
func (a *qualGenesisFault) SaveAccount(account vmcommon.AccountHandler) error {
	if a.saveFault != nil {
		if err := a.AccountsAdapter.SaveAccount(account); err != nil {
			return err
		}
		return a.saveFault
	}
	return a.AccountsAdapter.SaveAccount(account)
}

func TestQualDRWAGenesisProtectedDenials(t *testing.T) {
	for _, name := range []string{"journal", "existing", "root", "load", "nil_account", "wrong_address", "item", "save"} {
		t.Run(name, func(t *testing.T) {
			db := qualGenesisAccounts(t, false)
			adapter := &qualGenesisFault{AccountsAdapter: db}
			fault := errors.New("native provisioning boundary failed")
			want := fault
			switch name {
			case "journal", "existing":
				a, err := db.LoadAccount(bytes.Repeat([]byte{7}, 32))
				require.NoError(t, err)
				require.NoError(t, db.SaveAccount(a))
				want = ErrUncommittedState
				if name == "existing" {
					_, err = db.Commit()
					require.NoError(t, err)
					want = errInvalidGenesisState
				}
			case "root":
				adapter.rootFault = fault
			case "load":
				adapter.loadFault = fault
			case "nil_account":
				adapter.load = func([]byte) (vmcommon.AccountHandler, error) { return nil, nil }
				want = errInvalidGenesisState
			case "wrong_address":
				adapter.load = func([]byte) (vmcommon.AccountHandler, error) { return db.LoadAccount(bytes.Repeat([]byte{9}, 32)) }
				want = errInvalidGenesisState
			case "item":
				adapter.load = func(address []byte) (vmcommon.AccountHandler, error) {
					a, err := db.LoadAccount(address)
					if err != nil {
						return nil, err
					}
					return &qualProtectedItemFault{UserAccountHandler: a.(state.UserAccountHandler), fault: fault}, nil
				}
			case "save":
				adapter.saveFault = fault
			}
			s, err := newProtectedState(adapter)
			require.NoError(t, err)
			before, err := db.RootHash()
			require.NoError(t, err)
			journal := db.JournalLen()
			if name == "journal" {
				require.ErrorIs(t, s.provisionGenesis(), want)
			} else {
				owner, err := NewRollbackContainment(db)
				require.NoError(t, err)
				require.ErrorIs(t, owner.Execute(func() (*vmcommon.VMOutput, error) { return nil, s.provisionGenesis() }), want)
			}
			after, err := db.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, journal, db.JournalLen())
			if common.IsEmptyTrie(before) {
				_, err = db.GetExistingAccount(core.SystemAccountAddress)
				require.ErrorIs(t, err, state.ErrAccNotFound)
			}
		})
	}
}
