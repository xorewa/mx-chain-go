package drwa

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/errChan"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// A forbidden walk is counted, not silently simulated. All individual reads
// delegate to an actual native account/data trie in the same committed store.
type qualIndexAccount struct {
	state.UserAccountHandler
	reads, walks int
}

func (a *qualIndexAccount) RetrieveValue(key []byte) ([]byte, uint32, error) {
	a.reads++
	return a.UserAccountHandler.RetrieveValue(key)
}

func (a *qualIndexAccount) GetAllLeaves(*common.TrieIteratorChannels, context.Context) error {
	a.walks++
	return errors.New("whole-system-account walk forbidden")
}

func qualIndexLiteralEntry(ordinal byte) []byte {
	return append([]byte("ELRONDDRWA@membershipIndex@entry@"), []byte{0, 0, 0, 0, 0, 0, 0, ordinal}...)
}

func TestQualDRWAMembershipIndex(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, name := range []string{"valid", "missing_count", "short_count", "over_bound", "huge_count", "missing_entry", "duplicate", "unlisted", "invalid_id", "missing_marker", "malformed_marker", "unrelated"} {
			t.Run(fmt.Sprintf("auto_%t/%s", auto, name), func(t *testing.T) {
				m, view, db, _ := qualRegistryMaterialization(t, auto)
				u, err := db.GetExistingAccount(core.SystemAccountAddress)
				require.NoError(t, err)
				a := u.(state.UserAccountHandler)
				count := []byte{0, 0, 0, 0, 0, 0, 0, 2}
				ids := [][]byte{[]byte("AAA-abcdef"), []byte("BBB-123456")}
				marker := []byte{1}
				switch name {
				case "missing_count":
					count = nil
				case "short_count":
					count = []byte{2}
				case "over_bound":
					count[7] = 3
				case "huge_count":
					count = bytes.Repeat([]byte{255}, 8)
				case "missing_entry":
					ids[1] = nil
				case "duplicate":
					ids[1] = ids[0]
				case "unlisted":
					ids[1] = []byte("CCC-abcdef")
				case "invalid_id":
					ids[1] = []byte("bad")
					view.members["bad"] = struct{}{}
				case "missing_marker":
					marker = nil
				case "malformed_marker":
					marker = []byte{2}
				}
				require.NoError(t, a.SaveKeyValue([]byte("ELRONDDRWA@membershipIndex@count"), count))
				for i, id := range ids {
					require.NoError(t, a.SaveKeyValue(qualIndexLiteralEntry(byte(i)), id))
					if len(id) != 0 {
						require.NoError(t, a.SaveKeyValue(append([]byte("ELRONDDRWA@membership@"), id...), marker))
					}
				}
				if name == "unrelated" {
					for i := 0; i < 512; i++ {
						require.NoError(t, a.SaveKeyValue([]byte(fmt.Sprintf("ELRONDesdt/unrelated/%d", i)), []byte("native metadata")))
					}
				}
				require.NoError(t, db.SaveAccount(a))
				_, err = db.Commit()
				require.NoError(t, err)
				m, err = newRegistryMaterialization(db, &view.anchor)
				require.NoError(t, err)
				u, err = db.GetExistingAccount(core.SystemAccountAddress)
				require.NoError(t, err)
				observed := &qualIndexAccount{UserAccountHandler: u.(state.UserAccountHandler)}
				m.state.accounts = &qualProtectedAccountSource{AccountsAdapter: db, account: observed}
				err = m.checkLocalMembership(context.Background(), view)
				if name == "valid" || name == "unrelated" {
					require.NoError(t, err)
					require.Equal(t, 5, observed.reads, "one count plus one index/marker pair per local member")
				} else {
					require.Error(t, err)
				}
				require.Zero(t, observed.walks)
				if name == "over_bound" || name == "huge_count" {
					require.Equal(t, 1, observed.reads)
				}
			})
		}
	}
}

func TestQualDRWAMembershipIndexNativeReadFailure(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, boundary := range []string{"count", "entry", "marker"} {
			t.Run(fmt.Sprintf("auto_%t/%s", auto, boundary), func(t *testing.T) {
				args := qualReaderArgs(auto)
				db := qualGenesisAccountsFromArgs(t, args)
				s, err := newProtectedState(db)
				require.NoError(t, err)
				require.NoError(t, s.provisionGenesis())
				require.NoError(t, s.materializeMembership([]byte("AAA-abcdef")))
				root, err := db.Commit()
				require.NoError(t, err)
				reopened := qualGenesisAccountsFromArgs(t, args)
				require.NoError(t, reopened.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
				_, view, _, _ := qualRegistryMaterialization(t, auto)
				m, err := newRegistryMaterialization(reopened, &view.anchor)
				require.NoError(t, err)
				if boundary != "count" {
					u, e := reopened.GetExistingAccount(core.SystemAccountAddress)
					require.NoError(t, e)
					_, _, e = u.(state.UserAccountHandler).RetrieveValue([]byte("ELRONDDRWA@membershipIndex@count"))
					require.NoError(t, e)
					if boundary == "marker" {
						_, _, e = u.(state.UserAccountHandler).RetrieveValue(qualIndexLiteralEntry(0))
						require.NoError(t, e)
					}
				}
				storage := args.StorageManager.(*storageManager.StorageManagerStub)
				get := storage.GetCalled
				fault := errors.New("missing native data-trie node")
				calls := 0
				var missingKey []byte
				storage.GetCalled = func(key []byte) ([]byte, error) { calls++; missingKey = bytes.Clone(key); return nil, fault }
				storage.GetFromCurrentEpochCalled = storage.GetCalled
				err = m.checkLocalMembership(context.Background(), view)
				require.Error(t, err)
				require.Positive(t, calls, "the concrete native trie must actually reach storage")
				want := core.NewGetNodeFromDBErrWithKey(missingKey, fault, storage.GetIdentifier())
				text := want.Error()
				// Native trie.Get adds a %w wrapper (patriciaMerkleTrie.go L108).
				// Preserve the inner native type, exact diagnostic and node key.
				require.ErrorAs(t, err, &want)
				require.EqualError(t, want, text)
				require.Equal(t, missingKey, want.GetKey())
				storage.GetCalled, storage.GetFromCurrentEpochCalled = get, get
				require.NoError(t, m.checkLocalMembership(context.Background(), view))
			})
		}
	}
}

// Reproduce MT-02's actual native error-channel boundary, although bounded
// production reconstruction no longer walks this trie. Allow its root load and
// refuse descendant nodes: GetAllLeaves returns nil while ErrChan carries the
// real native failure. The audited old guard is separately counterfactually run.
func TestQualDRWAMembershipIndexFormerWalkFailure(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprintf("auto_%t", auto), func(t *testing.T) {
			args := qualReaderArgs(auto)
			db := qualGenesisAccountsFromArgs(t, args)
			s, err := newProtectedState(db)
			require.NoError(t, err)
			require.NoError(t, s.provisionGenesis())
			for _, id := range []string{"AAA-abcdef", "BBB-123456"} {
				require.NoError(t, s.materializeMembership([]byte(id)))
			}
			root, err := db.Commit()
			require.NoError(t, err)
			reopened := qualGenesisAccountsFromArgs(t, args)
			require.NoError(t, reopened.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
			_, view, _, _ := qualRegistryMaterialization(t, auto)
			m, err := newRegistryMaterialization(reopened, &view.anchor)
			require.NoError(t, err)
			u, err := reopened.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			a := u.(state.UserAccountHandler)
			dataRoot := bytes.Clone(a.GetRootHash())
			storage := args.StorageManager.(*storageManager.StorageManagerStub)
			get := storage.GetCalled
			fault := errors.New("missing native descendant during full leaf walk")
			calls := 0
			storage.GetCalled = func(key []byte) ([]byte, error) {
				if bytes.Equal(key, dataRoot) {
					return get(key)
				}
				calls++
				return nil, fault
			}
			storage.GetFromCurrentEpochCalled = storage.GetCalled
			channels := &common.TrieIteratorChannels{LeavesChan: make(chan core.KeyValueHolder), ErrChan: errChan.NewErrChanWrapper()}
			require.NoError(t, a.GetAllLeaves(channels, context.Background()))
			for range channels.LeavesChan {
			}
			walkError := channels.ErrChan.ReadFromChanNonBlocking()
			require.Error(t, walkError)
			require.Positive(t, calls)
			want := core.NewGetNodeFromDBErrWithKey(nil, fault, storage.GetIdentifier())
			require.ErrorAs(t, walkError, &want)
			err = m.checkLocalMembership(context.Background(), view)
			require.Error(t, err)
			require.ErrorAs(t, err, &want)
			storage.GetCalled, storage.GetFromCurrentEpochCalled = get, get
			require.NoError(t, m.checkLocalMembership(context.Background(), view))
		})
	}
}

type qualIndexItemFault struct {
	state.UserAccountHandler
	key     []byte
	readKey []byte
	err     error
}

func (u *qualIndexItemFault) RetrieveValue(key []byte) ([]byte, uint32, error) {
	value, depth, err := u.UserAccountHandler.RetrieveValue(key)
	if err == nil && bytes.Equal(key, u.readKey) {
		return value, depth, u.err
	}
	return value, depth, err
}

func (u *qualIndexItemFault) SaveKeyValue(key, value []byte) error {
	if bytes.Equal(key, u.key) {
		return u.err
	}
	return u.UserAccountHandler.SaveKeyValue(key, value)
}

func TestQualDRWAMembershipIndexGenesisCountFailure(t *testing.T) {
	db := qualGenesisAccounts(t, false)
	fault := errors.New("native genesis local-index count save failed")
	adapter := &qualGenesisFault{AccountsAdapter: db, load: func(address []byte) (vmcommon.AccountHandler, error) {
		u, err := db.LoadAccount(address)
		if err != nil {
			return nil, err
		}
		return &qualIndexItemFault{UserAccountHandler: u.(state.UserAccountHandler), key: []byte("ELRONDDRWA@membershipIndex@count"), err: fault}, nil
	}}
	s, err := newProtectedState(adapter)
	require.NoError(t, err)
	owner, err := NewRollbackContainment(db)
	require.NoError(t, err)
	before, err := db.RootHash()
	require.NoError(t, err)
	require.ErrorIs(t, owner.Execute(func() (*vmcommon.VMOutput, error) { return nil, s.provisionGenesis() }), fault)
	after, err := db.RootHash()
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Zero(t, db.JournalLen())
}

func TestQualDRWAMembershipIndexWriterDenials(t *testing.T) {
	for _, name := range []string{"missing_count", "short_count", "overflow", "occupied", "entry_save", "count_save", "slot_read"} {
		t.Run(name, func(t *testing.T) {
			f, s := qualProtectedFixture(t, false)
			u, err := f.adb.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			a := u.(state.UserAccountHandler)
			if name == "missing_count" || name == "short_count" || name == "overflow" {
				var v []byte
				if name == "short_count" {
					v = []byte{1}
				}
				if name == "overflow" {
					v = bytes.Repeat([]byte{255}, 8)
				}
				require.NoError(t, a.SaveKeyValue([]byte("ELRONDDRWA@membershipIndex@count"), v))
			}
			if name == "occupied" {
				require.NoError(t, a.SaveKeyValue(qualIndexLiteralEntry(0), []byte("BBB-123456")))
			}
			require.NoError(t, f.adb.SaveAccount(a))
			_, err = f.adb.Commit()
			require.NoError(t, err)
			before, err := f.adb.RootHash()
			require.NoError(t, err)
			fault := errors.New("native local index save failed")
			if name == "entry_save" || name == "count_save" || name == "slot_read" {
				u, err = f.adb.GetExistingAccount(core.SystemAccountAddress)
				require.NoError(t, err)
				key := qualIndexLiteralEntry(0)
				if name == "count_save" {
					key = []byte("ELRONDDRWA@membershipIndex@count")
				}
				var readKey []byte
				if name == "slot_read" {
					readKey, key = key, nil
				}
				s, err = newProtectedState(&qualProtectedAccountSource{AccountsAdapter: f.adb, account: &qualIndexItemFault{UserAccountHandler: u.(state.UserAccountHandler), key: key, readKey: readKey, err: fault}})
				require.NoError(t, err)
			}
			owner, err := NewRollbackContainment(f.adb)
			require.NoError(t, err)
			err = owner.Execute(func() (*vmcommon.VMOutput, error) { return nil, s.materializeMembership([]byte("AAA-abcdef")) })
			require.Error(t, err)
			if name == "entry_save" || name == "count_save" || name == "slot_read" {
				require.ErrorIs(t, err, fault)
			}
			after, err := f.adb.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Zero(t, f.adb.JournalLen())
		})
	}
}

func TestQualDRWAMembershipIndexWriter(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprintf("auto_%t", auto), func(t *testing.T) {
			f, s := qualProtectedFixture(t, auto)
			require.NoError(t, s.materializeMembership([]byte("AAA-abcdef")))
			boundary := f.adb.JournalLen()
			require.NoError(t, s.materializeMembership([]byte("AAA-abcdef")))
			require.Equal(t, boundary, f.adb.JournalLen())
			require.NoError(t, s.materializeMembership([]byte("BBB-123456")))
			check := func(count byte, second []byte) {
				u, err := f.adb.GetExistingAccount(core.SystemAccountAddress)
				require.NoError(t, err)
				a := u.(state.UserAccountHandler)
				value, _, err := a.RetrieveValue([]byte("ELRONDDRWA@membershipIndex@count"))
				require.NoError(t, err)
				require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, count}, value)
				value, _, err = a.RetrieveValue(qualIndexLiteralEntry(0))
				require.NoError(t, err)
				require.Equal(t, []byte("AAA-abcdef"), value)
				value, _, err = a.RetrieveValue(qualIndexLiteralEntry(1))
				require.NoError(t, err)
				require.Equal(t, second, value)
			}
			check(2, []byte("BBB-123456"))
			require.NoError(t, f.adb.RevertToSnapshot(boundary))
			check(1, nil)
			root, err := f.adb.Commit()
			require.NoError(t, err)
			require.NoError(t, s.materializeMembership([]byte("BBB-123456")))
			require.NoError(t, f.adb.RevertToSnapshot(0))
			require.NoError(t, f.adb.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
			check(1, nil)
		})
	}
}

func TestQualDRWAMembershipIndexInputOwnership(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprintf("auto_%t", auto), func(t *testing.T) {
			f, s := qualProtectedFixture(t, auto)
			id := make([]byte, len("AAA-abcdef"), 256)
			copy(id, "AAA-abcdef")
			require.NoError(t, s.materializeMembership(id))
			id[0] = 'Z'
			u, err := f.adb.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			value, _, err := u.(state.UserAccountHandler).RetrieveValue(qualIndexLiteralEntry(0))
			require.NoError(t, err)
			require.Equal(t, []byte("AAA-abcdef"), value)
		})
	}
}
