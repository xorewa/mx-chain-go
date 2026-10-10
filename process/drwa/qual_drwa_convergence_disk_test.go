package drwa

import (
	"bytes"
	"fmt"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/integrationTests"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/stretchr/testify/require"
)

// L46 development: real native disk persistence, fresh caches and AccountsDB,
// with the existing SYNTHETIC GAS/canonicality/funding host. Roots are selected
// by this fixture. Graceful Close is not a crash, fsync, pruning or finality proof.
// Resource values reuse the current promotion-disk fixture; no profile is chosen.
func qualConvergenceDiskOpen(t *testing.T, path string, balanced bool) (*qualNativeStore, func()) {
	t.Helper()
	cache, err := storageunit.NewCache(storageunit.CacheConfig{Type: storageunit.LRUCache, Capacity: 100})
	require.NoError(t, err)
	persister, err := storageunit.NewDB(storageunit.ArgDB{DBType: storageunit.LvlDBSerial,
		Path: path, BatchDelaySeconds: 5, MaxBatchSize: 10, MaxOpenFiles: 10})
	require.NoError(t, err)
	unit, err := storageunit.NewStorageUnit(cache, persister)
	require.NoError(t, err)
	manager, _ := integrationTests.CreateTrieStorageManager(unit)
	require.NotNil(t, manager)
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	if balanced {
		flags.AddActiveFlags(common.AutoBalanceDataTriesFlag)
	}
	accounts, _ := integrationTests.CreateAccountsDBWithEnableEpochsHandler(integrationTests.UserAccount, manager, flags)
	require.NotNil(t, accounts)
	closed := false
	closeStore := func() {
		if closed {
			return
		}
		closed = true
		accountErr := accounts.Close()
		storageErr := manager.Close() // AccountsDB.Close does not close this owner.
		require.NoError(t, accountErr)
		require.NoError(t, storageErr)
		require.True(t, manager.IsClosed())
	}
	t.Cleanup(closeStore)
	return &qualNativeStore{AccountsAdapter: accounts}, closeStore
}

func qualConvergenceDiskRebind(t *testing.T, f *qualConvergenceFixture, store *qualNativeStore) {
	t.Helper()
	f.store = store
	// Rebuild the entire verifier, owner and reader. Only literal public fixture
	// inputs survive; no old host counters, receipt cache or account aliases do.
	f.host = &qualConvergenceHost{t: t, store: store, binding: bytes.Clone(f.binding), key: bytes.Clone(f.key),
		acks: make(map[string]uint32), faults: make(map[string]error), hooks: make(map[string]func())}
	for _, shard := range f.tr.shards {
		id := []byte{0, 0, 0, byte(shard)}
		f.host.acks[string(qualRecordFrame(f.binding, id, f.local[shard]))] = shard
	}
	f.reopen(t, store)
}

func qualConvergenceDiskInit(t *testing.T, path string, balanced bool) (*qualConvergenceFixture, func()) {
	t.Helper()
	f := qualConvergenceNew(t, 3) // Reuse its independently specified literal inputs.
	require.NoError(t, f.store.Close())
	store, closeStore := qualConvergenceDiskOpen(t, path, balanced)
	protected, err := newProtectedState(store)
	require.NoError(t, err)
	require.NoError(t, protected.provisionGenesis())
	account, err := store.LoadAccount(bytes.Repeat([]byte{42}, 32))
	require.NoError(t, err)
	user := account.(state.UserAccountHandler)
	require.NoError(t, user.AddToBalance(big.NewInt(100)))
	require.NoError(t, user.SaveKeyValue([]byte("fixture/T29/disk/unrelated"), []byte("untouched")))
	require.NoError(t, store.SaveAccount(user))
	_, err = store.Commit()
	require.NoError(t, err)
	qualConvergenceDiskRebind(t, f, store)
	f.create(t)
	require.NoError(t, f.ack(0))
	return f, closeStore
}

func qualConvergenceDiskUnrelated(t *testing.T, f *qualConvergenceFixture) {
	t.Helper()
	account, err := f.store.GetExistingAccount(bytes.Repeat([]byte{42}, 32))
	require.NoError(t, err)
	user := account.(state.UserAccountHandler)
	require.Equal(t, big.NewInt(100), user.GetBalance())
	value, _, err := user.RetrieveValue([]byte("fixture/T29/disk/unrelated"))
	require.NoError(t, err)
	require.Equal(t, []byte("untouched"), value)
}

func TestQualDRWAConvergenceDiskUncommittedAndReplay(t *testing.T) {
	for _, balanced := range []bool{false, true} {
		for prefix := 0; prefix <= 3; prefix++ {
			t.Run(fmt.Sprintf("balanced_%t_prefix_%d", balanced, prefix), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "accounts")
				f, closeStore := qualConvergenceDiskInit(t, path, balanced)
				pendingRoots, _, err := f.owner.Commit()
				require.NoError(t, err)
				pendingRoot := bytes.Clone(pendingRoots[0])
				f.reopen(t, f.store)
				steps := []func() error{func() error { return f.ack(1) }, func() error { return f.ack(2) }, func() error { return f.records.complete(f.tr) }}
				for i := 0; i < prefix; i++ {
					require.NoError(t, steps[i]())
				}
				uncommittedRoot, err := f.store.RootHash()
				require.NoError(t, err)
				if prefix > 0 {
					require.NotEqual(t, pendingRoot, uncommittedRoot)
				}
				closeStore() // No AccountsDB.Commit of the attempted prefix.
				store, closeStore := qualConvergenceDiskOpen(t, path, balanced)
				if prefix > 0 {
					require.Error(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(uncommittedRoot)))
				}
				require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(pendingRoot)))
				qualConvergenceDiskRebind(t, f, store)
				f.assert(t, "PENDING", 0)
				require.Empty(t, qualRegistryValue(t, f.store, qualConvergenceParent))
				qualConvergenceDiskUnrelated(t, f)
				require.NoError(t, f.ack(0))
				require.Equal(t, 1, f.host.ackCalls)
				require.Zero(t, f.store.JournalLen())
				require.NoError(t, f.ack(1))
				require.NoError(t, f.ack(2))
				require.NoError(t, f.records.complete(f.tr))
				f.assert(t, "COMPLETE", 0, 1, 2)
				_, commitment := f.expected("COMPLETE", 0, 1, 2)
				parent := qualRecordFrame(f.binding, commitment)
				require.Equal(t, parent, qualRegistryValue(t, f.store, qualConvergenceParent))
				completedRoots, outputs, err := f.owner.Commit()
				require.NoError(t, err)
				published := 0
				for _, output := range outputs {
					if output != nil {
						published++
					}
				}
				require.Equal(t, 1, published)
				completedRoot := bytes.Clone(completedRoots[0])
				closeStore()
				store, closeStore = qualConvergenceDiskOpen(t, path, balanced)
				require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(completedRoot)))
				qualConvergenceDiskRebind(t, f, store)
				f.assert(t, "COMPLETE", 0, 1, 2)
				require.Equal(t, parent, qualRegistryValue(t, f.store, qualConvergenceParent))
				f.create(t)
				require.NoError(t, f.ack(0))
				require.NoError(t, f.records.complete(f.tr))
				require.Zero(t, f.store.JournalLen())
				require.Zero(t, f.host.admissionCalls)
				require.Zero(t, f.host.completeCalls)
				require.Positive(t, f.host.verifyCalls)
				require.Positive(t, f.host.parentCalls)
				qualConvergenceDiskUnrelated(t, f)
				_, outputs, err = f.owner.Commit()
				require.NoError(t, err)
				for _, output := range outputs {
					require.Nil(t, output)
				}
				// Trust-selected predecessor replay uses new native objects too.
				closeStore()
				store, closeStore = qualConvergenceDiskOpen(t, path, balanced)
				require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(pendingRoot)))
				qualConvergenceDiskRebind(t, f, store)
				f.assert(t, "PENDING", 0)
				require.NoError(t, f.ack(1))
				require.NoError(t, f.ack(2))
				require.NoError(t, f.records.complete(f.tr))
				replayedRoots, _, err := f.owner.Commit()
				require.NoError(t, err)
				require.Equal(t, completedRoot, replayedRoots[0])
				qualConvergenceDiskUnrelated(t, f)
				closeStore()
			})
		}
	}
}

func TestQualDRWAConvergenceDiskCorruptRetainedState(t *testing.T) {
	for _, balanced := range []bool{false, true} {
		for _, name := range []string{"missing_parent", "wrong_parent", "missing_progress", "malformed_progress"} {
			t.Run(fmt.Sprintf("balanced_%t_%s", balanced, name), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "accounts")
				f, closeStore := qualConvergenceDiskInit(t, path, balanced)
				require.NoError(t, f.ack(1))
				require.NoError(t, f.ack(2))
				require.NoError(t, f.records.complete(f.tr))
				_, _, err := f.owner.Commit()
				require.NoError(t, err)
				key := []byte(qualConvergenceParent)
				var value []byte
				switch name {
				case "wrong_parent":
					value = []byte("wrong-parent-commitment")
				case "missing_progress":
					key = f.key
				case "malformed_progress":
					key, value = f.key, []byte("malformed-progress")
				}
				// Deliberately commit a hostile fixture; this is not a lawful writer.
				qualRecordPut(t, f.store, key, value)
				corruptRoot, err := f.store.Commit()
				require.NoError(t, err)
				closeStore()
				store, closeStore := qualConvergenceDiskOpen(t, path, balanced)
				require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(corruptRoot)))
				qualConvergenceDiskRebind(t, f, store)
				beforeProgress := bytes.Clone(qualRegistryValue(t, f.store, string(f.key)))
				beforeParent := bytes.Clone(qualRegistryValue(t, f.store, qualConvergenceParent))
				require.Error(t, f.ack(0))
				require.Error(t, f.records.complete(f.tr))
				if name == "missing_parent" || name == "wrong_parent" {
					require.Error(t, f.records.create(f.tr))
				}
				require.Zero(t, f.store.JournalLen())
				require.Zero(t, f.host.completeCalls)
				require.Equal(t, beforeProgress, qualRegistryValue(t, f.store, string(f.key)))
				require.Equal(t, beforeParent, qualRegistryValue(t, f.store, qualConvergenceParent))
				after, err := f.store.RootHash()
				require.NoError(t, err)
				require.Equal(t, corruptRoot, after)
				qualConvergenceDiskUnrelated(t, f)
				closeStore()
			})
		}
	}
}
