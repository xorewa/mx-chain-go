package stateTrie

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/throttler"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-storage-go/types"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/common/statistics"
	"github.com/multiversx/mx-chain-go/common/statistics/disabled"
	"github.com/multiversx/mx-chain-go/epochStart/notifier"
	"github.com/multiversx/mx-chain-go/integrationTests"
	"github.com/multiversx/mx-chain-go/integrationTests/mock"
	"github.com/multiversx/mx-chain-go/state"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/factory"
	"github.com/multiversx/mx-chain-go/state/iteratorChannelsProvider"
	"github.com/multiversx/mx-chain-go/state/lastSnapshotMarker"
	"github.com/multiversx/mx-chain-go/state/storagePruningManager"
	"github.com/multiversx/mx-chain-go/state/storagePruningManager/evictionWaitingList"
	"github.com/multiversx/mx-chain-go/state/syncer"
	"github.com/multiversx/mx-chain-go/storage"
	storageMock "github.com/multiversx/mx-chain-go/storage/mock"
	"github.com/multiversx/mx-chain-go/storage/pruning"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/cache"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/testscommon/statusHandler"
	storageStubs "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/multiversx/mx-chain-go/trie/keyBuilder"
)

// SP2-20 / P20 (Part A L6372-6375, L1005-1015; Plan L579). Restart and recovery
// of the exact core.SystemAccountAddress data trie and of the protected child
// trie it binds, on a real multi-epoch pruning store: after snapshot, after
// pruning, after restart, after state sync into another store and after the
// recovery-trie repair path. In every stage the protected records and child
// roots are byte-identical, and a failure is an error, never a silent loss.

const sp220Domain = core.ProtectedKeyPrefix + "DRWA@"

var (
	sp220ChildRecord = []byte(sp220Domain + "sp220/child-root")
	sp220Ordinary    = bytes.Repeat([]byte{7}, 32)
)

// sp220Checkpoints is the test's owner of the checkpoint to child-record
// relation, which production code derives from the committed chain.
type sp220Checkpoints struct {
	mutex   sync.Mutex
	records map[string][]byte
	order   [][]byte
	fail    error
}

func (c *sp220Checkpoints) add(root, record []byte) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if _, exists := c.records[string(root)]; !exists {
		c.order = append(c.order, bytes.Clone(root))
	}
	c.records[string(root)] = bytes.Clone(record)
}

func (c *sp220Checkpoints) selectors() *state.ProtectedChildCheckpoints {
	return &state.ProtectedChildCheckpoints{
		Locate: func(checkpoint common.RootHashHolder) ([]state.ProtectedChildLocator, error) {
			c.mutex.Lock()
			defer c.mutex.Unlock()
			if c.fail != nil {
				return nil, c.fail
			}
			record, exists := c.records[string(checkpoint.GetRootHash())]
			if !exists {
				return nil, fmt.Errorf("checkpoint %x is not retained", checkpoint.GetRootHash())
			}
			return []state.ProtectedChildLocator{{Address: bytes.Clone(core.SystemAccountAddress), Key: bytes.Clone(sp220ChildRecord), Record: bytes.Clone(record)}}, nil
		},
		Retained: func() ([]common.RootHashHolder, error) {
			c.mutex.Lock()
			defer c.mutex.Unlock()
			if c.fail != nil {
				return nil, c.fail
			}
			retained := c.order
			if len(retained) > 2 {
				retained = retained[len(retained)-2:]
			}
			roots := make([]common.RootHashHolder, 0, len(retained))
			for _, root := range retained {
				roots = append(roots, holders.NewDefaultRootHashesHolder(bytes.Clone(root)))
			}
			return roots, nil
		},
		ReadNode: func(hash []byte, db common.TrieStorageInteractor) ([]common.TrieNodeData, error) {
			return trie.GetNodeDataFromHash(hash, keyBuilder.NewKeyBuilder(), db, integrationTests.TestMarshalizer, integrationTests.TestHasher)
		},
		MaxLocators: 1, MaxCheckpoints: 2, MaxBytes: 1 << 20,
	}
}

// sp220Disk is one node's database directory: a LevelDB database per epoch,
// created, closed and reopened by the native pruning storer.
type sp220Disk struct {
	directory string
}

func sp220NewDisk(t *testing.T) *sp220Disk {
	return &sp220Disk{directory: t.TempDir()}
}

func (d *sp220Disk) open(path string) (storage.Persister, error) {
	return storageunit.NewDB(storageunit.ArgDB{
		DBType: storageunit.LvlDBSerial, Path: filepath.Join(d.directory, filepath.FromSlash(path)),
		BatchDelaySeconds: 1, MaxBatchSize: 10, MaxOpenFiles: 10,
	})
}

type sp220Store struct {
	t           *testing.T
	disk        *sp220Disk
	checkpoints *sp220Checkpoints
	storer      storage.Storer
	manager     common.StorageManager
	main        common.Trie
	adb         *state.AccountsDB
	// retention is false only in the control store.
	retention bool
}

func sp220Open(t *testing.T, disk *sp220Disk, checkpoints *sp220Checkpoints, epoch uint32, retention bool) (*sp220Store, func(uint32)) {
	t.Helper()
	s := &sp220Store{t: t, disk: disk, checkpoints: checkpoints, retention: retention}
	epochs := notifier.NewEpochStartSubscriptionHandler()
	epochsData := pruning.EpochArgs{NumOfEpochsToKeep: 4, NumOfActivePersisters: 4, StartingEpoch: epoch}
	var err error
	s.storer, err = pruning.NewTriePruningStorer(pruning.StorerArgs{
		PruningEnabled: true, Identifier: "id", ShardCoordinator: &testscommon.ShardsCoordinatorMock{},
		PathManager: &testscommon.PathManagerStub{PathForEpochCalled: func(shard string, epoch uint32, identifier string) string {
			return fmt.Sprintf("Epoch_%d/Shard_%s/%s", epoch, shard, identifier)
		}},
		CacheConf:              storageunit.CacheConfig{Capacity: 10, Type: "LRU", Shards: 3},
		DbPath:                 "path/Epoch_0/Shard_1",
		PersisterFactory:       &storageMock.PersisterFactoryStub{CreateCalled: disk.open},
		EpochsData:             epochsData,
		Notifier:               epochs,
		OldDataCleanerProvider: &testscommon.OldDataCleanerProviderStub{},
		CustomDatabaseRemover:  &testscommon.CustomDatabaseRemoverStub{},
		MaxBatchSize:           10,
		PersistersTracker:      pruning.NewPersistersTracker(epochsData),
		StateStatsHandler:      disabled.NewStateStatistics(),
	})
	require.NoError(t, err)
	args := storageStubs.GetStorageManagerArgs()
	args.MainStorer, args.Marshalizer, args.Hasher = s.storer, integrationTests.TestMarshalizer, integrationTests.TestHasher
	s.manager, err = trie.NewTrieStorageManager(args)
	require.NoError(t, err)
	flags := &enableEpochsHandlerMock.EnableEpochsHandlerStub{}
	s.main, err = trie.NewTrie(s.manager, integrationTests.TestMarshalizer, integrationTests.TestHasher, flags, 5)
	require.NoError(t, err)
	waiting, err := evictionWaitingList.NewMemoryEvictionWaitingList(evictionWaitingList.MemoryEvictionWaitingListArgs{RootHashesSize: 100, HashesSize: 10000})
	require.NoError(t, err)
	pruner, err := storagePruningManager.NewStoragePruningManager(waiting, 10)
	require.NoError(t, err)
	accountFactory, err := factory.NewAccountCreator(factory.ArgsAccountCreator{Hasher: integrationTests.TestHasher,
		Marshaller: integrationTests.TestMarshalizer, EnableEpochsHandler: flags, StateAccessesCollector: stateDisabled.NewDisabledStateAccessesCollector()})
	require.NoError(t, err)
	snapshots, err := state.NewSnapshotsManager(state.ArgsNewSnapshotsManager{
		ProcessingMode: common.Normal, Marshaller: integrationTests.TestMarshalizer,
		AddressConverter: &testscommon.PubkeyConverterMock{}, ProcessStatusHandler: &testscommon.ProcessStatusHandlerStub{},
		StateMetrics: &stateMock.StateMetricsStub{}, AccountFactory: accountFactory,
		ChannelsProvider:   iteratorChannelsProvider.NewUserStateIteratorChannelsProvider(),
		LastSnapshotMarker: lastSnapshotMarker.NewLastSnapshotMarker(), StateStatsHandler: statistics.NewStateStatistics(),
	})
	require.NoError(t, err)
	require.NoError(t, snapshots.SetSyncer(&mock.AccountsDBSyncerStub{SyncAccountsCalled: func([]byte, common.StorageMarker) error {
		return errors.New("no node transport in this test")
	}}))
	var selectors *state.ProtectedChildCheckpoints
	if retention {
		selectors = checkpoints.selectors()
	}
	s.adb, err = state.NewAccountsDB(state.ArgsAccountsDB{
		Trie: s.main, Hasher: integrationTests.TestHasher, Marshaller: integrationTests.TestMarshalizer,
		AccountFactory: accountFactory, StoragePruningManager: pruner, AddressConverter: &testscommon.PubkeyConverterMock{},
		SnapshotsManager: snapshots, StateAccessesCollector: stateDisabled.NewDisabledStateAccessesCollector(), PruningEnabled: true,
		ProtectedChildRoot: func(address, key, record []byte) ([]byte, error) {
			if !bytes.Equal(address, core.SystemAccountAddress) || !bytes.Equal(key, sp220ChildRecord) || len(record) != integrationTests.TestHasher.Size() {
				return nil, errors.New("not a child-binding record")
			}
			return record, nil
		},
		ProtectedChildCheckpoints: selectors,
	})
	require.NoError(t, err)
	setEpoch := func(next uint32) {
		s.storer.(types.StorerWithPutInEpoch).SetEpochForPutOperation(next)
		epochs.NotifyAll(&block.Header{Epoch: next})
	}
	return s, setEpoch
}

func (s *sp220Store) close() {
	require.NoError(s.t, s.adb.Close())
	require.NoError(s.t, s.manager.Close())
}

func (s *sp220Store) write(address, key, value []byte) {
	account, err := s.adb.LoadAccount(address)
	require.NoError(s.t, err)
	require.NoError(s.t, account.(state.UserAccountHandler).SaveKeyValue(key, value))
	require.NoError(s.t, s.adb.SaveAccount(account))
}

func (s *sp220Store) read(address, key []byte) ([]byte, error) {
	account, err := s.adb.GetExistingAccount(address)
	if err != nil {
		return nil, err
	}
	value, _, err := account.(state.UserAccountHandler).RetrieveValue(key)
	return bytes.Clone(value), err
}

// sp220Expected is the protected substate and the ordinary keys at one root.
type sp220Expected struct {
	root      []byte
	records   map[string][]byte
	ordinary  map[string][]byte
	childRoot []byte
	leaves    []core.TrieData
}

func (s *sp220Store) check(expected *sp220Expected) error {
	if err := s.adb.RecreateTrie(holders.NewDefaultRootHashesHolder(expected.root)); err != nil {
		return err
	}
	for key, record := range expected.records {
		value, err := s.read(core.SystemAccountAddress, []byte(key))
		if err != nil {
			return err
		}
		if !bytes.Equal(record, value) {
			return fmt.Errorf("protected record %q changed: %x, expected %x", key, value, record)
		}
	}
	for key, want := range expected.ordinary {
		for _, address := range [][]byte{core.SystemAccountAddress, sp220Ordinary} {
			value, err := s.read(address, []byte(key))
			if err != nil {
				return err
			}
			if !bytes.Equal(want, value) {
				return fmt.Errorf("ordinary key %q changed", key)
			}
		}
	}
	if common.IsEmptyTrie(expected.childRoot) {
		_, err := s.adb.RecreateAllTries(expected.root)
		return err
	}
	keys := make([][]byte, len(expected.leaves))
	for i := range expected.leaves {
		keys[i] = expected.leaves[i].Key
	}
	leaves, err := s.adb.ReadProtectedChildLeaves(core.SystemAccountAddress, sp220ChildRecord, expected.childRoot, keys)
	if err != nil {
		return err
	}
	for i := range leaves {
		if !bytes.Equal(leaves[i].Value, expected.leaves[i].Value) {
			return fmt.Errorf("child leaf %q changed", keys[i])
		}
	}
	tries, err := s.adb.RecreateAllTries(expected.root)
	if err != nil || !s.retention {
		return err
	}
	child, exists := tries[string(expected.childRoot)]
	if !exists {
		return errors.New("the child trie is not reachable from the checkpoint")
	}
	for i := range expected.leaves {
		value, _, readErr := child.Get(keys[i])
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(value, expected.leaves[i].Value) {
			return fmt.Errorf("child leaf %q changed in the reopened child", keys[i])
		}
	}
	return nil
}

func sp220Serve(source common.StorageManager, cacher storage.Cacher, withheld map[string]struct{}) *testscommon.RequestHandlerStub {
	serve := func(hashes [][]byte) {
		for _, hash := range hashes {
			if _, skip := withheld[string(hash)]; skip {
				continue
			}
			value, err := source.Get(hash)
			if err != nil {
				continue
			}
			node, err := trie.NewInterceptedTrieNode(value, integrationTests.TestHasher)
			if err != nil {
				continue
			}
			cacher.Put(hash, node, len(value))
		}
	}
	return &testscommon.RequestHandlerStub{
		RequestTrieNodesCalled:         func(_ uint32, hashes [][]byte, _ string) { serve(hashes) },
		RequestTrieNodesForEpochCalled: func(_ uint32, hashes [][]byte, _ string, _ uint32) { serve(hashes) },
	}
}

type sp220Marker struct{ marked bool }

func (m *sp220Marker) IsInterfaceNil() bool                                { return m == nil }
func (m *sp220Marker) MarkStorerAsSyncedAndActive(_ common.StorageManager) { m.marked = true }

func sp220Syncer(t *testing.T, target *sp220Store, source common.StorageManager, withheld map[string]struct{}, timeout time.Duration) interface {
	SyncAccounts(rootHash []byte, storageMarker common.StorageMarker) error
	SyncAccountsWithDiskCheck(rootHash []byte, storageMarker common.StorageMarker, epoch uint32) error
} {
	t.Helper()
	cacher := cache.NewCacherMock()
	limiter, err := throttler.NewNumGoRoutinesThrottler(2)
	require.NoError(t, err)
	accountsSyncer, err := syncer.NewUserAccountsSyncer(syncer.ArgsNewUserAccountsSyncer{
		ArgsNewBaseAccountsSyncer: syncer.ArgsNewBaseAccountsSyncer{
			Hasher: integrationTests.TestHasher, Marshalizer: integrationTests.TestMarshalizer,
			TrieStorageManager: target.manager, RequestHandler: sp220Serve(source, cacher, withheld),
			Timeout: timeout, Cacher: cacher,
			UserAccountsSyncStatisticsHandler: &testscommon.SizeSyncStatisticsHandlerStub{},
			AppStatusHandler:                  &statusHandler.AppStatusHandlerStub{},
			EnableEpochsHandler:               &enableEpochsHandlerMock.EnableEpochsHandlerStub{},
			MaxTrieLevelInMemory:              5, MaxHardCapForMissingNodes: 100, TrieSyncerVersion: 2,
		},
		ShardId: 0, Throttler: limiter, AddressPubKeyConverter: &testscommon.PubkeyConverterMock{},
		ProtectedChildren: target.adb.ProtectedChildResolver(),
	})
	require.NoError(t, err)
	return accountsSyncer
}

// sp220History runs eight epochs of blocks on a new multi-epoch store. Each
// epoch starts with the native snapshot; each block commits and prunes the
// previous root. The child changes only in epochs 1-3. It returns the first
// failed check when stopOnError is set (the control without retention).
func sp220History(t *testing.T, disk *sp220Disk, checkpoints *sp220Checkpoints, retention bool) (*sp220Store, *sp220Expected, error) {
	t.Helper()
	store, setEpoch := sp220Open(t, disk, checkpoints, 0, retention)
	expected := &sp220Expected{
		records: map[string][]byte{
			sp220Domain + "membership@TOKEN-000001": {1},
			sp220Domain + "membershipIndex@count":   {0, 0, 0, 0, 0, 0, 0, 1},
			sp220Domain + "supply@TOKEN-000001":     []byte("protocol-owned supply record"),
		},
		ordinary: map[string][]byte{"ordinary-existing-leaf": []byte("untouched"), "DRWA@membership@TOKEN-000001": []byte("look-alike")},
	}
	for key, value := range expected.records {
		store.write(core.SystemAccountAddress, []byte(key), value)
	}
	store.write(core.SystemAccountAddress, sp220ChildRecord, common.EmptyTrieHash)
	for key, value := range expected.ordinary {
		store.write(core.SystemAccountAddress, []byte(key), value)
		store.write(sp220Ordinary, []byte(key), value)
	}
	record := bytes.Clone(common.EmptyTrieHash)
	previous, err := store.adb.Commit()
	require.NoError(t, err)
	checkpoints.add(previous, record)
	expected.root, expected.childRoot = previous, bytes.Clone(record)
	expected.records[string(sp220ChildRecord)] = bytes.Clone(record)

	advance := func(block int, changeChild bool) error {
		if changeChild {
			for i := 0; i < 20; i++ {
				leaf := core.TrieData{Key: []byte(fmt.Sprintf("nonce-%03d", i)), Value: []byte(fmt.Sprintf("issued=%d/block=%d", i, block)), Version: core.NotSpecified}
				next, stageErr := store.adb.StageDerivedProtectedChildTrie(core.SystemAccountAddress, sp220ChildRecord, record, [][]byte{leaf.Key},
					func([]core.TrieData) ([]core.TrieData, error) { return []core.TrieData{leaf}, nil },
					func(root []byte) ([]byte, error) { return root, nil })
				if stageErr != nil {
					return stageErr
				}
				record = next
				if len(expected.leaves) <= i {
					expected.leaves = append(expected.leaves, leaf)
				}
				expected.leaves[i] = leaf
			}
			expected.childRoot = bytes.Clone(record)
			expected.records[string(sp220ChildRecord)] = bytes.Clone(record)
		}
		expected.ordinary["counter"] = []byte(fmt.Sprintf("block-%d", block))
		store.write(core.SystemAccountAddress, []byte("counter"), expected.ordinary["counter"])
		store.write(sp220Ordinary, []byte("counter"), expected.ordinary["counter"])
		root, commitErr := store.adb.Commit()
		if commitErr != nil {
			return commitErr
		}
		checkpoints.add(root, record)
		store.adb.CancelPrune(root, state.NewRoot)
		store.adb.PruneTrie(previous, state.OldRoot, state.NewPruningHandler(state.EnableDataRemoval))
		previous, expected.root = root, root
		return store.check(expected)
	}
	snapshot := func(epoch uint32) error {
		store.adb.SnapshotState(expected.root, epoch)
		require.Eventually(t, func() bool { return !store.adb.IsSnapshotInProgress() }, 10*time.Second, time.Millisecond)
		return store.check(expected)
	}
	block := 0
	for epoch := uint32(1); epoch <= 8; epoch++ {
		setEpoch(epoch)
		if err = snapshot(epoch); err != nil {
			return store, expected, fmt.Errorf("after the snapshot of epoch %d: %w", epoch, err)
		}
		for i := 0; i < 3; i++ {
			block++
			if err = advance(block, epoch <= 3); err != nil {
				return store, expected, fmt.Errorf("after block %d of epoch %d: %w", block, epoch, err)
			}
		}
	}
	latest, err := store.storer.(interface{ GetLatestStorageEpoch() (uint32, error) }).GetLatestStorageEpoch()
	require.NoError(t, err)
	require.Equal(t, uint32(8), latest)
	return store, expected, snapshot(8)
}

func TestQualSP220ProtectedStateRestartAndRecovery(t *testing.T) {
	checkpoints := &sp220Checkpoints{records: map[string][]byte{}}
	disk := sp220NewDisk(t)
	store, expected, err := sp220History(t, disk, checkpoints, true)
	require.NoError(t, err)
	final := *expected

	t.Run("control_without_retention_is_an_error", func(t *testing.T) {
		// The same history on a store that does not carry the protected child
		// through snapshot and pruning. The child's data leaves the active
		// epochs, and that is reported as an error, never as an empty child.
		_, lost, controlErr := sp220History(t, sp220NewDisk(t), &sp220Checkpoints{records: map[string][]byte{}}, false)
		require.Error(t, controlErr)
		t.Log("control:", controlErr)
		require.NotEmpty(t, lost.leaves)
	})

	t.Run("restart", func(t *testing.T) {
		store.close()
		reopened, _ := sp220Open(t, disk, checkpoints, 8, true)
		require.NoError(t, reopened.check(&final))
		store = reopened
	})

	// The child root node and the node holding the system account's data root.
	systemAccount, err := store.adb.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	dataRoot := systemAccount.(state.UserAccountHandler).GetRootHash()
	require.NotEmpty(t, dataRoot)

	var synced *sp220Store
	// The synced store is used by the next stage: its directory belongs to
	// the whole test, not to the subtest that fills it.
	syncedDisk := sp220NewDisk(t)
	t.Run("state_sync_from_another_store", func(t *testing.T) {
		for _, withheld := range [][]byte{final.childRoot, dataRoot} {
			// A source that cannot supply a node of the protected substate
			// fails the sync and the target is not marked ready.
			target, _ := sp220Open(t, sp220NewDisk(t), checkpoints, 8, true)
			marker := &sp220Marker{}
			accountsSyncer := sp220Syncer(t, target, store.manager, map[string]struct{}{string(withheld): {}}, time.Second)
			require.Error(t, accountsSyncer.SyncAccounts(final.root, marker))
			require.False(t, marker.marked)
			require.Error(t, target.check(&final), "an incomplete target reports an error, not an empty substate")
			target.close()
		}
		checkpoints.mutex.Lock()
		checkpoints.fail = errors.New("checkpoint relation unavailable")
		checkpoints.mutex.Unlock()
		target, _ := sp220Open(t, syncedDisk, checkpoints, 8, true)
		marker := &sp220Marker{}
		require.ErrorContains(t, sp220Syncer(t, target, store.manager, nil, 5*time.Second).SyncAccounts(final.root, marker), "checkpoint relation unavailable")
		require.False(t, marker.marked)
		checkpoints.mutex.Lock()
		checkpoints.fail = nil
		checkpoints.mutex.Unlock()

		require.NoError(t, sp220Syncer(t, target, store.manager, nil, 5*time.Second).SyncAccounts(final.root, marker))
		require.True(t, marker.marked)
		require.NoError(t, target.check(&final))
		synced = target
	})
	require.NotNil(t, synced)

	t.Run("recovery_trie_repair", func(t *testing.T) {
		remover := synced.storer.(interface{ RemoveFromAllActiveEpochs(key []byte) error })
		for _, hash := range [][]byte{final.childRoot, dataRoot} {
			node, getErr := synced.manager.Get(hash)
			require.NoError(t, getErr)
			require.NoError(t, remover.RemoveFromAllActiveEpochs(hash))
			_, getErr = synced.manager.Get(hash)
			require.Error(t, getErr)

			// Damage is an error on every read of the substate.
			require.Error(t, synced.check(&final))
			marker := &sp220Marker{}
			// A repair whose source lacks the node fails and marks nothing.
			failing := sp220Syncer(t, synced, store.manager, map[string]struct{}{string(hash): {}}, time.Second)
			require.Error(t, failing.SyncAccountsWithDiskCheck(final.root, marker, 8))
			require.False(t, marker.marked)
			require.Error(t, synced.check(&final))

			// The recovery-trie repair path restores exactly the stored bytes.
			require.NoError(t, sp220Syncer(t, synced, store.manager, nil, 5*time.Second).SyncAccountsWithDiskCheck(final.root, marker, 8))
			require.True(t, marker.marked)
			repaired, getErr := synced.manager.Get(hash)
			require.NoError(t, getErr)
			require.Equal(t, node, repaired)
			require.NoError(t, synced.check(&final))
		}
		// The repaired store restarts with the same substate.
		disk := synced.disk
		synced.close()
		reopened, _ := sp220Open(t, disk, checkpoints, 8, true)
		require.NoError(t, reopened.check(&final))
		reopened.close()
	})
	// The source was only read by sync and repair.
	require.NoError(t, store.check(&final))
	store.close()
}
