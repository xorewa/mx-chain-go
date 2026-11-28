package syncer

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/api/mock"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/factory"
	"github.com/multiversx/mx-chain-go/state/storagePruningManager/disabled"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/testscommon"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/multiversx/mx-chain-go/trie/keyBuilder"
	"github.com/stretchr/testify/require"
)

func TestQualLaneZ2ProtectedChildSyncLocalOutcomes(t *testing.T) {
	writeUnavailable := errors.New("fixture storage write unavailable")
	readUnavailable := errors.New("fixture node reader unavailable")
	for _, tc := range []struct {
		name     string
		empty    bool
		writeErr error
		readErr  error
	}{
		{name: "nonempty child"},
		{name: "empty child", empty: true},
		{name: "storage write error", writeErr: writeUnavailable},
		{name: "verification read error", readErr: readUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := getDefaultBaseAccSyncerArgs()
			args.Marshalizer = &testscommon.ProtobufMarshalizerMock{}
			args.TrieSyncerVersion = 3
			args.Timeout = 5 * time.Second
			nodes := make(map[string][]byte)
			store := &storageManager.StorageManagerStub{}
			store.GetBaseTrieStorageManagerCalled = func() common.StorageManager { return store }
			store.GetCalled = func(key []byte) ([]byte, error) {
				value, ok := nodes[string(key)]
				if !ok {
					return nil, storage.ErrKeyNotFound
				}
				return bytes.Clone(value), nil
			}
			store.PutCalled = func(key, value []byte) error {
				nodes[string(key)] = bytes.Clone(value)
				return nil
			}
			args.TrieStorageManager = store
			main, err := trie.NewTrie(store, args.Marshalizer, args.Hasher, args.EnableEpochsHandler, 5)
			require.NoError(t, err)

			address := bytes.Repeat([]byte{1}, 32)
			locator := []byte(core.ProtectedKeyPrefix + "fixture/z2/child")
			leaf := core.TrieData{Key: []byte("local-key"), Value: []byte("local-value"), Version: core.NotSpecified}
			childRoot := bytes.Clone(common.EmptyTrieHash)
			var checkpoint []byte
			readCalls := 0
			checkpoints := &state.ProtectedChildCheckpoints{
				Locate: func(root common.RootHashHolder) ([]state.ProtectedChildLocator, error) {
					require.Equal(t, checkpoint, root.GetRootHash())
					require.False(t, root.GetEpoch().HasValue)
					return []state.ProtectedChildLocator{{Address: address, Key: locator, Record: childRoot}}, nil
				},
				Retained: func() ([]common.RootHashHolder, error) {
					return []common.RootHashHolder{holders.NewDefaultRootHashesHolder(checkpoint)}, nil
				},
				ReadNode: func(hash []byte, reader common.TrieStorageInteractor) ([]common.TrieNodeData, error) {
					readCalls++
					require.Equal(t, childRoot, hash)
					if tc.readErr != nil {
						return nil, tc.readErr
					}
					return trie.GetNodeDataFromHash(hash, keyBuilder.NewKeyBuilder(), reader, args.Marshalizer, args.Hasher)
				},
				MaxLocators: 1, MaxCheckpoints: 1, MaxBytes: 4096,
			}
			collector := &stateMock.StateAccessesCollectorStub{}
			creator, err := factory.NewAccountCreator(factory.ArgsAccountCreator{
				Hasher: args.Hasher, Marshaller: args.Marshalizer, EnableEpochsHandler: args.EnableEpochsHandler,
				StateAccessesCollector: collector,
			})
			require.NoError(t, err)
			db, err := state.NewAccountsDB(state.ArgsAccountsDB{
				Trie: main, Hasher: args.Hasher, Marshaller: args.Marshalizer, AccountFactory: creator,
				StoragePruningManager: disabled.NewDisabledStoragePruningManager(), AddressConverter: &testscommon.PubkeyConverterMock{},
				SnapshotsManager: &stateMock.SnapshotsManagerStub{}, StateAccessesCollector: collector,
				ProtectedChildRoot: func(owner, key, record []byte) ([]byte, error) {
					require.Equal(t, address, owner)
					require.Equal(t, locator, key)
					require.Len(t, record, args.Hasher.Size())
					return bytes.Clone(record), nil
				},
				ProtectedChildCheckpoints: checkpoints,
			})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			account, err := db.LoadAccount(address)
			require.NoError(t, err)
			require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(locator, childRoot))
			require.NoError(t, db.SaveAccount(account))
			checkpoint, err = db.Commit()
			require.NoError(t, err)
			if !tc.empty {
				child, createErr := main.Recreate(holders.NewDefaultRootHashesHolder(common.EmptyTrieHash))
				require.NoError(t, createErr)
				require.NoError(t, child.Update(leaf.Key, leaf.Value))
				childRoot, err = child.RootHash()
				require.NoError(t, err)
				require.NoError(t, db.StageProtectedChildTrie(address, locator, common.EmptyTrieHash, childRoot, []core.TrieData{leaf}))
				checkpoint, err = db.Commit()
				require.NoError(t, err)
				require.NotEmpty(t, nodes[string(childRoot)])
			}

			writes := 0
			store.PutInEpochCalled = func(key, value []byte, _ uint32) error {
				writes++
				require.Equal(t, childRoot, key)
				if tc.writeErr != nil {
					return tc.writeErr
				}
				return store.Put(key, value)
			}
			args.RequestHandler = &testscommon.RequestHandlerStub{
				RequestTrieNodesCalled: func(uint32, [][]byte, string) { t.Fatal("local fixture must not request trie nodes") },
			}
			u, err := NewUserAccountsSyncer(ArgsNewUserAccountsSyncer{
				ArgsNewBaseAccountsSyncer: args, Throttler: &mock.ThrottlerStub{},
				AddressPubKeyConverter: &testscommon.PubkeyConverterStub{}, ProtectedChildren: db.ProtectedChildResolver(),
			})
			require.NoError(t, err)
			u.timeoutHandler.ResetWatchdog()
			err = u.syncProtectedChildren(context.Background(), checkpoint, true, args.RequestHandler)
			if tc.empty {
				require.NoError(t, err)
				require.Zero(t, writes)
				require.Zero(t, readCalls)
				require.Empty(t, u.dataTries)
				return
			}
			require.Equal(t, 1, writes)
			if tc.writeErr != nil {
				require.ErrorIs(t, err, tc.writeErr)
				require.Zero(t, readCalls)
				require.Empty(t, u.dataTries)
				return
			}
			require.Equal(t, 1, readCalls)
			if tc.readErr != nil {
				require.ErrorIs(t, err, tc.readErr)
				require.Empty(t, u.dataTries)
				return
			}
			require.NoError(t, err)
			require.Equal(t, map[string]struct{}{string(childRoot): {}}, u.dataTries)
			reopened, err := main.Recreate(holders.NewDefaultRootHashesHolder(childRoot))
			require.NoError(t, err)
			got, _, err := reopened.Get(leaf.Key)
			require.NoError(t, err)
			require.Equal(t, leaf.Value, got)
		})
	}
}
