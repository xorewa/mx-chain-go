package genesis

import (
	"bytes"
	"fmt"
	"sort"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/state"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	pruningDisabled "github.com/multiversx/mx-chain-go/state/storagePruningManager/disabled"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/hashingMocks"
	testStorage "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/multiversx/mx-chain-go/trie/keyBuilder"
	"github.com/multiversx/mx-chain-go/update/mock"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAA19ProtectedChildHardforkRoundTrip(t *testing.T) {
	msh, hsh := &marshal.GogoProtoMarshalizer{}, &hashingMocks.HasherMock{}
	flags := &enableEpochsHandlerMock.EnableEpochsHandlerStub{}
	newStorage := func(t *testing.T) common.StorageManager {
		t.Helper()
		args := testStorage.GetStorageManagerArgs()
		args.Marshalizer, args.Hasher = msh, hsh
		storage, err := trie.NewTrieStorageManager(args)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, storage.Close()) })
		return storage
	}
	owner := bytes.Repeat([]byte{1}, 32)
	recordKey := []byte(core.ProtectedKeyPrefix + "synthetic/a19/nonce-root")
	key, history := []byte("synthetic-nonce"), []byte("issued=5/live=0")
	decode := func(address, key, record []byte) ([]byte, error) {
		if !bytes.Equal(address, owner) || !bytes.Equal(key, recordKey) || len(record) != hsh.Size() {
			return nil, fmt.Errorf("unknown synthetic child record")
		}
		return record, nil
	}
	var checkpoint, committedChild []byte
	selectors := &state.ProtectedChildCheckpoints{
		Locate: func(ref common.RootHashHolder) ([]state.ProtectedChildLocator, error) {
			if !bytes.Equal(ref.GetRootHash(), checkpoint) {
				return nil, fmt.Errorf("unknown synthetic checkpoint")
			}
			return []state.ProtectedChildLocator{{Address: owner, Key: recordKey, Record: committedChild}}, nil
		},
		Retained: func() ([]common.RootHashHolder, error) {
			return []common.RootHashHolder{holders.NewDefaultRootHashesHolder(checkpoint)}, nil
		},
		ReadNode: func(hash []byte, storage common.TrieStorageInteractor) ([]common.TrieNodeData, error) {
			return trie.GetNodeDataFromHash(hash, keyBuilder.NewKeyBuilder(), storage, msh, hsh)
		},
		MaxLocators: 1, MaxCheckpoints: 1, MaxBytes: 4096,
	}
	main, err := trie.NewTrie(newStorage(t), msh, hsh, flags, maxTrieLevelInMemory)
	require.NoError(t, err)
	accFactory, err := newAccountCreator(UserAccount, hsh, msh, flags)
	require.NoError(t, err)
	adb, err := state.NewAccountsDB(state.ArgsAccountsDB{
		Trie: main, Hasher: hsh, Marshaller: msh, AccountFactory: accFactory,
		StoragePruningManager: pruningDisabled.NewDisabledStoragePruningManager(),
		AddressConverter:      &testscommon.PubkeyConverterMock{}, SnapshotsManager: stateDisabled.NewDisabledSnapshotsManager(),
		StateAccessesCollector: stateDisabled.NewDisabledStateAccessesCollector(),
		ProtectedChildRoot:     decode, ProtectedChildCheckpoints: selectors,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adb.Close()) })
	account, err := adb.LoadAccount(owner)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(recordKey, common.EmptyTrieHash))
	require.NoError(t, adb.SaveAccount(account))
	_, err = adb.Commit()
	require.NoError(t, err)

	child, err := main.Recreate(holders.NewDefaultRootHashesHolder(common.EmptyTrieHash))
	require.NoError(t, err)
	require.NoError(t, child.Update(key, history))
	childRoot, err := child.RootHash()
	require.NoError(t, err)
	committedChild = bytes.Clone(childRoot)
	require.NoError(t, adb.StageProtectedChildTrie(owner, recordKey, common.EmptyTrieHash, childRoot,
		[]core.TrieData{{Key: key, Value: history, Version: core.NotSpecified}}))
	checkpoint, err = adb.Commit()
	require.NoError(t, err)
	recreated, err := adb.RecreateAllTries(checkpoint)
	require.NoError(t, err)

	tries := make(map[string]common.Trie)
	for hash, tree := range recreated {
		if hash == string(checkpoint) {
			tries[CreateTrieIdentifier(0, UserAccount)] = tree
			continue
		}
		tries[AddRootHashToIdentifier(CreateTrieIdentifier(0, DataTrie), hash)] = tree
	}

	childID := AddRootHashToIdentifier(CreateTrieIdentifier(0, DataTrie), string(childRoot))
	exported := make(map[string][][]byte)
	values := make(map[string]map[string][]byte)
	bundle := &mock.HardforkStorerStub{
		WriteCalled: func(id string, key, value []byte) error {
			exported[id] = append(exported[id], bytes.Clone(key))
			if values[id] == nil {
				values[id] = make(map[string][]byte)
			}
			values[id][string(key)] = bytes.Clone(value)
			return nil
		},
	}
	args := getDefaultStateExporterArgs()
	args.Hasher, args.Marshalizer, args.ProtectedChildren = hsh, msh, adb.ProtectedChildResolver()
	args.StateSyncer = &mock.StateSyncStub{GetAllTriesCalled: func() (map[string]common.Trie, error) { return tries, nil }}
	args.HardforkStorer = bundle
	exporter, err := NewStateExporter(args)
	require.NoError(t, err)
	mainID := CreateTrieIdentifier(0, UserAccount)
	accountTrie := tries[mainID]
	delete(tries, mainID)
	require.ErrorContains(t, exporter.exportAllTries(), "protected account checkpoint absent")
	require.Empty(t, exported)
	tries[mainID] = accountTrie

	physical := tries[childID]
	delete(tries, childID)
	require.ErrorContains(t, exporter.exportAllTries(), "required protected child absent")
	require.Empty(t, exported)
	tries[childID] = physical
	require.NoError(t, exporter.exportAllTries())

	for _, fault := range []string{"none", "missing", "mismatched"} {
		t.Run(fault, func(t *testing.T) {
			childFile := TrieIdentifier + atSep + childID
			reader := &mock.HardforkStorerStub{
				RangeKeysCalled: func(consume func(string, [][]byte) bool) {
					ids := make([]string, 0, len(exported))
					for id := range exported {
						if fault != "missing" || id != childFile {
							ids = append(ids, id)
						}
					}
					sort.Strings(ids)
					for _, id := range ids {
						if !consume(id, exported[id]) {
							return
						}
					}
				},
				GetCalled: func(id string, key []byte) ([]byte, error) {
					if fault == "mismatched" && id == childFile && bytes.Equal(key, exported[id][1]) {
						return []byte("different native leaf"), nil
					}
					return bytes.Clone(values[id][string(key)]), nil
				},
			}
			importer, err := NewStateImport(ArgsNewStateImport{
				Hasher: hsh, Marshalizer: msh, EnableEpochsHandler: flags, HardforkStorer: reader,
				AddressConverter:    &testscommon.PubkeyConverterMock{},
				TrieStorageManagers: map[string]common.StorageManager{dataRetriever.UserAccountsUnit.String(): newStorage(t)},
				ProtectedChildRoot:  decode, ProtectedCheckpoints: selectors, ExpectedProtectedRoots: map[uint32][]byte{0: checkpoint},
			})
			require.NoError(t, err)
			require.Nil(t, importer.GetAccountsDBForShard(0))
			err = importer.ImportAll()
			if fault != "none" {
				require.Error(t, err)
				require.Nil(t, importer.GetAccountsDBForShard(0))
				return
			}
			require.NoError(t, err)
			imported := importer.GetAccountsDBForShard(0)
			require.NotNil(t, imported)
			physical, err := imported.GetTrie(childRoot)
			require.NoError(t, err)
			got, _, err := physical.Get(key)
			require.NoError(t, err)
			require.Equal(t, history, got)
		})
	}
}
