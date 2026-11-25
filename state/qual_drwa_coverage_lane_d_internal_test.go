package state

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/sha256"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/errChan"
	storagemock "github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/stretchr/testify/require"
)

func TestQualLaneDProtectedChildPruningMembership(t *testing.T) {
	handler := &protectedPruningHandler{keep: common.ModifiedHashes{"retained": {}}}
	require.True(t, handler.KeepProtectedTrieNode("retained"))
	require.False(t, handler.KeepProtectedTrieNode("ordinary"))
}

type laneDProtectedAccountReader struct {
	common.Trie
	get func([]byte) ([]byte, uint32, error)
}

func (reader *laneDProtectedAccountReader) Get(key []byte) ([]byte, uint32, error) {
	return reader.get(key)
}

func TestQualLaneDProtectedChildPredecessorReadRefusals(t *testing.T) {
	address := []byte("public fixture account")
	readFailure := errors.New("fixture account read failed")
	for _, tc := range []struct {
		name     string
		readErr  error
		expected error
	}{
		{name: "absent account", expected: errProtectedChild},
		{name: "read error", readErr: readFailure, expected: readFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			adb := &AccountsDB{mainTrie: &laneDProtectedAccountReader{
				get: func(key []byte) ([]byte, uint32, error) {
					calls++
					require.Equal(t, address, key)
					return nil, 0, tc.readErr
				},
			}}
			account, err := adb.protectedChildPredecessorAccount(address, []byte("fixture key"), []byte("fixture prior value"))
			require.ErrorIs(t, err, tc.expected)
			require.Nil(t, account)
			require.Equal(t, 1, calls)
		})
	}
}

type laneDProtectedLeafReader struct {
	DataTrie
	get func([]byte) ([]byte, uint32, uint32, error)
}

func (reader *laneDProtectedLeafReader) GetWithVersion(key []byte) ([]byte, uint32, uint32, error) {
	return reader.get(key)
}

func TestQualLaneDProtectedChildLeafReadRefusal(t *testing.T) {
	keys := [][]byte{[]byte("first"), []byte("second"), []byte("later")}
	readErr := errors.New("fixture leaf read failed")
	var reads [][]byte
	trie := &laneDProtectedLeafReader{get: func(key []byte) ([]byte, uint32, uint32, error) {
		reads = append(reads, key)
		if len(reads) == 1 {
			return []byte("fixture leaf"), 0, uint32(core.NotSpecified), nil
		}
		return nil, 0, 0, readErr
	}}

	leaves, err := readProtectedChildLeaves(trie, keys)
	require.ErrorIs(t, err, readErr)
	require.Nil(t, leaves)
	require.Equal(t, keys[:2], reads)
}

type laneDProtectedChildView struct {
	common.Trie
	store common.StorageManager
}

func (view *laneDProtectedChildView) GetStorageManager() common.StorageManager {
	return view.store
}

func (view *laneDProtectedChildView) IsInterfaceNil() bool {
	return view == nil
}

func TestQualLaneDProtectedChildReferenceStoreMatch(t *testing.T) {
	base := &storagemock.StorageManagerStub{}
	otherBase := &storagemock.StorageManagerStub{}
	snapshotStore := &storagemock.StorageManagerStub{
		GetBaseTrieStorageManagerCalled: func() common.StorageManager { return base },
	}
	syncStore := &storagemock.StorageManagerStub{
		GetBaseTrieStorageManagerCalled: func() common.StorageManager { return base },
	}
	unrelatedStore := &storagemock.StorageManagerStub{
		GetBaseTrieStorageManagerCalled: func() common.StorageManager { return otherBase },
	}
	view := &laneDProtectedChildView{store: snapshotStore}
	ref := ProtectedChildReference{root: []byte("fixture child root"), view: view}
	root := ref.RootHash()
	require.Equal(t, []byte("fixture child root"), root)
	root[0] = '!'
	require.Equal(t, []byte("fixture child root"), ref.RootHash())
	require.True(t, ref.IsForStorage(syncStore))
	require.False(t, ref.IsForStorage(unrelatedStore))
	require.False(t, ref.IsForStorage(nil))
	require.False(t, (ProtectedChildReference{}).IsForStorage(syncStore))

	snapshotStore.GetBaseTrieStorageManagerCalled = func() common.StorageManager { return nil }
	require.False(t, ref.IsForStorage(syncStore))
}

func TestQualLaneDProtectedSnapshotResolverBoundary(t *testing.T) {
	root := []byte("fixture parent root")
	const epoch = uint32(3)
	manager := &snapshotsManager{}
	fail := errChan.NewErrChanWrapper()
	t.Cleanup(fail.Close)
	manager.snapshotProtectedChildren(root, epoch, nil, fail, nil, nil)
	require.NoError(t, fail.ReadFromChanNonBlocking())

	unavailable := errors.New("fixture checkpoint unavailable")
	manager.protectedChildren = func(checkpoint common.RootHashHolder) ([]ProtectedChildReference, error) {
		require.Equal(t, root, checkpoint.GetRootHash())
		require.Equal(t, core.OptionalUint32{Value: epoch, HasValue: true}, checkpoint.GetEpoch())
		return nil, unavailable
	}
	manager.snapshotProtectedChildren(root, epoch, nil, fail, nil, nil)
	require.ErrorIs(t, fail.ReadFromChanNonBlocking(), unavailable)
}

type laneDProtectedNodeReader struct {
	common.TrieStorageInteractor
	get func([]byte) ([]byte, error)
}

func (reader *laneDProtectedNodeReader) Get(hash []byte) ([]byte, error) {
	return reader.get(hash)
}

func TestQualLaneDProtectedNodeReadAuthenticatesAndDebits(t *testing.T) {
	digest, err := hex.DecodeString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	require.NoError(t, err)
	readError := errors.New("inert store read failure")
	for _, tc := range []struct {
		name       string
		hash       []byte
		budget     uint64
		bytes      string
		storeError error
		want       error
		wantReads  int
		remaining  uint64
	}{
		{name: "wrong hash size", hash: digest[:31], budget: 3, want: errProtectedChild, remaining: 3},
		{name: "exhausted budget", hash: digest, want: errProtectedChild},
		{name: "store error", hash: digest, budget: 3, storeError: readError, want: readError, wantReads: 1, remaining: 3},
		{name: "missing bytes", hash: digest, budget: 3, want: errProtectedChild, wantReads: 1, remaining: 3},
		{name: "over budget", hash: digest, budget: 2, bytes: "abc", want: errProtectedChild, wantReads: 1, remaining: 2},
		{name: "wrong digest", hash: digest, budget: 3, bytes: "abd", want: errProtectedChild, wantReads: 1, remaining: 3},
		{name: "exact debit", hash: digest, budget: 4, bytes: "abc", wantReads: 1, remaining: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget, reads := tc.budget, 0
			store := &laneDProtectedNodeReader{get: func(key []byte) ([]byte, error) {
				reads++
				require.Equal(t, tc.hash, key)
				return []byte(tc.bytes), tc.storeError
			}}
			reader := &verifiedProtectedTrieStorage{TrieStorageInteractor: store, hasher: sha256.NewSha256(), budget: &budget}
			got, err := reader.Get(tc.hash)
			if tc.want == nil {
				require.NoError(t, err)
				require.Equal(t, []byte(tc.bytes), got)
			} else {
				require.ErrorIs(t, err, tc.want)
				require.Nil(t, got)
			}
			require.Equal(t, tc.wantReads, reads)
			require.Equal(t, tc.remaining, budget)
		})
	}
}
