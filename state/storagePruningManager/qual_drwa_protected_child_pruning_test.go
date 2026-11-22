package storagePruningManager

import (
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/storagePruningManager/evictionWaitingList"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/stretchr/testify/require"
)

type qualA19KeepNode string

func (qualA19KeepNode) IsPruningEnabled() bool                     { return true }
func (keep qualA19KeepNode) KeepProtectedTrieNode(key string) bool { return key == string(keep) }

func TestQualDRWAA19NativePruningKeepsRequiredNode(t *testing.T) {
	ewl, err := evictionWaitingList.NewMemoryEvictionWaitingList(evictionWaitingList.MemoryEvictionWaitingListArgs{
		RootHashesSize: 10, HashesSize: 100,
	})
	require.NoError(t, err)
	pruning, err := NewStoragePruningManager(ewl, 10)
	require.NoError(t, err)
	old, next := []byte("synthetic losing checkpoint"), []byte("synthetic current checkpoint")
	oldNodes := common.ModifiedHashes{"shared": {}, "obsolete": {}}
	require.NoError(t, pruning.MarkForEviction(old, next, oldNodes, nil))
	var removed []string
	store := &storageManager.StorageManagerStub{
		IsPruningEnabledCalled: func() bool { return true },
		RemoveCalled:           func(key []byte) error { removed = append(removed, string(key)); return nil },
	}
	pruning.PruneTrie(old, state.OldRoot, store, qualA19KeepNode("shared"))
	require.Equal(t, []string{"obsolete"}, removed)
}
