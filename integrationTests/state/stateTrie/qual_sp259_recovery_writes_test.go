package stateTrie

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

// Observe successful native recovery writes without substituting any storage
// behavior. The actual recovery account syncer uses the actual pruning store.
type sp259RecoveryStore struct {
	common.StorageManager
	recovery interface {
		GetForRecovery([]byte, uint32) ([]byte, error)
		PutForRecovery([]byte, []byte, uint32) error
	}
	mutex  sync.Mutex
	writes map[string][]byte
	epochs map[string]uint32
}

func (s *sp259RecoveryStore) GetForRecovery(key []byte, epoch uint32) ([]byte, error) {
	return s.recovery.GetForRecovery(key, epoch)
}

func (s *sp259RecoveryStore) PutForRecovery(key, data []byte, epoch uint32) error {
	if err := s.recovery.PutForRecovery(key, data, epoch); err != nil {
		return err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.writes[string(key)] = bytes.Clone(data)
	s.epochs[string(key)] = epoch
	return nil
}

// Represents an ordinary storage read that returns unusable bytes for one
// fixture node. All other reads use the original native store.
type sp259UnreadableSource struct {
	common.StorageManager
	key []byte
}

func (s *sp259UnreadableSource) Get(key []byte) ([]byte, error) {
	if bytes.Equal(key, s.key) {
		return []byte{}, nil
	}
	return s.StorageManager.Get(key)
}

func TestQualSP259ProtectedRecoveryNativeWrites(t *testing.T) {
	checkpoints := &sp220Checkpoints{records: map[string][]byte{}}
	source, expected, err := sp220History(t, sp220NewDisk(t), checkpoints, true)
	require.NoError(t, err)
	defer source.close()
	account, err := source.adb.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	dataRoot := account.(state.UserAccountHandler).GetRootHash()
	hashes := [][]byte{dataRoot, expected.childRoot}
	for _, hash := range hashes {
		require.NotEmpty(t, hash)
	}
	const epoch = uint32(8)
	t.Run("unavailable protected node does not mark recovery complete", func(t *testing.T) {
		for _, hash := range hashes {
			target, _ := sp220Open(t, sp220NewDisk(t), checkpoints, epoch, true)
			marker := &sp220Marker{}
			require.Error(t, sp220Syncer(t, target, source.manager, map[string]struct{}{string(hash): {}}, time.Second).SyncAccountsWithDiskCheck(expected.root, marker, epoch))
			require.False(t, marker.marked)
			require.Error(t, target.check(expected))
			target.close()
		}
	})
	t.Run("unusable protected node does not mark recovery complete", func(t *testing.T) {
		for _, hash := range hashes {
			target, _ := sp220Open(t, sp220NewDisk(t), checkpoints, epoch, true)
			marker := &sp220Marker{}
			unreadable := &sp259UnreadableSource{StorageManager: source.manager, key: hash}
			require.Error(t, sp220Syncer(t, target, unreadable, nil, time.Second).SyncAccountsWithDiskCheck(expected.root, marker, epoch))
			require.False(t, marker.marked)
			require.Error(t, target.check(expected))
			target.close()
		}
	})
	disk := sp220NewDisk(t)
	target, _ := sp220Open(t, disk, checkpoints, epoch, true)
	manager := target.manager
	native, ok := manager.(interface {
		GetForRecovery([]byte, uint32) ([]byte, error)
		PutForRecovery([]byte, []byte, uint32) error
	})
	require.True(t, ok)
	observed := &sp259RecoveryStore{StorageManager: manager, recovery: native, writes: make(map[string][]byte), epochs: make(map[string]uint32)}
	target.manager = observed
	marker := &sp220Marker{}
	require.NoError(t, sp220Syncer(t, target, source.manager, nil, 5*time.Second).SyncAccountsWithDiskCheck(expected.root, marker, epoch))
	require.True(t, marker.marked)
	for _, hash := range hashes {
		want, err := source.manager.Get(hash)
		require.NoError(t, err)
		observed.mutex.Lock()
		actual, written := observed.writes[string(hash)]
		writtenEpoch := observed.epochs[string(hash)]
		observed.mutex.Unlock()
		require.True(t, written, "required protected root was written through PutForRecovery")
		require.Equal(t, epoch, writtenEpoch)
		require.Equal(t, want, actual)
		read, err := native.GetForRecovery(hash, epoch)
		require.NoError(t, err)
		require.Equal(t, want, read)
	}
	require.NoError(t, target.check(expected))
	target.manager = manager
	target.close()
	reopened, _ := sp220Open(t, disk, checkpoints, epoch, true)
	defer reopened.close()
	require.NoError(t, reopened.check(expected))
	require.NoError(t, source.check(expected))
}
