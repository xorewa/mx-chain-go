package syncer_test

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/syncer"
	"github.com/stretchr/testify/require"
)

type qualA19ReadinessMarker struct{ marked bool }

func (m *qualA19ReadinessMarker) IsInterfaceNil() bool { return m == nil }
func (m *qualA19ReadinessMarker) MarkStorerAsSyncedAndActive(_ common.StorageManager) {
	m.marked = true
}

func TestQualDRWAA19SyncDeniesReadinessWithUnavailableProtectedInput(t *testing.T) {
	root := common.EmptyTrieHash
	unavailable := errors.New("required protected history unavailable")
	for _, valid := range []bool{false, true} {
		args := getDefaultUserAccountsSyncerArgs()
		args.ProtectedChildren = func(checkpoint common.RootHashHolder) ([]state.ProtectedChildReference, error) {
			require.Equal(t, root, checkpoint.GetRootHash())
			if !valid {
				return nil, unavailable
			}
			return nil, nil // synthetic authenticated empty root set
		}
		s, err := syncer.NewUserAccountsSyncer(args)
		require.NoError(t, err)
		marker := &qualA19ReadinessMarker{}
		err = s.SyncAccounts(root, marker)
		if valid {
			require.NoError(t, err)
			require.True(t, marker.marked)
		} else {
			require.ErrorIs(t, err, unavailable)
			require.False(t, marker.marked)
		}
	}
}
