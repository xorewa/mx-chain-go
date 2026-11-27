package state

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

// Only the input provider's ordinary error contract is under test. No actual
// checkpoint, trie, account, or native ownership input is constructed.
func TestQualSP281CRetentionDependencyFailure(t *testing.T) {
	t.Run("provider_error", func(t *testing.T) {
		expected := errors.New("local provider read failed")
		db := &AccountsDB{protectedCheckpoints: &ProtectedChildCheckpoints{
			Retained: func() ([]common.RootHashHolder, error) { return nil, expected },
		}}
		nodes, err := db.retainedProtectedNodes()
		require.ErrorIs(t, err, expected)
		require.Nil(t, nodes)
	})
	t.Run("no_results", func(t *testing.T) {
		db := &AccountsDB{protectedCheckpoints: &ProtectedChildCheckpoints{
			MaxCheckpoints: 1,
			Retained:       func() ([]common.RootHashHolder, error) { return nil, nil },
		}}
		nodes, err := db.retainedProtectedNodes()
		require.Error(t, err)
		require.Nil(t, nodes)
	})
	t.Run("missing_provider_item", func(t *testing.T) {
		db := &AccountsDB{protectedCheckpoints: &ProtectedChildCheckpoints{
			MaxCheckpoints: 1,
			Retained:       func() ([]common.RootHashHolder, error) { return []common.RootHashHolder{nil}, nil },
		}}
		nodes, err := db.retainedProtectedNodes()
		require.ErrorIs(t, err, errProtectedChild)
		require.Nil(t, nodes)
	})
}
