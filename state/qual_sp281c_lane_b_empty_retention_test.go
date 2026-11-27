package state

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/sha256"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/stretchr/testify/require"
)

// The canonical empty trie has no child data. Exercise retention bookkeeping
// with its ordinary empty root and with an unavailable local metadata provider;
// neither case supplies a protected locator or opens a store.
func TestQualSP281CEmptyRetentionMetadata(t *testing.T) {
	root := bytes.Clone(common.EmptyTrieHash)
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "no_children"},
		{name: "provider_unavailable", err: errors.New("local metadata unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &AccountsDB{
				hasher:       sha256.NewSha256(),
				lastRootHash: root,
				protectedCheckpoints: &ProtectedChildCheckpoints{
					MaxCheckpoints: 1,
					Retained: func() ([]common.RootHashHolder, error) {
						return []common.RootHashHolder{holders.NewDefaultRootHashesHolder(root)}, nil
					},
					Locate: func(common.RootHashHolder) ([]ProtectedChildLocator, error) { return nil, tc.err },
				},
			}
			nodes, err := db.retainedProtectedNodes()
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				require.Nil(t, nodes)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, nodes)
			require.Empty(t, nodes)
		})
	}
}

// Invalid dependency results or an unavailable view must stop the operation
// before inspecting any locator. The entries are empty placeholders, not
// native locator or ownership data; the view is only an error-returning stub.
func TestQualSP281CLocalRetentionResolverDependencyErrors(t *testing.T) {
	root := bytes.Clone(common.EmptyTrieHash)
	checkpoint := holders.NewDefaultRootHashesHolder(root)
	readErr := errors.New("local view unavailable")
	for _, tc := range []struct {
		name    string
		results int
		want    error
	}{
		{name: "too_many_results", results: 2, want: errProtectedChild},
		{name: "view_unavailable", results: 1, want: readErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &AccountsDB{
				hasher: sha256.NewSha256(),
				protectedCheckpoints: &ProtectedChildCheckpoints{
					MaxLocators: 1,
					Locate: func(common.RootHashHolder) ([]ProtectedChildLocator, error) {
						return make([]ProtectedChildLocator, tc.results), nil
					},
				},
			}
			refs, err := db.resolveProtectedChildren(&localRecreateFailure{err: readErr}, checkpoint)
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, refs)
		})
	}
}

// An empty local checkpoint list item cannot establish the missing current
// metadata. The fixture supplies only the canonical empty root, not a store
// or any protected locator.
func TestQualSP281CLocalRetentionCurrentMetadataAbsent(t *testing.T) {
	root := bytes.Clone(common.EmptyTrieHash)
	db := &AccountsDB{
		hasher: sha256.NewSha256(),
		protectedCheckpoints: &ProtectedChildCheckpoints{
			MaxCheckpoints: 1,
			Retained: func() ([]common.RootHashHolder, error) {
				return []common.RootHashHolder{holders.NewDefaultRootHashesHolder(root)}, nil
			},
			Locate: func(common.RootHashHolder) ([]ProtectedChildLocator, error) { return nil, nil },
		},
	}
	nodes, err := db.retainedProtectedNodes()
	require.ErrorIs(t, err, errProtectedChild)
	require.Nil(t, nodes)
}
