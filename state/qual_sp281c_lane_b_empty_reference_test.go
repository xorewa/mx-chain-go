package state

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/sha256"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

type localEmptyTrieView struct{ common.Trie }

func (v *localEmptyTrieView) IsInterfaceNil() bool { return v == nil }

// Exercise only absent input and the canonical empty trie. The supplied view
// has no backing store and the read callback must not be invoked.
func TestQualSP281CLocalEmptyReference(t *testing.T) {
	t.Run("missing_dependency", func(t *testing.T) {
		require.ErrorIs(t, (ProtectedChildReference{}).Verify(), errProtectedChild)
	})
	t.Run("empty_trie_no_reads", func(t *testing.T) {
		ref := ProtectedChildReference{
			root:   bytes.Clone(common.EmptyTrieHash),
			hasher: sha256.NewSha256(),
			view:   &localEmptyTrieView{},
			readNode: func([]byte, common.TrieStorageInteractor) ([]common.TrieNodeData, error) {
				t.Fatal("empty trie must not read nodes")
				return nil, nil
			},
		}
		require.NoError(t, ref.Verify())
	})
}
