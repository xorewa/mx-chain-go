package state

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

type localJournalDependency struct {
	DataTrie
	updateErr error
	rootErr   error
	root      []byte
	updates   int
}

func (d *localJournalDependency) UpdateWithVersion([]byte, []byte, core.TrieNodeVersion) error {
	d.updates++
	return d.updateErr
}

func (d *localJournalDependency) RootHash() ([]byte, error) { return d.root, d.rootErr }

// The journal helper is exercised against a local map and inert callbacks.
// There is no backing trie, real account, record, owner input, or state write.
func TestQualSP281CLocalJournalBookkeeping(t *testing.T) {
	t.Run("empty_journal", func(t *testing.T) {
		owner := &AccountsDB{protectedChildren: make(map[protectedChildKey]*stagedProtectedChild)}
		entry := &journalEntryProtectedChild{owner: owner}
		account, err := entry.Revert()
		require.NoError(t, err)
		require.Nil(t, account)
		require.Empty(t, owner.protectedChildren)
	})

	updateErr := errors.New("local dependency update failed")
	rootErr := errors.New("local dependency read failed")
	for _, tt := range []struct {
		name    string
		dep     localJournalDependency
		wantErr error
	}{
		{name: "local_update_error", dep: localJournalDependency{updateErr: updateErr}, wantErr: updateErr},
		{name: "local_root_error", dep: localJournalDependency{rootErr: rootErr}, wantErr: rootErr},
		{name: "inconsistent_local_result", dep: localJournalDependency{root: []byte("unexpected local value")}, wantErr: errProtectedChild},
		{name: "local_bookkeeping_success"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			owner := &AccountsDB{protectedChildren: make(map[protectedChildKey]*stagedProtectedChild)}
			prior := &stagedProtectedChild{}
			entry := &journalEntryProtectedChild{
				owner: owner, previous: prior, child: &tt.dep, undo: []core.TrieData{{}},
			}
			account, err := entry.Revert()
			require.Nil(t, account)
			require.Equal(t, 1, tt.dep.updates)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				require.ErrorIs(t, owner.protectedCommitFailure, tt.wantErr)
				require.Empty(t, owner.protectedChildren)
				return
			}
			require.NoError(t, err)
			require.NoError(t, owner.protectedCommitFailure)
			require.Same(t, prior, owner.protectedChildren[entry.key])
		})
	}
}
