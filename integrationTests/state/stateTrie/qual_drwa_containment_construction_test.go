package stateTrie

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE Part A 5.4 P-05 construction extending the existing local
// projection experiment. Native AccountsDB really mutates and returns the
// rollback error. The test-local coordinator preserves both diagnostics and
// denies guarded commit/read until explicit reconstruction. This does not
// wire containment through native processors, results, logs or gas; direct
// adapter access remains a bypass that production ownership must eliminate.
func TestQualDRWARollbackContainmentConstruction(t *testing.T) {
	for _, fails := range []bool{false, true} {
		name := "restored"
		if fails {
			name = "invalid_snapshot_before_undo"
		}
		t.Run(name, func(t *testing.T) {
			p := qualNewLocalProjection(t)
			before, err := p.adb.RootHash()
			require.NoError(t, err)
			primary := errors.New("fixture operation failure")
			require.NoError(t, p.add("fixture-a"))
			snapshot := 0
			if fails {
				snapshot = -1
			}
			rollback := p.rollback(snapshot)
			returned := errors.Join(primary, rollback)
			require.ErrorIs(t, returned, primary)
			if !fails {
				require.NoError(t, rollback)
				qualAssertLocalMembership(t, p)
				restored, commitErr := p.commit()
				require.NoError(t, commitErr)
				require.Equal(t, before, restored)
				return
			}
			require.ErrorIs(t, returned, state.ErrSnapshotValueOutOfBounds)
			_, err = p.lookup("fixture-a", p.generation)
			require.ErrorIs(t, err, qualProjectionUnavailable)
			_, err = p.commit()
			require.ErrorIs(t, err, qualProjectionUnavailable)
			mutated, err := p.adb.RootHash()
			require.NoError(t, err)
			require.NotEqual(t, before, mutated)
			require.NoError(t, p.reconstruct(before))
			qualAssertLocalMembership(t, p)
			recovered, err := p.commit()
			require.NoError(t, err)
			require.Equal(t, before, recovered)
		})
	}
	for _, fails := range []bool{false, true} {
		name := "native_undo_control"
		if fails {
			name = "native_partial_undo_failure"
		}
		t.Run(name, func(t *testing.T) {
			p := qualNewLocalProjection(t)
			committed, err := p.adb.RootHash()
			require.NoError(t, err)
			require.NoError(t, p.add("fixture-a"))
			snapshot := p.adb.JournalLen()
			require.Positive(t, snapshot) // zero bypasses individual undo entries
			surviving, err := p.adb.RootHash()
			require.NoError(t, err)

			// SaveAccount creates the real native journal entry. Its account
			// retains the data-trie reference (accountsDB.go:534-550).
			// Replace only that reference after saving, using the upstream
			// stub to fail the entry's UpdateWithVersion during rollback.
			account, err := p.adb.LoadAccount(bytes.Repeat([]byte{8}, 32))
			require.NoError(t, err)
			user := account.(state.UserAccountHandler)
			require.NoError(t, user.SaveKeyValue([]byte("fault-fixture"), []byte{1}))
			require.NoError(t, p.adb.SaveAccount(user))
			dataTrie := user.DataTrie().(state.DataTrie)
			undoErr := errors.New("fixture native data-trie undo failure")
			undoCalls := 0
			user.SetDataTrie(&trieMock.TrieStub{
				RootCalled: dataTrie.RootHash,
				UpdateWithVersionCalled: func(key, value []byte, version core.TrieNodeVersion) error {
					undoCalls++
					if fails {
						return undoErr
					}
					return dataTrie.UpdateWithVersion(key, value, version)
				},
			})
			require.NoError(t, p.add("fixture-b"))
			require.NoError(t, p.add("fixture-c"))
			mutated, err := p.adb.RootHash()
			require.NoError(t, err)
			journalBefore := p.adb.JournalLen()
			primary := errors.New("fixture operation failure")
			rollback := p.rollback(snapshot)
			returned := errors.Join(primary, rollback)
			require.ErrorIs(t, returned, primary)
			require.Equal(t, 1, undoCalls)
			// Read native bytes, not the projection: later real entries must
			// already have undone b/c while the earlier a update survives.
			native, err := p.adb.GetExistingAccount(p.address)
			require.NoError(t, err)
			for key, expected := range map[string]byte{"fixture-a": 1, "fixture-b": 0, "fixture-c": 0} {
				value, _, readErr := native.(state.UserAccountHandler).RetrieveValue([]byte(key))
				require.NoError(t, readErr)
				require.Equal(t, []byte{expected}, value, key)
			}
			partial, err := p.adb.RootHash()
			require.NoError(t, err)
			require.NotEqual(t, mutated, partial)
			if !fails {
				require.NoError(t, rollback)
				require.Equal(t, snapshot, p.adb.JournalLen())
				require.Equal(t, surviving, partial)
				qualAssertLocalMembership(t, p, "fixture-a")
				return
			}
			require.ErrorIs(t, returned, undoErr)
			require.Greater(t, p.adb.JournalLen(), snapshot)
			require.Less(t, p.adb.JournalLen(), journalBefore)
			require.NotEqual(t, surviving, partial)
			for _, key := range p.keys {
				_, err = p.lookup(key, p.generation)
				require.ErrorIs(t, err, qualProjectionUnavailable)
			}
			require.ErrorIs(t, p.add("fixture-b"), qualProjectionUnavailable)
			require.ErrorIs(t, p.rollback(snapshot), qualProjectionUnavailable)
			_, err = p.commit()
			require.ErrorIs(t, err, qualProjectionUnavailable)
			require.Equal(t, 1, undoCalls, "poisoned-context retry cannot execute undo again")
			require.NoError(t, p.reconstruct(committed))
			qualAssertLocalMembership(t, p)
			recovered, err := p.commit()
			require.NoError(t, err)
			require.Equal(t, committed, recovered)
		})
	}
	t.Run("direct_adapter_bypass_is_not_contained", func(t *testing.T) {
		p := qualNewLocalProjection(t)
		before, err := p.adb.RootHash()
		require.NoError(t, err)
		require.NoError(t, p.add("fixture-a"))
		require.ErrorIs(t, p.rollback(-1), state.ErrSnapshotValueOutOfBounds)
		_, err = p.commit()
		require.ErrorIs(t, err, qualProjectionUnavailable)
		// Deliberate counterexample: the unwrapped native adapter does not know
		// that a separate projection coordinator is poisoned.
		bypassed, err := p.adb.Commit()
		require.NoError(t, err)
		require.NotEqual(t, before, bypassed)
		require.NoError(t, p.reconstruct(before))
		qualAssertLocalMembership(t, p)
	})
}
