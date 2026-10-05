package stateTrie

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/state"
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
			name = "restoration_failed"
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
