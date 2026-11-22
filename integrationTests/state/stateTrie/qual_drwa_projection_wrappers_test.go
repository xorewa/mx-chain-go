package stateTrie

import (
	"testing"

	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process/transactionEvaluator"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Native wrapper observations for W04, not DRWA implementation or acceptance.
// Synthetic fixture keys have no authority to classify real token identifiers.
func qualWrapperMarker(t *testing.T, account vmcommon.AccountHandler, want byte) {
	t.Helper()
	require.NotNil(t, account)
	value, _, err := account.(state.UserAccountHandler).RetrieveValue([]byte("fixture-a"))
	require.NoError(t, err)
	require.Equal(t, []byte{want}, value)
}

func TestQualDRWAProjectionSimulationBoundary(t *testing.T) {
	p := qualNewLocalProjection(t)
	root, err := p.adb.RootHash()
	require.NoError(t, err)
	sim, err := transactionEvaluator.NewSimulationAccountsDB(p.adb)
	require.NoError(t, err)

	actions := []struct {
		name string
		call func(*testing.T) error
	}{
		{"rollback_is_not_cache_reset", func(t *testing.T) error { return sim.RevertToSnapshot(0) }},
		{"recreate_is_not_cache_reset", func(t *testing.T) error { return sim.RecreateTrie(holders.NewDefaultRootHashesHolder(root)) }},
		{"conditional_recreate_is_not_cache_reset", func(t *testing.T) error { return sim.RecreateTrieIfNeeded(holders.NewDefaultRootHashesHolder(root)) }},
		{"commit_has_no_persisted_root", func(t *testing.T) error { got, e := sim.Commit(); require.Nil(t, got); return e }},
		{"epoch_commit_has_no_persisted_root", func(t *testing.T) error { got, e := sim.CommitInEpoch(0, 0); require.Nil(t, got); return e }},
		{"remove_is_not_cache_eviction", func(t *testing.T) error { return sim.RemoveAccount(p.address) }},
	}
	for _, action := range actions {
		t.Run(action.name, func(t *testing.T) {
			sim.CleanCache()
			account, e := sim.LoadAccount(p.address)
			require.NoError(t, e)
			qualWrapperMarker(t, account, 0)
			require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue([]byte("fixture-a"), []byte{1}))
			require.NoError(t, sim.SaveAccount(account))
			require.NoError(t, action.call(t))
			cached, e := sim.GetExistingAccount(p.address)
			require.NoError(t, e)
			qualWrapperMarker(t, cached, 1)
			native, e := p.adb.GetExistingAccount(p.address)
			require.NoError(t, e)
			qualWrapperMarker(t, native, 0)
			actualRoot, e := sim.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, actualRoot)
			sim.CleanCache()
			refreshed, e := sim.GetExistingAccount(p.address)
			require.NoError(t, e)
			qualWrapperMarker(t, refreshed, 0)
		})
	}

	t.Run("native_rollback_does_not_clear_cached_account", func(t *testing.T) {
		sim.CleanCache()
		require.NoError(t, p.add("fixture-a"))
		account, e := sim.GetExistingAccount(p.address)
		require.NoError(t, e)
		qualWrapperMarker(t, account, 1)
		require.NoError(t, p.rollback(0))
		cached, e := sim.GetExistingAccount(p.address)
		require.NoError(t, e)
		qualWrapperMarker(t, cached, 1)
		sim.CleanCache()
		refreshed, e := sim.GetExistingAccount(p.address)
		require.NoError(t, e)
		qualWrapperMarker(t, refreshed, 0)
	})
}

func TestQualDRWAProjectionHistoricalBoundary(t *testing.T) {
	// Deliberately shared inner database exposes why a live projection cannot be
	// attached blindly to an API wrapper. Production API factories construct
	// separate AccountsDB instances; this is not a claim they share live state.
	p := qualNewLocalProjection(t)
	before, err := p.adb.RootHash()
	require.NoError(t, err)
	require.NoError(t, p.add("fixture-a"))
	after, err := p.commit()
	require.NoError(t, err)
	require.NotEqual(t, before, after)
	api, err := state.NewAccountsDBApiWithHistory(p.adb)
	require.NoError(t, err)

	t.Run("public_mutators_reject", func(t *testing.T) {
		require.ErrorIs(t, api.RecreateTrie(holders.NewDefaultRootHashesHolder(before)), state.ErrOperationNotPermitted)
		require.ErrorIs(t, api.RecreateTrieIfNeeded(holders.NewDefaultRootHashesHolder(before)), state.ErrOperationNotPermitted)
		require.ErrorIs(t, api.RevertToSnapshot(0), state.ErrOperationNotPermitted)
		_, e := api.Commit()
		require.ErrorIs(t, e, state.ErrOperationNotPermitted)
	})
	t.Run("account_read_recreates_inner_state", func(t *testing.T) {
		for _, selected := range []struct {
			root   []byte
			marker byte
		}{{before, 0}, {after, 1}, {before, 0}} {
			account, info, e := api.GetAccountWithBlockInfo(p.address, holders.NewDefaultRootHashesHolder(selected.root))
			require.NoError(t, e)
			qualWrapperMarker(t, account, selected.marker)
			require.Equal(t, selected.root, info.GetRootHash())
			actual, e := p.adb.RootHash()
			require.NoError(t, e)
			require.Equal(t, selected.root, actual)
		}
		cached, e := p.lookup("fixture-a", p.generation)
		require.NoError(t, e)
		require.True(t, cached, "negative control: local experiment was bypassed by private API reconstruction")
	})
	t.Run("code_read_also_recreates_inner_state", func(t *testing.T) {
		code, info, e := api.GetCodeWithBlockInfo([]byte("absent-fixture-code"), holders.NewDefaultRootHashesHolder(after))
		require.NoError(t, e)
		require.Empty(t, code)
		require.Equal(t, after, info.GetRootHash())
		actual, e := p.adb.RootHash()
		require.NoError(t, e)
		require.Equal(t, after, actual)
	})
	t.Run("sharing_inner_db_violates_history_cache_ownership", func(t *testing.T) {
		// The wrapper's cache presumes it owns recreation of its inner DB. Changing
		// that DB behind it invalidates this premise; a matching requested label
		// alone is not proof of the actual state. This is intentional misuse.
		_, _, e := api.GetAccountWithBlockInfo(p.address, holders.NewDefaultRootHashesHolder(after))
		require.NoError(t, e)
		require.NoError(t, p.adb.RecreateTrie(holders.NewDefaultRootHashesHolder(before)))
		account, info, e := api.GetAccountWithBlockInfo(p.address, holders.NewDefaultRootHashesHolder(after))
		require.NoError(t, e)
		require.Equal(t, after, info.GetRootHash())
		qualWrapperMarker(t, account, 0)
		actual, e := p.adb.RootHash()
		require.NoError(t, e)
		require.Equal(t, before, actual)
	})
}
