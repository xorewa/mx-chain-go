package stateTrie

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE Part A 6.1 AR-01 rollback construction. Eligibility, import
// authentication and the expected predecessor are preconditions supplied by
// the fixture, NOT established by these writes. Exercise native account
// journaling and root recreation, not a substitute map-based state database.
// This is in-memory storage, not crash/restart or consensus reorg evidence.
func TestQualDRWAPromotionNativeRollbackBoundary(t *testing.T) {
	for stopAfter := 0; stopAfter <= 5; stopAfter++ {
		t.Run(fmt.Sprintf("interrupt_after_%d_writes", stopAfter), func(t *testing.T) {
			adb := createAccountsDBTestSetup()
			t.Cleanup(func() { require.NoError(t, adb.Close()) })
			control := bytes.Repeat([]byte{41}, 32)
			consumer := bytes.Repeat([]byte{42}, 32)
			keys := [][]byte{
				qualProtectedFixtureKey([]byte("token-A"), []byte("final/record")),
				qualProtectedFixtureKey([]byte("token-A"), []byte("pending/record")),
				qualProtectedFixtureKey([]byte("token-A"), []byte("item/origin")),
				qualProtectedFixtureKey([]byte("token-A"), []byte("ack/phase-A")),
			}
			write := func(address, key, value []byte) {
				account, err := adb.LoadAccount(address)
				require.NoError(t, err)
				require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, value))
				require.NoError(t, adb.SaveAccount(account))
			}
			read := func(address, key []byte) []byte {
				account, err := adb.GetExistingAccount(address)
				require.NoError(t, err)
				value, _, err := account.(state.UserAccountHandler).RetrieveValue(key)
				require.NoError(t, err, "storage errors must not masquerade as absence")
				return value
			}
			write(control, keys[0], []byte("predecessor-A"))
			write(control, keys[1], []byte("candidate-B"))
			write(control, keys[2], []byte("result-S"))
			write(consumer, []byte("ordinary"), []byte("untouched"))
			before, err := adb.Commit()
			require.NoError(t, err)
			steps := []func(){
				func() { write(control, keys[0], []byte("candidate-B")) },
				func() { write(control, keys[1], nil) },
				func() { write(control, keys[2], nil) },
				func() { write(control, keys[3], []byte("canonical-result-S")) },
				func() { write(consumer, []byte("dependent-effect"), []byte("consumed-B")) },
			}
			for i := 0; i < stopAfter; i++ {
				steps[i]()
			}
			require.NoError(t, adb.RevertToSnapshot(0))
			after, err := adb.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, []byte("predecessor-A"), read(control, keys[0]))
			require.Equal(t, []byte("candidate-B"), read(control, keys[1]))
			require.Equal(t, []byte("result-S"), read(control, keys[2]))
			require.Empty(t, read(control, keys[3]))
			require.Empty(t, read(consumer, []byte("dependent-effect")))
			require.Equal(t, []byte("untouched"), read(consumer, []byte("ordinary")))

			// Successful branch, duplicate exact writes, restoration to its parent,
			// and replay. Canonical branch SELECTION is deliberately not modelled.
			for _, step := range steps {
				step()
			}
			applied, err := adb.RootHash()
			require.NoError(t, err)
			for _, step := range steps {
				step()
			}
			repeated, err := adb.Commit()
			require.NoError(t, err)
			require.Equal(t, applied, repeated)
			require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(before)))
			require.Equal(t, []byte("predecessor-A"), read(control, keys[0]))
			require.Empty(t, read(consumer, []byte("dependent-effect")))
			for _, step := range steps {
				step()
			}
			replayed, err := adb.Commit()
			require.NoError(t, err)
			require.Equal(t, repeated, replayed)
			require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(replayed)))
			require.Equal(t, []byte("candidate-B"), read(control, keys[0]))
			require.Empty(t, read(control, keys[1]))
			require.Empty(t, read(control, keys[2]))
			require.Equal(t, []byte("canonical-result-S"), read(control, keys[3]))
			require.Equal(t, []byte("consumed-B"), read(consumer, []byte("dependent-effect")))
		})
	}
}
