package drwa

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// Independently grouped detached positive quantities preserve the same
// gross-issuance and live-stock totals. The comparison is arithmetic only;
// it does not describe permitted native sequences or select a policy.
func TestQualSP248Z3DetachedQuantityGrouping(t *testing.T) {
	unit := new(big.Int).Lsh(big.NewInt(1), 64)
	quantity := func(coefficient int64) *big.Int {
		return new(big.Int).Mul(unit, big.NewInt(coefficient))
	}
	type projection struct {
		increase            bool
		delta, issued, live int64
	}
	for _, row := range []struct {
		name  string
		steps []projection
	}{
		{
			name: "grouped_quantities",
			steps: []projection{
				{true, 6, 106, 76},
				{false, 3, 106, 73},
			},
		},
		{
			name: "partitioned_quantities",
			steps: []projection{
				{true, 2, 102, 72},
				{true, 4, 106, 76},
				{false, 1, 106, 75},
				{false, 2, 106, 73},
			},
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			initial := &supplyAccounting{cumulativeIssued: quantity(100), liveSupply: quantity(70)}
			state := initial
			cap := quantity(110)
			const fixtureWidth = 16
			for i, step := range row.steps {
				delta := quantity(step.delta)
				// This counter labels independent numeric calculations
				// only, not any persisted or authenticated action.
				next, err := state.advance(uint64(i), step.increase, delta, cap, fixtureWidth)
				require.NoError(t, err)
				require.Equal(t, quantity(step.issued), next.cumulativeIssued)
				require.Equal(t, quantity(step.live), next.liveSupply)
				require.Equal(t, uint64(i+1), next.nextSupplyNonce)
				require.Equal(t, quantity(step.delta), delta)
				require.Equal(t, quantity(110), cap)
				state = next
			}
			// The two decompositions have identical gross and net
			// expected values, while their calculation counts differ.
			require.Equal(t, quantity(106), state.cumulativeIssued)
			require.Equal(t, quantity(73), state.liveSupply)
			require.Equal(t, quantity(4), new(big.Int).Sub(cap, state.cumulativeIssued))
			require.Equal(t, quantity(100), initial.cumulativeIssued)
			require.Equal(t, quantity(70), initial.liveSupply)
			require.Zero(t, initial.nextSupplyNonce)
		})
	}
}
