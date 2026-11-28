package drwa

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

// These are independent numerical position observations, not native effects,
// shard identities, transfers, or evidence of a terminal accounting decision.
func TestQualSP249Z3DetachedUnequalWidePositions(t *testing.T) {
	integer := func(s string) *big.Int {
		t.Helper()
		v, ok := new(big.Int).SetString(s, 10)
		require.True(t, ok)
		return v
	}
	const width = 32 // illustrative width, not an admitted policy value
	rows := []struct {
		before, delta, after string
		credit               bool
	}{
		{"1208925819614629174706213", "18446744073709551627", "1208944266358702884257840", true},
		{"2417851639229258349412371", "1208925819614629174706183", "1208925819614629174706188", false},
		{"3626777458843887524118629", "36893488147419103245", "3626740565355740105015384", false},
	}
	var beforeSum, afterSum big.Int
	for _, row := range rows {
		prior, delta := integer(row.before), integer(row.delta)
		p := &initializedPositionState{family: core.Fungible, quantity: prior}
		observed, err := p.quantityAfter(row.credit, delta, width)
		require.NoError(t, err)
		require.Equal(t, row.after, observed.String())
		beforeSum.Add(&beforeSum, prior)
		afterSum.Add(&afterSum, observed)

		// A detached successor must retain its own numeric value separately
		// from the predecessor and the independent change quantity.
		repeat, err := p.quantityAfter(row.credit, delta, width)
		require.NoError(t, err)
		observed.SetInt64(1)
		require.Equal(t, row.after, repeat.String())
		require.Equal(t, row.before, p.quantity.String())
		require.Equal(t, row.delta, delta.String())
	}
	require.Equal(t, "7253554917687775048237213", beforeSum.String())
	require.Equal(t, "6044610651329072163979412", afterSum.String())
}
