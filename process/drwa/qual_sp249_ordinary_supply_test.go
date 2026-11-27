package drwa

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP249OrdinarySupplyConservation(t *testing.T) {
	t.Parallel()

	state := newSupplyAccounting()
	cap := big.NewInt(1000)
	for i, sample := range []struct {
		increase bool
		quantity int64
		issued   int64
		live     int64
	}{
		{true, 7, 7, 7},
		{true, 11, 18, 18},
		{false, 3, 18, 15},
		{true, 5, 23, 20},
	} {
		priorIssued := new(big.Int).Set(state.cumulativeIssued)
		priorLive := new(big.Int).Set(state.liveSupply)
		next, err := state.advance(uint64(i), sample.increase, big.NewInt(sample.quantity), cap, 32)
		require.NoError(t, err)
		require.Equal(t, big.NewInt(sample.issued), next.cumulativeIssued)
		require.Equal(t, big.NewInt(sample.live), next.liveSupply)
		require.Equal(t, priorIssued, state.cumulativeIssued)
		require.Equal(t, priorLive, state.liveSupply)
		state = next
	}
}
