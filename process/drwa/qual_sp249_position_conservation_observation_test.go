package drwa

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

// These are detached numerical observations, not transactions, shard proofs,
// policy decisions, or an authorization to finalize a token.
func TestQualSP249NominalPositionConservation(t *testing.T) {
	for _, family := range []core.ESDTType{
		core.Fungible, core.NonFungibleV2, core.SemiFungible, core.MetaFungible,
		core.DynamicNFT, core.DynamicSFT, core.DynamicMeta,
	} {
		t.Run(family.String(), func(t *testing.T) {
			const width = 32 // illustrative arithmetic fixture width, not policy
			cap := big.NewInt(5)
			supply := newSupplyAccounting()
			a := &initializedPositionState{family: family, quantity: new(big.Int)}
			b := &initializedPositionState{family: family, quantity: new(big.Int)}

			observe := func(issued, live, left, right, headroom int64, nonce uint64) {
				t.Helper()
				require.Equal(t, big.NewInt(issued), supply.cumulativeIssued)
				require.Equal(t, big.NewInt(live), supply.liveSupply)
				require.Equal(t, nonce, supply.nextSupplyNonce)
				require.Equal(t, big.NewInt(left), a.quantity)
				require.Equal(t, big.NewInt(right), b.quantity)
				require.Equal(t, big.NewInt(live), new(big.Int).Add(a.quantity, b.quantity))
				require.Equal(t, big.NewInt(headroom), new(big.Int).Sub(cap, supply.cumulativeIssued))
			}
			move := func(position *initializedPositionState, credit bool) {
				t.Helper()
				prior := position.quantity
				before := new(big.Int).Set(prior)
				next, err := position.quantityAfter(credit, big.NewInt(1), width)
				require.NoError(t, err)
				require.Equal(t, before, prior)
				position.quantity = next
			}
			supplyStep := func(increase bool) {
				t.Helper()
				prior := supply
				issued, live := new(big.Int).Set(prior.cumulativeIssued), new(big.Int).Set(prior.liveSupply)
				nonce := prior.nextSupplyNonce
				next, err := prior.advance(nonce, increase, big.NewInt(1), cap, width)
				require.NoError(t, err)
				require.Equal(t, issued, prior.cumulativeIssued)
				require.Equal(t, live, prior.liveSupply)
				require.Equal(t, nonce, prior.nextSupplyNonce)
				require.Equal(t, big.NewInt(5), cap)
				supply = next
				move(a, increase)
			}

			observe(0, 0, 0, 0, 5, 0)
			for range 3 {
				supplyStep(true)
			}
			observe(3, 3, 3, 0, 2, 3)
			move(a, false)
			move(b, true)
			observe(3, 3, 2, 1, 2, 3)
			supplyStep(false)
			observe(3, 2, 1, 1, 2, 4)
			supplyStep(true)
			observe(4, 3, 2, 1, 1, 5)
		})
	}

	t.Run("wide fungible observation", func(t *testing.T) {
		const width = 32
		whole := new(big.Int).Lsh(big.NewInt(1), 70)
		half := new(big.Int).Lsh(big.NewInt(1), 69)
		cap := new(big.Int).Lsh(big.NewInt(1), 71)
		state, err := newSupplyAccounting().advance(0, true, whole, cap, width)
		require.NoError(t, err)
		zero := &initializedPositionState{family: core.Fungible, quantity: new(big.Int)}
		left, err := zero.quantityAfter(true, half, width)
		require.NoError(t, err)
		right, err := zero.quantityAfter(true, half, width)
		require.NoError(t, err)
		require.Zero(t, zero.quantity.Sign())
		require.Equal(t, whole, state.cumulativeIssued)
		require.Equal(t, whole, state.liveSupply)
		require.Equal(t, whole, new(big.Int).Add(left, right))
		require.Equal(t, whole, new(big.Int).Sub(cap, state.cumulativeIssued))
	})
}
