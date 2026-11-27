package esdtSupply

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinarySupplyValueComparisonAndDisplay(t *testing.T) {
	want := &SupplyESDT{
		Supply: big.NewInt(120), Burned: big.NewInt(10), Minted: big.NewInt(130), RecomputedSupply: true,
	}
	copyValue := SupplyESDT{
		Supply: big.NewInt(120), Burned: big.NewInt(10), Minted: big.NewInt(130), RecomputedSupply: true,
	}
	require.True(t, want.Equal(&copyValue))
	require.True(t, want.Equal(copyValue))
	require.Equal(t, "&SupplyESDT{Supply:120,Burned:10,Minted:130,RecomputedSupply:true,}", want.String())

	// Distinct ordinary reported values remain distinguishable, independent of pointer identity.
	for _, other := range []SupplyESDT{
		{Supply: big.NewInt(121), Burned: big.NewInt(10), Minted: big.NewInt(130), RecomputedSupply: true},
		{Supply: big.NewInt(120), Burned: big.NewInt(11), Minted: big.NewInt(130), RecomputedSupply: true},
		{Supply: big.NewInt(120), Burned: big.NewInt(10), Minted: big.NewInt(131), RecomputedSupply: true},
		{Supply: big.NewInt(120), Burned: big.NewInt(10), Minted: big.NewInt(130), RecomputedSupply: false},
	} {
		require.False(t, want.Equal(other))
	}
}
