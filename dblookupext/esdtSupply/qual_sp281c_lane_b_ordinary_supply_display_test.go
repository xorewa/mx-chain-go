package esdtSupply

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinarySupplyDisplayAndGetterDefaults(t *testing.T) {
	value := &SupplyESDT{
		Supply: big.NewInt(75), Burned: big.NewInt(25), Minted: big.NewInt(100), RecomputedSupply: true,
	}
	require.Same(t, value.Supply, value.GetSupply())
	require.Same(t, value.Burned, value.GetBurned())
	require.Same(t, value.Minted, value.GetMinted())
	require.True(t, value.GetRecomputedSupply())

	wantRepresentation := fmt.Sprintf("&esdtSupply.SupplyESDT{Supply: %#v,\nBurned: %#v,\nMinted: %#v,\nRecomputedSupply: true,\n}",
		big.NewInt(75), big.NewInt(25), big.NewInt(100))
	require.Equal(t, wantRepresentation, value.GoString())

	var absent *SupplyESDT
	require.Nil(t, absent.GetSupply())
	require.Nil(t, absent.GetBurned())
	require.Nil(t, absent.GetMinted())
	require.False(t, absent.GetRecomputedSupply())
	require.Equal(t, "nil", absent.GoString())
	require.Equal(t, "nil", absent.String())

	require.True(t, absent.Equal(nil))
	require.True(t, absent.Equal((*SupplyESDT)(nil)))
	require.False(t, value.Equal(nil))
	require.False(t, value.Equal(absent))
	require.False(t, absent.Equal(value))
	require.False(t, value.Equal("ordinary display"))
}
