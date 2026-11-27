package esdtSupply

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// Check the encoded-size reporting accessor alone, using ordinary in-memory DTOs.
func TestQualLaneDOrdinarySupplySizeDTO(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report *SupplyESDT
		size   int
	}{
		{"absent", nil, 0},
		{"empty", &SupplyESDT{}, 9},
		{"reported", &SupplyESDT{Supply: big.NewInt(75), Burned: big.NewInt(25), Minted: big.NewInt(100)}, 12},
		{"recomputed", &SupplyESDT{Supply: big.NewInt(75), Burned: big.NewInt(25), Minted: big.NewInt(100), RecomputedSupply: true}, 14},
		{"wide", &SupplyESDT{Supply: big.NewInt(256), Burned: big.NewInt(0), Minted: big.NewInt(256)}, 14},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.size, tc.report.Size())
			require.Equal(t, tc.size, tc.report.XXX_Size())
		})
	}
}
