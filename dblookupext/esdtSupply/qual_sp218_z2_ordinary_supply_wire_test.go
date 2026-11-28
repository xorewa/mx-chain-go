package esdtSupply

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// Check ordinary supply report serialization in isolation. Expected tags,
// lengths and nonnegative amounts follow the unchanged SupplyESDT schema.
func TestQualSP218Z2OrdinarySupplyWireDTO(t *testing.T) {
	for _, tc := range []struct {
		name string
		dto  *SupplyESDT
		wire []byte
	}{
		{
			name: "empty report",
			dto:  &SupplyESDT{},
			wire: []byte{0x0a, 1, 0, 0x12, 1, 0, 0x1a, 1, 0},
		},
		{
			name: "ordinary supply",
			dto:  &SupplyESDT{Supply: big.NewInt(75), Burned: big.NewInt(25), Minted: big.NewInt(100)},
			wire: []byte{0x0a, 2, 0, 75, 0x12, 2, 0, 25, 0x1a, 2, 0, 100},
		},
		{
			name: "recomputed supply",
			dto:  &SupplyESDT{Supply: big.NewInt(256), Burned: big.NewInt(0), Minted: big.NewInt(256), RecomputedSupply: true},
			wire: []byte{0x0a, 3, 0, 1, 0, 0x12, 2, 0, 0, 0x1a, 3, 0, 1, 0, 0x20, 1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, len(tc.wire), tc.dto.Size())
			wire, err := tc.dto.Marshal()
			require.NoError(t, err)
			require.Equal(t, tc.wire, wire)

			buf := make([]byte, len(tc.wire))
			n, err := tc.dto.MarshalTo(buf)
			require.NoError(t, err)
			require.Equal(t, len(tc.wire), n)
			require.Equal(t, tc.wire, buf)
		})
	}
}
