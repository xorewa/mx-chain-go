package drwa

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// Detached positive numeric values only. No identifier, nonce key, policy,
// state write or native operation participates in this representation check.
func TestQualSP235Z3DetachedQuantityAggregate(t *testing.T) {
	codec := rootLeafRecords{maxAmountBytes: 16} // illustrative fixture width
	fixtures := []struct {
		decimal string
		wireHex string
	}{
		{"18374120213919168759", "fefdfcfbfaf9f8f7"},
		{"145247719580765712", "020406080a0c0e10"},
		{"1234605616436508552", "1122334455667788"},
	}
	values := make([]*big.Int, 0, len(fixtures))
	for _, fixture := range fixtures {
		value, ok := new(big.Int).SetString(fixture.decimal, 10)
		require.True(t, ok)
		expected, err := hex.DecodeString(fixture.wireHex)
		require.NoError(t, err)
		encoded, err := codec.quantityValue(value)
		require.NoError(t, err)
		require.Equal(t, expected, encoded)
		decoded, err := codec.decodeQuantityValue(expected)
		require.NoError(t, err)
		require.Equal(t, fixture.decimal, decoded.String())
		values = append(values, decoded)
	}

	// Independent decimal and byte-level oracles for the same aggregate.
	// Each input fits eight bytes, while their positive sum needs nine.
	const expectedTotal = "19753973549936443023"
	expectedWire, err := hex.DecodeString("01122436485a6c7e8f")
	require.NoError(t, err)
	for _, order := range [][]int{{0, 1, 2}, {2, 1, 0}} {
		var total big.Int
		for _, index := range order {
			total.Add(&total, values[index])
		}
		require.Equal(t, expectedTotal, total.String())
		wire, err := codec.quantityValue(&total)
		require.NoError(t, err)
		require.Equal(t, expectedWire, wire)
		decodedTotal, err := codec.decodeQuantityValue(wire)
		require.NoError(t, err)
		require.Equal(t, expectedTotal, decodedTotal.String())
		for i, fixture := range fixtures {
			require.Equal(t, fixture.decimal, values[i].String())
		}
	}
}
