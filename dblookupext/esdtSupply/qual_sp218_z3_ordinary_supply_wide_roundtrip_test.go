package esdtSupply

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// A detached report preserves positive arbitrary-precision display values at
// the one-byte to two-byte encoded field-length transition. These synthetic
// values exercise representation only, not a permitted real token quantity.
func TestQualSP218Z3OrdinarySupplyWideRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name            string
		magnitudeLength int
		fieldLength     []byte
	}{
		{"one_byte_length", 126, []byte{0x7f}},
		{"two_byte_length", 127, []byte{0x80, 0x01}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A positive magnitude with known big-endian bytes and a
			// separate positive ordinary reporting delta.
			supplyMagnitude := make([]byte, tc.magnitudeLength)
			supplyMagnitude[0] = 1
			mintedMagnitude := bytes.Clone(supplyMagnitude)
			mintedMagnitude[len(mintedMagnitude)-1] = 7
			supply := new(big.Int).SetBytes(supplyMagnitude)
			burned := big.NewInt(7)
			minted := new(big.Int).SetBytes(mintedMagnitude)
			require.Equal(t, minted, new(big.Int).Add(supply, burned))

			report := &SupplyESDT{Supply: new(big.Int).Set(supply), Burned: new(big.Int).Set(burned), Minted: new(big.Int).Set(minted)}
			// Independent expected wire using the fixed schema tags,
			// signed positive integer prefix, and explicit length bytes.
			want := []byte{0x0a}
			want = append(want, tc.fieldLength...)
			want = append(want, 0)
			want = append(want, supplyMagnitude...)
			want = append(want, 0x12, 2, 0, 7, 0x1a)
			want = append(want, tc.fieldLength...)
			want = append(want, 0)
			want = append(want, mintedMagnitude...)

			require.Equal(t, len(want), report.Size())
			wire, err := report.Marshal()
			require.NoError(t, err)
			require.Equal(t, want, wire)
			buf := make([]byte, len(want))
			n, err := report.MarshalTo(buf)
			require.NoError(t, err)
			require.Equal(t, len(want), n)
			require.Equal(t, want, buf)

			var first, second SupplyESDT
			require.NoError(t, first.Unmarshal(wire))
			require.NoError(t, second.Unmarshal(wire))
			require.True(t, report.Equal(&first))
			require.True(t, report.Equal(&second))
			require.Equal(t, supply, second.GetSupply())
			require.Equal(t, burned, second.GetBurned())
			require.Equal(t, minted, second.GetMinted())
			require.Equal(t, supply, new(big.Int).Sub(second.GetMinted(), second.GetBurned()))

			roundTrip, err := second.Marshal()
			require.NoError(t, err)
			require.Equal(t, want, roundTrip)
			// Mutate only local values after decoding; other owned
			// representations and the independent report stay intact.
			report.GetSupply().SetInt64(1)
			first.GetBurned().SetInt64(2)
			require.Equal(t, want, wire)
			wire[0] = 0
			require.Equal(t, want, buf)
			require.Equal(t, want, roundTrip)
			require.Equal(t, supply, second.GetSupply())
			require.Equal(t, burned, second.GetBurned())
			require.Equal(t, minted, second.GetMinted())
		})
	}
}
