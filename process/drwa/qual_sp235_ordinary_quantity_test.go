package drwa

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP235OrdinaryQuantityExactMixedBytes(t *testing.T) {
	t.Parallel()

	codec := rootLeafRecords{maxAmountBytes: 32}
	quantity, ok := new(big.Int).SetString("72623859790382856", 10)
	require.True(t, ok)

	encoded, err := codec.quantityValue(quantity)
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, encoded)
	decoded, err := codec.decodeQuantityValue(encoded)
	require.NoError(t, err)
	require.Equal(t, "72623859790382856", decoded.String())
	require.Zero(t, quantity.Cmp(decoded))
}
