package transactionAPI

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryScalarDisplayBoundaries(t *testing.T) {
	t.Parallel()

	require.Equal(t, "0", bigIntToStr(big.NewInt(0)))

	const decimal = "18446744073709551616"
	value, ok := new(big.Int).SetString(decimal, 10)
	require.True(t, ok)
	require.Equal(t, decimal, bigIntToStr(value))
}
