package common_test

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryPrettifyBigValueDTO(t *testing.T) {
	t.Parallel()

	value := struct {
		Integer  big.Int `json:"integer"`
		Rational big.Rat `json:"rational"`
	}{
		Integer:  *new(big.Int).Lsh(big.NewInt(1), 70),
		Rational: *big.NewRat(7, 4),
	}

	got, err := common.PrettifyStruct(value)
	require.NoError(t, err)
	require.Equal(t, `{"integer":"1180591620717411303424","rational":"7/4"}`, got)
}
