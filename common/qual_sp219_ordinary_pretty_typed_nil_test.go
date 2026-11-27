package common_test

import (
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

func TestQualSP219OrdinaryPrettyTypedNilDTO(t *testing.T) {
	t.Parallel()

	type displayDTO struct {
		Label string `json:"label"`
	}
	var value *displayDTO

	got, err := common.PrettifyStruct(value)
	require.NoError(t, err)
	require.Equal(t, "null", got)
}
