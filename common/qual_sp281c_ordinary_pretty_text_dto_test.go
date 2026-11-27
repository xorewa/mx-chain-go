package common_test

import (
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryPrettyTextDTO(t *testing.T) {
	t.Parallel()

	value := struct {
		Label string   `json:"label"`
		Lines []string `json:"lines"`
	}{
		Label: "Café \"tea\"\nsecond line",
		Lines: []string{"Ångström", "ordinary note"},
	}

	got, err := common.PrettifyStruct(value)
	require.NoError(t, err)
	require.Equal(t, `{"label":"Café \"tea\"\nsecond line","lines":["Ångström","ordinary note"]}`, got)
}
