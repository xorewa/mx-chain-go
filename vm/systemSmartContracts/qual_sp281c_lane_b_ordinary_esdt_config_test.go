package systemSmartContracts

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryESDTConfigDTO(t *testing.T) {
	cost := new(big.Int).Lsh(big.NewInt(1), 70)
	value := &ESDTConfig{BaseIssuingCost: cost, MinTokenNameLength: 3, MaxTokenNameLength: 20}
	require.Equal(t, "1180591620717411303424", value.GetBaseIssuingCost().String())
	require.Equal(t, uint32(3), value.GetMinTokenNameLength())
	require.Equal(t, uint32(20), value.GetMaxTokenNameLength())

	ordinary, detailed := value.String(), value.GoString()
	require.True(t, strings.HasPrefix(ordinary, "&ESDTConfig{"))
	require.True(t, strings.HasPrefix(detailed, "&systemSmartContracts.ESDTConfig{"))
	require.True(t, strings.HasSuffix(ordinary, "}"))
	require.True(t, strings.HasSuffix(detailed, "}"))
	for _, field := range []struct {
		label string
		value interface{}
	}{
		{"BaseIssuingCost", cost}, {"MinTokenNameLength", uint32(3)}, {"MaxTokenNameLength", uint32(20)},
	} {
		require.Contains(t, ordinary, fmt.Sprintf("%s:%v,", field.label, field.value))
		require.Contains(t, detailed, fmt.Sprintf("%s: %#v,\n", field.label, field.value))
	}

	var absent *ESDTConfig
	require.Nil(t, absent.GetBaseIssuingCost())
	require.Zero(t, absent.GetMinTokenNameLength())
	require.Zero(t, absent.GetMaxTokenNameLength())
	require.Equal(t, "nil", absent.String())
	require.Equal(t, "nil", absent.GoString())
}
