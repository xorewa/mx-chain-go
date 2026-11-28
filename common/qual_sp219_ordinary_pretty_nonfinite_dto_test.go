package common_test

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

// A detached measurement DTO can hold a value JSON cannot represent.
func TestQualSP219OrdinaryPrettyNonfiniteDTO(t *testing.T) {
	t.Parallel()

	type displaySample struct {
		Reading float64 `json:"reading"`
	}

	finite, err := common.PrettifyStruct(displaySample{Reading: 1.5})
	require.NoError(t, err)
	require.Equal(t, `{"reading":1.5}`, finite)

	out, err := common.PrettifyStruct(displaySample{Reading: math.NaN()})
	var encodingError *json.UnsupportedValueError
	require.ErrorAs(t, err, &encodingError)
	require.Empty(t, out)
}
