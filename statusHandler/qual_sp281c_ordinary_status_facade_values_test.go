package statusHandler_test

import (
	"testing"

	"github.com/multiversx/mx-chain-go/statusHandler"
	statusHandlerMock "github.com/multiversx/mx-chain-go/testscommon/statusHandler"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryStatusFacadeSuppliedValues(t *testing.T) {
	t.Parallel()

	type metric struct {
		key   string
		value interface{}
	}
	var first, second []metric
	stub := func(received *[]metric) *statusHandlerMock.AppStatusHandlerStub {
		return &statusHandlerMock.AppStatusHandlerStub{
			SetStringValueHandler: func(key string, value string) {
				*received = append(*received, metric{key, value})
			},
			SetInt64ValueHandler: func(key string, value int64) {
				*received = append(*received, metric{key, value})
			},
			SetUInt64ValueHandler: func(key string, value uint64) {
				*received = append(*received, metric{key, value})
			},
		}
	}
	facade, err := statusHandler.NewAppStatusFacadeWithHandlers(stub(&first), stub(&second))
	require.NoError(t, err)

	facade.SetStringValue("sample_label", "ordinary display")
	facade.SetInt64Value("sample_signed", -17)
	facade.SetUInt64Value("sample_unsigned", 42)
	want := []metric{{"sample_label", "ordinary display"}, {"sample_signed", int64(-17)}, {"sample_unsigned", uint64(42)}}
	require.Equal(t, want, first)
	require.Equal(t, want, second)
}
