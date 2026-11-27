package statusHandler_test

import (
	"testing"

	"github.com/multiversx/mx-chain-go/statusHandler"
	statusHandlerMock "github.com/multiversx/mx-chain-go/testscommon/statusHandler"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryStatusFacadeCounterForwarding(t *testing.T) {
	t.Parallel()

	type counterCall struct {
		method string
		key    string
		amount uint64
	}
	var first, second []counterCall
	stub := func(received *[]counterCall) *statusHandlerMock.AppStatusHandlerStub {
		return &statusHandlerMock.AppStatusHandlerStub{
			IncrementHandler: func(key string) {
				*received = append(*received, counterCall{method: "increment", key: key})
			},
			DecrementHandler: func(key string) {
				*received = append(*received, counterCall{method: "decrement", key: key})
			},
			AddUint64Handler: func(key string, amount uint64) {
				*received = append(*received, counterCall{method: "add", key: key, amount: amount})
			},
		}
	}
	facade, err := statusHandler.NewAppStatusFacadeWithHandlers(stub(&first), stub(&second))
	require.NoError(t, err)

	facade.Increment("sample_increment")
	facade.Decrement("sample_decrement")
	facade.AddUint64("sample_add", 17)
	want := []counterCall{{method: "increment", key: "sample_increment"}, {method: "decrement", key: "sample_decrement"}, {method: "add", key: "sample_add", amount: 17}}
	require.Equal(t, want, first)
	require.Equal(t, want, second)
}
