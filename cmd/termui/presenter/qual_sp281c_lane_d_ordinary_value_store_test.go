package presenter_test

import (
	"testing"

	"github.com/multiversx/mx-chain-go/cmd/termui/presenter"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryPresenterValueStoreRoundTrip(t *testing.T) {
	t.Parallel()

	store := presenter.NewPresenterStatusHandler()
	store.SetStringValue("sample-text", "ordinary label")
	store.SetInt64Value("sample-signed", int64(-12))
	store.SetUInt64Value("sample-unsigned", uint64(34))

	for _, tc := range []struct {
		key  string
		want interface{}
	}{
		{"sample-text", "ordinary label"},
		{"sample-signed", int64(-12)},
		{"sample-unsigned", uint64(34)},
	} {
		got, err := store.GetPresenterMetricByKey(tc.key)
		require.NoError(t, err)
		require.IsType(t, tc.want, got)
		require.Equal(t, tc.want, got)
	}
}
