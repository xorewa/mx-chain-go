package presenter_test

import (
	"testing"

	"github.com/multiversx/mx-chain-go/cmd/termui/presenter"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryPresenterCounterArithmetic(t *testing.T) {
	t.Parallel()

	const key = "sample-counter"
	store := presenter.NewPresenterStatusHandler()
	store.SetUInt64Value(key, 10)
	checkValue := func(want uint64) {
		t.Helper()
		got, err := store.GetPresenterMetricByKey(key)
		require.NoError(t, err)
		require.IsType(t, want, got)
		require.Equal(t, want, got)
	}

	store.Increment(key)
	checkValue(11)
	store.AddUint64(key, 5)
	checkValue(16)
	store.Decrement(key)
	checkValue(15)
}
