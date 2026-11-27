package presenter_test

import (
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-go/cmd/termui/presenter"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryPresenterConcurrentCounters(t *testing.T) {
	t.Parallel()

	const first = "sample-counter-first"
	const second = "sample-counter-second"
	store := presenter.NewPresenterStatusHandler()
	store.SetUInt64Value(first, 10)
	store.SetUInt64Value(second, 20)

	var done sync.WaitGroup
	start := make(chan struct{})
	done.Add(2)
	go func() {
		defer done.Done()
		<-start
		store.Increment(first)
		store.AddUint64(second, 3)
	}()
	go func() {
		defer done.Done()
		<-start
		store.AddUint64(first, 4)
		store.Decrement(second)
	}()
	close(start)
	done.Wait()

	gotFirst, err := store.GetPresenterMetricByKey(first)
	require.NoError(t, err)
	require.IsType(t, uint64(0), gotFirst)
	require.Equal(t, uint64(15), gotFirst)
	gotSecond, err := store.GetPresenterMetricByKey(second)
	require.NoError(t, err)
	require.IsType(t, uint64(0), gotSecond)
	require.Equal(t, uint64(22), gotSecond)
}
