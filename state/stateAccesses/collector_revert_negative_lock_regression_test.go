package stateAccesses

import (
	"runtime"
	"sync"
	"testing"

	data "github.com/multiversx/mx-chain-core-go/data/stateChange"
	"github.com/multiversx/mx-chain-go/state/disabled"
)

// TestCollector_RevertToIndexNegativeConcurrentMutation guards the lock in
// RevertToIndex's negative-index error path. Run this test with -race: removing
// that lock makes len(c.stateAccesses) race with AddStateAccess and Reset.
func TestCollector_RevertToIndexNegativeConcurrentMutation(t *testing.T) {
	c, err := NewCollector(disabled.NewDisabledStateAccessesStorer(), WithCollectWrite())
	if err != nil {
		t.Fatal(err)
	}

	const iterations = 50_000
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start

		for idx := 0; idx < iterations; idx++ {
			c.AddStateAccess(&data.StateAccess{Type: data.Write})
			c.Reset()
			if idx%16 == 0 {
				runtime.Gosched()
			}
		}
	}()

	go func() {
		defer wg.Done()
		<-start

		for idx := 0; idx < iterations; idx++ {
			_ = c.RevertToIndex(-1)
			if idx%16 == 0 {
				runtime.Gosched()
			}
		}
	}()

	close(start)
	wg.Wait()
}
