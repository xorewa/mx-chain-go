package systemSmartContracts

import (
	"runtime"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/require"
)

// These fixtures exercise only the context's status/execution lock boundary.
// Real owner lineage, native output and gas remain covered by the unchanged
// process/drwa TestQualDRWASystemSCHandoff and refusal tests.
type qualStatusHandoffClassifier struct {
	qualFA01HandoffClassifier
	health  func() error
	replace func(vm.DRWATokenClassifier, func()) error
}

func (c *qualStatusHandoffClassifier) DRWAExecutionHealthError() error {
	if c.health != nil {
		return c.health()
	}
	return nil
}

func (c *qualStatusHandoffClassifier) WithDRWAClassifierReplacement(next vm.DRWATokenClassifier, replace func()) error {
	if c.replace != nil {
		return c.replace(next, replace)
	}
	replace()
	return nil
}

func TestQualDRWAClassifierPassiveReadHandoff(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseRead := func() { releaseOnce.Do(func() { close(release) }) }
	old := &qualStatusHandoffClassifier{health: func() error {
		close(entered)
		<-release
		return nil
	}}
	args := createDefaultEeiArgs()
	args.DRWAClassifier = old
	host, err := NewVMContext(args)
	require.NoError(t, err)
	readResult := make(chan error, 1)
	go func() { readResult <- host.DRWAExecutionError() }()
	defer func() { releaseRead(); require.NoError(t, <-readResult) }()
	<-entered // the production status read now owns its read dependency

	free := host.mutDRWAClassifier.TryLock()
	if free {
		host.mutDRWAClassifier.Unlock()
	}
	require.True(t, free, "passive status read must leave classifier execution exclusion available")

	next := &qualStatusHandoffClassifier{}
	writerResult := make(chan error, 1)
	go func() { writerResult <- host.ReplaceDRWAClassifier(next) }()
	defer func() {
		releaseRead()
		require.NoError(t, <-writerResult)
		require.Same(t, next, host.drwaClassifier)
	}()
	// Observe the writer blocked inside the status mutex without taking any
	// classifier lock: a contending probe could itself cause TryLock refusal.
	// No elapsed time establishes exclusion; go test's deadline is a watchdog.
	for !qualStatusHandoffWriterWaiting() {
		select {
		case err = <-writerResult:
			writerResult <- err // retain the result for deferred cleanup
			t.Fatalf("handoff returned before passive status release: %v", err)
		default:
			runtime.Gosched()
		}
	}
	select {
	case err = <-writerResult:
		writerResult <- err
		t.Fatalf("handoff returned before passive status release: %v", err)
	default:
	}
	releaseRead()
	// Deferred receives join both goroutines before the test ends.
}

func qualStatusHandoffWriterWaiting() bool {
	for {
		n, _ := runtime.GoroutineProfile(nil)
		stacks := make([]runtime.StackRecord, n+1)
		n, captured := runtime.GoroutineProfile(stacks)
		if !captured {
			continue
		}
		for _, stack := range stacks[:n] {
			frames := runtime.CallersFrames(stack.Stack())
			mutexWait := false
			for {
				frame, more := frames.Next()
				if frame.Function == "sync.(*RWMutex).Lock" {
					mutexWait = true
				}
				if mutexWait && frame.Function == "github.com/multiversx/mx-chain-go/vm/systemSmartContracts.(*vmContext).ReplaceDRWAClassifier" {
					return true
				}
				if !more {
					break
				}
			}
		}
		return false
	}
}

func TestQualDRWAClassifierHandoffStatusWriterGuard(t *testing.T) {
	old := &qualStatusHandoffClassifier{}
	args := createDefaultEeiArgs()
	args.DRWAClassifier = old
	host, err := NewVMContext(args)
	require.NoError(t, err)
	called, statusWriterHeld, classifierWriterHeld := false, false, false
	old.replace = func(_ vm.DRWATokenClassifier, replace func()) error {
		called = true
		free := host.mutDRWAStatus.TryRLock()
		statusWriterHeld = !free
		if free {
			host.mutDRWAStatus.RUnlock()
		}
		free = host.mutDRWAClassifier.TryRLock()
		classifierWriterHeld = !free
		if free {
			host.mutDRWAClassifier.RUnlock()
		}
		replace()
		return nil
	}
	next := &qualStatusHandoffClassifier{}
	require.NoError(t, host.ReplaceDRWAClassifier(next))
	require.True(t, called)
	require.True(t, statusWriterHeld, "replacement callback must hold the status writer guard")
	require.True(t, classifierWriterHeld, "replacement callback must hold the classifier writer guard")
	require.Same(t, next, host.drwaClassifier)
	require.NoError(t, host.DRWAExecutionError())
}
