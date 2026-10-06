package hooks

import (
	"errors"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE T05 lifecycle experiment, Part A L550-568/L4956 and
// proposed N02/M04 model items 2-5. No model-dependent credit before audit.
// Only calls through this fixture owner receive lifecycle invalidation.
// Direct native installers remain available: the final test retains the
// A -> B -> A counterexample. This is not exclusive production ownership,
// a classifier, a real factory binding or an authenticated F06 consumer.
type qualTimeLifecycle struct {
	mu      sync.RWMutex
	hook    *BlockChainHookImpl
	current *qualTimeOperation
}

type qualTimeOperation struct {
	owner    *qualTimeLifecycle
	expected []byte
	closed   bool
}

var errQualTimeOperation = errors.New("non-normative time operation is inactive")

func (owner *qualTimeLifecycle) invalidate() {
	if owner.current != nil {
		owner.current.closed = true
	}
	owner.current = nil
}

func (owner *qualTimeLifecycle) begin(header data.HeaderHandler) (*qualTimeOperation, error) {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	// Invalidate before a failed installation can leave the native old header.
	owner.invalidate()
	if err := owner.hook.SetCurrentHeader(header); err != nil {
		return nil, err
	}
	expected, err := core.CalculateHash(&marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), header)
	if err != nil {
		return nil, err
	}
	operation := &qualTimeOperation{owner: owner, expected: expected}
	owner.current = operation
	return operation, nil
}

func (owner *qualTimeLifecycle) read(operation *qualTimeOperation) (qualBoundHeaderMilliseconds, error) {
	owner.mu.RLock()
	defer owner.mu.RUnlock()
	if operation == nil || operation.owner != owner || operation.closed || owner.current != operation {
		return 0, errQualTimeOperation
	}
	return qualReadBoundHeaderTime(owner.hook, operation.expected, true)
}

func (owner *qualTimeLifecycle) end(operation *qualTimeOperation) {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if operation != nil && owner.current == operation {
		owner.invalidate()
	}
}

func TestQualDRWATimeOperationLifecycle(t *testing.T) {
	for _, name := range []string{"end", "same_header_replacement", "failed_installation_and_retry", "nil_installation", "valid_zero", "foreign_owner", "missing_operation"} {
		t.Run(name, func(t *testing.T) {
			header := &block.HeaderV3{Epoch: 10, TimestampMs: 1234567}
			owner := &qualTimeLifecycle{hook: qualTimeBindingHook(t, header)}
			operation, err := owner.begin(header)
			require.NoError(t, err)
			ms, err := owner.read(operation)
			require.NoError(t, err)
			require.Equal(t, qualBoundHeaderMilliseconds(1234567), ms)
			switch name {
			case "end":
				owner.end(operation)
				owner.end(operation) // Ending twice cannot restore authority.
			case "same_header_replacement":
				next, installErr := owner.begin(header)
				require.NoError(t, installErr)
				owner.end(operation) // Ending an old operation cannot end the new one.
				ms, err = owner.read(next)
				require.NoError(t, err)
				require.Equal(t, qualBoundHeaderMilliseconds(1234567), ms)
			case "failed_installation_and_retry":
				failure := errors.New("epoch-start installation failed")
				attempted := &block.HeaderV3{Epoch: 11, TimestampMs: 7654321}
				fail := true
				owner.hook.epochStartTrigger = &testscommon.EpochStartTriggerStub{
					LastCommitedEpochStartHdrCalled: func() (data.HeaderHandler, error) {
						if fail {
							return nil, failure
						}
						return attempted, nil
					},
					GetEpochStartHdrFromStorageCalled: func(uint32) (data.HeaderHandler, error) {
						t.Fatal("unexpected storage lookup: trigger epoch matches requested epoch")
						return nil, failure
					},
				}
				next, installErr := owner.begin(attempted)
				require.ErrorIs(t, installErr, failure)
				require.Nil(t, next)
				require.Equal(t, uint64(1234567), owner.hook.CurrentTimeStampMs())
				_, err = owner.read(operation)
				require.ErrorIs(t, err, errQualTimeOperation)
				fail = false
				next, installErr = owner.begin(attempted)
				require.NoError(t, installErr)
				ms, err = owner.read(next)
				require.NoError(t, err)
				require.Equal(t, qualBoundHeaderMilliseconds(7654321), ms)
			case "nil_installation":
				next, installErr := owner.begin(nil)
				require.ErrorIs(t, installErr, ErrNilCurrentHeader)
				require.Nil(t, next)
			case "valid_zero":
				zero := &block.HeaderV3{Epoch: 10, TimestampMs: 0}
				next, installErr := owner.begin(zero)
				require.NoError(t, installErr)
				ms, err = owner.read(next)
				require.NoError(t, err, "a valid zero is distinct from an invalid-context fallback")
				require.Zero(t, ms)
			case "foreign_owner":
				other := &qualTimeLifecycle{hook: owner.hook}
				_, err = other.read(operation)
				require.ErrorIs(t, err, errQualTimeOperation)
				return
			case "missing_operation":
				_, err = owner.read(nil)
				require.ErrorIs(t, err, errQualTimeOperation)
				return
			}
			_, err = owner.read(operation)
			require.ErrorIs(t, err, errQualTimeOperation)
		})
	}
}

func TestQualDRWATimeOperationConcurrentEnd(t *testing.T) {
	header := &block.HeaderV3{Epoch: 10, TimestampMs: 1234567}
	owner := &qualTimeLifecycle{hook: qualTimeBindingHook(t, header)}
	operation, err := owner.begin(header)
	require.NoError(t, err)
	start := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		<-start
		for i := 0; i < 100; i++ {
			ms, readErr := owner.read(operation)
			if readErr != nil && !errors.Is(readErr, errQualTimeOperation) {
				finished <- readErr
				return
			}
			if readErr == nil && ms != 1234567 {
				finished <- errors.New("incorrect time in a live operation")
				return
			}
		}
		finished <- nil
	}()
	close(start)
	owner.end(operation)
	require.NoError(t, <-finished)
	_, err = owner.read(operation)
	require.ErrorIs(t, err, errQualTimeOperation)
}

func TestQualDRWATimeOperationDirectInstallerABAStillOpen(t *testing.T) {
	first := &block.HeaderV3{Epoch: 10, TimestampMs: 1234567}
	second := &block.HeaderV3{Epoch: 10, TimestampMs: 7654321}
	owner := &qualTimeLifecycle{hook: qualTimeBindingHook(t, first)}
	operation, err := owner.begin(first)
	require.NoError(t, err)
	require.NoError(t, owner.hook.SetCurrentHeader(second))
	_, err = owner.read(operation)
	require.ErrorIs(t, err, errQualHeaderBinding)
	require.NoError(t, owner.hook.SetCurrentHeader(first))
	ms, err := owner.read(operation)
	// Counterexample, not conformance: private fixture lifecycle ownership
	// cannot observe installs through an exposed native alias.
	require.NoError(t, err, "the exposed installer can restore the stale header identity")
	require.Equal(t, qualBoundHeaderMilliseconds(1234567), ms)
}
