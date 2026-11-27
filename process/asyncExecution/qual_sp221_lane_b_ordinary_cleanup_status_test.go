package asyncExecution

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// The stub performs no block, state or transaction operation. It supplies a
// deterministic local cleanup result solely to test error preservation.
type ordinaryCleanupResultStub struct {
	testscommon.BlockProcessorStub
	result error
	calls  int
}

func (stub *ordinaryCleanupResultStub) RevertBlockProposalState() error {
	stub.calls++
	return stub.result
}

func TestQualSP221OrdinaryCleanupResultPreservation(t *testing.T) {
	trigger := errors.New("original local result")
	cleanupErr := errors.New("local cleanup result")
	t.Run("successful_cleanup_preserves_original_result", func(t *testing.T) {
		stub := &ordinaryCleanupResultStub{}
		executor := &headersExecutor{blockProcessor: stub}
		result := executor.finishProposalFailure(trigger, trigger)
		require.Same(t, trigger, result)
		require.Equal(t, 1, stub.calls)
	})
	t.Run("cleanup_error_preserves_both_causes", func(t *testing.T) {
		stub := &ordinaryCleanupResultStub{result: cleanupErr}
		executor := &headersExecutor{blockProcessor: stub}
		result := executor.finishProposalFailure(trigger, trigger)
		require.ErrorIs(t, result, trigger)
		require.ErrorIs(t, result, cleanupErr)
		require.Equal(t, 1, stub.calls)
	})
}

// This test checks only the local error-status bookkeeping. It starts no
// executor and uses no state, header, or transaction input.
func TestQualSP221OrdinaryCleanupStatusRetention(t *testing.T) {
	executor := &headersExecutor{}
	require.False(t, executor.retainRollbackFailure(errors.New("ordinary local result")))

	stub := &ordinaryCleanupResultStub{result: errors.New("local cleanup result")}
	executor.blockProcessor = stub
	trigger := errors.New("original local result")
	result := executor.finishProposalFailure(trigger, trigger)

	require.True(t, executor.retainRollbackFailure(result))
	require.True(t, executor.rollbackFailed)
	require.ErrorIs(t, result, trigger)
	require.ErrorIs(t, result, stub.result)
}
