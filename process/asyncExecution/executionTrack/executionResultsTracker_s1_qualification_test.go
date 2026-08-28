package executionTrack

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"
)

func TestS1QualificationDismissalRemainsOwnedByExternalConsumer(t *testing.T) {
	tracker := newExecutionResultsTrackerForTest()
	require.NoError(t, tracker.SetLastNotarizedResult(&block.ExecutionResult{
		BaseExecutionResult: &block.BaseExecutionResult{HeaderHash: []byte("anchor")},
	}))
	first := &block.ExecutionResult{BaseExecutionResult: &block.BaseExecutionResult{HeaderHash: []byte("first"), HeaderNonce: 1}}
	second := &block.ExecutionResult{BaseExecutionResult: &block.BaseExecutionResult{HeaderHash: []byte("second"), HeaderNonce: 1}}
	added, err := tracker.AddExecutionResult(first)
	require.NoError(t, err)
	require.True(t, added)
	added, err = tracker.AddExecutionResult(second)
	require.NoError(t, err)
	require.True(t, added)

	// The qualification replacement seam must not consume this queue. The ordinary downstream
	// consumer observes and pops the exact dismissed result.
	dismissed := tracker.PopDismissedResults()
	require.Len(t, dismissed, 1)
	require.Equal(t, first, dismissed[0].Results[0])
	require.Empty(t, tracker.PopDismissedResults())
}
