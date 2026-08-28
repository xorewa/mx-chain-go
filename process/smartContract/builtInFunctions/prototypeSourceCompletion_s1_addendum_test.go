package builtInFunctions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestS1AddendumNoTagPostAuthMutationIsExactPassThrough(t *testing.T) {
	completion, input, _, _, _ := newDRWASourceCompletionFixture(t, false)
	payload := append([]byte(nil), input.Arguments[0]...)
	observedInput, observedPayload, err := completion.qualificationMutation.apply(input, payload)
	require.NoError(t, err)
	require.Same(t, input, observedInput)
	require.Equal(t, payload, observedPayload)
}
