package asyncExecution

import (
	"errors"
	"testing"
)

func TestQualSP281COrdinaryProposalErrorUnwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("ordinary example")
	wrapped := proposalRollbackFailure{error: cause}
	if got := errors.Unwrap(wrapped); got != cause {
		t.Fatalf("expected exact wrapped error, got %v", got)
	}
}
