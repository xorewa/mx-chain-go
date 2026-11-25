package block

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// This checks only the ordinary Go error wrapper, not a block operation.
func TestQualSP281CBlockRollbackFailureUnwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("local sample error")
	wrapped := blockRollbackFailure{error: cause}
	require.Same(t, cause, wrapped.Unwrap())
}
