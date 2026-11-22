package drwa

import (
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestQualFA01ClassifierAccountIdentity(t *testing.T) {
	r, _ := qualSystemSCOrdinaryCandidate(t)
	_, foreign := qualSystemSCOrdinaryCandidate(t)
	for _, accounts := range []state.AccountsAdapter{nil, foreign} {
		called := false
		out, err := r.WithTokenClassification(accounts, []byte("AAA-abcdef"), func(bool) (*vmcommon.VMOutput, error) {
			called = true
			return &vmcommon.VMOutput{}, nil
		})
		require.ErrorIs(t, err, errInvalidMetaContext)
		require.Nil(t, out)
		require.False(t, called)
	}
}

func TestQualFA01HandoffRetainsOwnerFailure(t *testing.T) {
	old, user := qualSystemSCOrdinaryCandidate(t)
	next := qualNextSystemSCOwner(t, old, user, false)
	// Isolate the failed-owner guard from VM status latches and recovery guards.
	// This is a hostile private-state fixture, not canonical owner admission.
	old.writer.boundary.failure = ErrExecutionInterrupted
	called := false
	err := old.WithDRWAClassifierReplacement(next, func() { called = true })
	require.Same(t, ErrExecutionInterrupted, err)
	require.False(t, called)
}
