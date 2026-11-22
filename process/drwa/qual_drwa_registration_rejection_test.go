package drwa

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAUnadmittedNativeRegistrationRejection(t *testing.T) {
	t.Run("healthy owner refuses before original operation", func(t *testing.T) {
		candidate, store, _ := qualRegistrationCandidate(t, false, false)
		root, err := store.RootHash()
		require.NoError(t, err)
		journal := store.JournalLen()

		for range 2 {
			code, err := candidate.rejectUnadmittedNativeRegistration()
			require.Equal(t, vmcommon.UserError, code)
			require.ErrorIs(t, err, process.ErrTransactionNotExecutable)
			require.NotErrorIs(t, err, vm.ErrDRWAExecution)
			require.True(t, process.IsNotExecutableTransactionError(err))
			require.NoError(t, candidate.DRWAExecutionError())
		}

		after, err := store.RootHash()
		require.NoError(t, err)
		require.Equal(t, root, after)
		require.Equal(t, journal, store.JournalLen())
		require.Empty(t, candidate.writer.boundary.outputs)
		require.Empty(t, candidate.view.added)
	})

	t.Run("integrity cause remains fatal", func(t *testing.T) {
		candidate, _, _ := qualRegistrationCandidate(t, false, false)
		cause := errors.New("original journal unavailable")
		candidate.writer.boundary.failure = cause
		code, err := candidate.rejectUnadmittedNativeRegistration()
		require.Equal(t, vmcommon.ExecutionFailed, code)
		require.ErrorIs(t, err, vm.ErrDRWAExecution)
		require.ErrorIs(t, err, cause)
		require.NotErrorIs(t, err, process.ErrTransactionNotExecutable)
	})

	t.Run("inactive view remains fatal", func(t *testing.T) {
		candidate, _, _ := qualRegistrationCandidate(t, false, false)
		candidate.view.ready = false
		code, err := candidate.rejectUnadmittedNativeRegistration()
		require.Equal(t, vmcommon.ExecutionFailed, code)
		require.ErrorIs(t, err, vm.ErrDRWAExecution)
		require.NotErrorIs(t, err, process.ErrTransactionNotExecutable)
	})
}
