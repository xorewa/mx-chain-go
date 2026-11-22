package drwa

import (
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/require"
	"testing"
)

// Real native account/context/SystemVM graph with explicitly synthetic source
// anchors. This proves dependency/refusal mechanics, never canonical authority.
func TestQualD18NativeDeletionGuard(t *testing.T) {
	t.Run("ordinary-read-lease", func(t *testing.T) {
		r, user := qualSystemSCOrdinaryCandidate(t)
		f := qualSystemSCNative(t, user, r)
		guard := f.runtime.(vm.DRWAAccountDeletionGuard)
		calls := 0
		sentinel := errors.New("synthetic callback outcome")
		err := guard.WithDRWAAccountDeletion(user, [][]byte{[]byte("ordinary")}, func() error {
			calls++
			_, _, commitErr := r.commit()
			require.ErrorIs(t, commitErr, ErrExecutionBusy)
			nested := false
			require.ErrorIs(t, guard.WithDRWAAccountDeletion(user, nil, func() error { nested = true; return nil }), vm.ErrDRWAExecution)
			require.False(t, nested)
			return sentinel
		})
		require.Same(t, sentinel, err)
		require.Equal(t, 1, calls)
		require.NoError(t, f.runtime.(interface{ DRWAExecutionError() error }).DRWAExecutionError())
	})
	for _, kind := range []string{"protected-late", "foreign-store", "nil-store", "nil-callback", "closed-owner", "failed-owner", "replaced-owner", "unready-view"} {
		t.Run(kind, func(t *testing.T) {
			r, user := qualSystemSCOrdinaryCandidate(t)
			f := qualSystemSCNative(t, user, r)
			guard := f.runtime.(vm.DRWAAccountDeletionGuard)
			var accounts state.AccountsAdapter = user
			batch := [][]byte{[]byte("ordinary")}
			calls := 0
			cb := func() error { calls++; return nil }
			switch kind {
			case "protected-late":
				batch = append(batch, core.SystemAccountAddress)
			case "foreign-store":
				_, accounts = qualSystemSCOrdinaryCandidate(t)
			case "nil-store":
				accounts = nil
			case "nil-callback":
				cb = nil
			case "closed-owner":
				_, _, err := r.commit()
				require.NoError(t, err)
			case "failed-owner":
				r.writer.boundary.failure = ErrExecutionInterrupted
			case "unready-view":
				r.view.ready = false
			case "replaced-owner":
				_ = qualNextSystemSCOwner(t, r, user, false)
			}
			err := guard.WithDRWAAccountDeletion(accounts, batch, cb)
			require.Error(t, err)
			require.Zero(t, calls)
			if kind == "unready-view" {
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.ErrorIs(t, f.runtime.(interface{ DRWAExecutionError() error }).DRWAExecutionError(), vm.ErrDRWAExecution)
			}
			if kind == "protected-late" {
				require.ErrorIs(t, err, process.ErrNotAllowedToWriteUnderProtectedKey)
				require.NoError(t, f.runtime.(interface{ DRWAExecutionError() error }).DRWAExecutionError())
			}
		})
	}
	t.Run("unconfigured-native", func(t *testing.T) {
		_, user := qualSystemSCOrdinaryCandidate(t)
		f := qualSystemSCNative(t, user, nil)
		calls := 0
		sentinel := errors.New("ordinary result")
		require.Same(t, sentinel, f.runtime.(vm.DRWAAccountDeletionGuard).WithDRWAAccountDeletion(user, nil, func() error { calls++; return sentinel }))
		require.Equal(t, 1, calls)
	})
}
