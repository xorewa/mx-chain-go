package hooks_test

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/stretchr/testify/require"
)

func TestQualSP221OrdinaryHookCleanupError(t *testing.T) {
	sentinel := errors.New("local cleanup error")
	calls := 0
	args := createMockBlockChainHookArgs()
	args.Accounts = &stateMock.AccountsStub{
		RevertToSnapshotCalled: func(snapshot int) error {
			require.Equal(t, 7, snapshot)
			calls++
			return sentinel
		},
	}

	hook, err := hooks.NewBlockChainHookImpl(args)
	require.NoError(t, err)
	require.Same(t, sentinel, hook.RevertToSnapshot(7))
	require.Equal(t, 1, calls)
}
