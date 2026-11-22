package drwa

import (
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/require"
)

// DS02-M7: actual existing native context/System VM, actual closed candidate.
// Cache clearing cannot erase the failure. This is not canonical recovery or
// native factory admission. Reused fixture values and read-loop sizes are
// experimental, replace or confirm before testnet admission (R7).
func TestQualDRWAVMStatusRetainsNativeFailure(t *testing.T) {
	candidate, accounts := qualSystemSCOrdinaryCandidate(t)
	f := qualSystemSCNative(t, accounts, candidate)
	runtime, exists := f.runtime.(interface{ DRWAExecutionError() error })
	require.True(t, exists)
	context, exists := f.context.(interface{ DRWAExecutionError() error })
	require.True(t, exists)
	require.NoError(t, runtime.DRWAExecutionError())
	require.NoError(t, context.DRWAExecutionError())
	require.NoError(t, candidate.abort())
	var readers sync.WaitGroup
	observed := make(chan error, 8*16)
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 16; j++ {
				observed <- context.DRWAExecutionError()
			}
		}()
	}
	output, failure := f.runtime.RunSmartContractCall(qualSystemSCInput("setBurnRoleGlobally", "TOKEN-abcdef"))
	readers.Wait()
	close(observed)
	for err := range observed {
		if err != nil {
			require.ErrorIs(t, err, vm.ErrDRWAExecution)
		}
	}
	require.Nil(t, output)
	require.ErrorIs(t, failure, vm.ErrDRWAExecution)
	require.ErrorIs(t, failure, ErrExecutionClosed)
	require.Same(t, failure, runtime.DRWAExecutionError())
	f.context.CleanCache()
	require.Same(t, failure, context.DRWAExecutionError())
	require.Same(t, failure, runtime.DRWAExecutionError())
}
