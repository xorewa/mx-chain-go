package hooks_test

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/stretchr/testify/require"
)

// T42-1 reproduction on the real constructor. This probe does not substitute
// for the native lifecycle and actual record-consumer checks in this repair.
// The optional adapter is the engineering boundary selected under architecture
// 5.4 N-02/M-04 and PB-01; no vm-common interface is widened.
func TestQualDRWAT42NativeTimeAdapter(t *testing.T) {
	args := createMockBlockChainHookArgs()
	t.Cleanup(func() { require.NoError(t, args.DataPool.Close()) })
	hook, err := hooks.NewBlockChainHookImpl(args)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, hook.Close()) })
	_, exists := any(hook).(interface {
		BeginDRWAHeaderEvaluation() (func(data.HeaderHandler) error, func(), error)
		EvaluatedHeaderTimeContext() (*drwa.HeaderTimeContext, error)
	})
	require.True(t, exists, "T42-1: the native constructor must provide its own evaluated-header lifecycle and typed consumer adapter")
}
