package processProxy

import (
	"github.com/multiversx/mx-chain-go/state"
	epochNotifierMock "github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/require"
	"testing"
)

// Always refuses; construction cannot supply positive native authority.
type qualD18DenyGuard struct{}

func (*qualD18DenyGuard) WithDRWAAccountDeletion(state.AccountsAdapter, [][]byte, func() error) error {
	return vm.ErrDRWAExecution
}
func TestQualD18ProxyRetainsDeletionGuard(t *testing.T) {
	args := createMockSmartContractProcessorArguments()
	guard := &qualD18DenyGuard{}
	args.DRWAAccountDeletionGuard = guard
	proxy, err := NewSmartContractProcessorProxy(args, &epochNotifierMock.EpochNotifierStub{})
	require.NoError(t, err)
	require.Same(t, guard, proxy.args.DRWAAccountDeletionGuard)
	require.NotNil(t, proxy.processorsCache[procV1])
	require.NotNil(t, proxy.processorsCache[procV2])
}
