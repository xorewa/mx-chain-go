package processing

import (
	"testing"

	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/require"
)

// Only constructor forwarding is modelled; this guard always refuses and
// cannot supply a native creating-owner, G6 locator or authenticated source.
type qualNativeDeletionFactory struct {
	process.VirtualMachinesContainerFactory
	guard vm.DRWAAccountDeletionGuard
}

func (f *qualNativeDeletionFactory) DRWAAccountDeletionGuard() vm.DRWAAccountDeletionGuard {
	return f.guard
}

type qualNativeDeletionRefusal struct{}

func (*qualNativeDeletionRefusal) WithDRWAAccountDeletion(state.AccountsAdapter, [][]byte, func() error) error {
	return vm.ErrDRWAExecution
}

func TestQualNativeDeletionFactoryForwarding(t *testing.T) {
	require.Nil(t, nativeDRWAAccountDeletionGuard(nil))
	require.Nil(t, nativeDRWAAccountDeletionGuard(&qualNativeDeletionFactory{}))
	guard := &qualNativeDeletionRefusal{}
	require.Same(t, guard, nativeDRWAAccountDeletionGuard(&qualNativeDeletionFactory{guard: guard}))
}
