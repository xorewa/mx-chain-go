package systemSmartContracts

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// INV-0: an unconfigured context must reach native execution without owning
// the DRWA lock. TryLock observes ownership without timing or blocked goroutines.
func TestQualFA01OrdinarySystemSCNoClassifierLock(t *testing.T) {
	host, err := NewVMContext(createDefaultEeiArgs())
	require.NoError(t, err)
	args := createMockArgumentsForESDT()
	args.Eei = host
	sc, err := NewESDTSmartContract(args)
	require.NoError(t, err)
	observed := false
	args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).IsFlagEnabledCalled = func(flag core.EnableEpochFlag) bool {
		if flag == common.ESDTFlag {
			observed = true
			unlocked := host.mutDRWAClassifier.TryLock()
			if unlocked {
				host.mutDRWAClassifier.Unlock()
			}
			require.True(t, unlocked, "ordinary native dispatch owns the DRWA lock")
		}
		return false
	}
	require.Equal(t, vmcommon.UserError, sc.Execute(&vmcommon.ContractCallInput{
		VMInput:       vmcommon.VMInput{CallValue: big.NewInt(0), CallerAddr: core.ESDTSCAddress},
		RecipientAddr: core.ESDTSCAddress, Function: "pause",
	}))
	require.True(t, observed)
	for _, recipient := range [][]byte{nil, core.ESDTSCAddress} {
		_, err = host.ExecuteDRWASystemCall(&vmcommon.ContractCallInput{RecipientAddr: recipient}, func() (*vmcommon.VMOutput, error) {
			unlocked := host.mutDRWAClassifier.TryLock()
			if unlocked {
				host.mutDRWAClassifier.Unlock()
			}
			require.True(t, unlocked, "ordinary VM boundary owns the DRWA lock")
			return nil, nil
		})
		require.NoError(t, err)
	}
}

type qualFA01HandoffClassifier struct {
	vm.DRWATokenClassifier
	replaced bool
}

func (c *qualFA01HandoffClassifier) IsInterfaceNil() bool { return c == nil }
func (c *qualFA01HandoffClassifier) ValidateAccounts(state.AccountsAdapter, state.AccountsAdapter) error {
	return nil
}
func (c *qualFA01HandoffClassifier) WithDRWAClassifierReplacement(_ vm.DRWATokenClassifier, replace func()) error {
	c.replaced = true
	replace()
	return nil
}

// Isolate the context boundary from the separate System-VM and owner guards.
func TestQualFA01ContextHandoffLock(t *testing.T) {
	old := &qualFA01HandoffClassifier{}
	args := createDefaultEeiArgs()
	args.DRWAClassifier = old
	host, err := NewVMContext(args)
	require.NoError(t, err)
	host.mutDRWAClassifier.RLock()
	err = host.ReplaceDRWAClassifier(&qualFA01HandoffClassifier{})
	host.mutDRWAClassifier.RUnlock()
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.False(t, old.replaced)
	require.Same(t, old, host.drwaClassifier)
}
