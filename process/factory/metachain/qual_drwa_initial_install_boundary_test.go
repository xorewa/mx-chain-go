package metachain

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/vm"
	vmmock "github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Synthetic factory construction, not an appointment/authentication provider.
// The ordinary mock contract output models native dispatch only; it supplies
// no creating-owner/appointment provider. Real ESDT reserved-name refusal is
// exercised separately by the pinned-source ordinary differential.
func TestQualA72FactoryUnconfiguredPreservesNativeDispatch(t *testing.T) {
	args := createVmContainerMockArgument(makeGasSchedule())
	require.Nil(t, args.DRWAClassifier)
	owner, err := NewVMContainerFactory(args)
	require.NoError(t, err)
	_, context, err := owner.createSystemVMFactoryAndEEI()
	require.NoError(t, err)
	calls := 0
	owner.systemContracts = &vmmock.SystemSCContainerStub{GetCalled: func([]byte) (vm.SystemSmartContract, error) { calls++; return &vmmock.SystemSCStub{}, nil }}
	runtime, err := owner.finalizeSystemVMCreation(context)
	require.NoError(t, err)
	for index, recipient := range [][]byte{nil, core.ESDTSCAddress, []byte("foreign")} {
		output, callErr := runtime.RunSmartContractCall(&vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallValue: big.NewInt(1), GasProvided: 100}, RecipientAddr: recipient, Function: "DRWAInstallInitialProgrammeAuthorities"})
		require.NoError(t, callErr)
		require.Equal(t, vmcommon.Ok, output.ReturnCode)
		require.Equal(t, uint64(100), output.GasRemaining)
		require.Equal(t, index+1, calls)
	}
	require.Nil(t, owner.drwaClassifier)
}
