package systemSmartContracts

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/require"
)

// Native allocation is strictly increasing from FirstDelegationSCAddress.
// The proposed replacement is BELOW that starting value, so it cannot occur
// in this sequence regardless of its length. This is not a genesis reservation.
func TestQualDRWANativeRegistrationManagerReplacementBelowAllocator(t *testing.T) {
	candidate, err := hex.DecodeString("00000000000000000000000000000000000000000000000000445200ffffffff")
	require.NoError(t, err)
	initial := new(big.Int).SetBytes(vm.FirstDelegationSCAddress)
	require.Negative(t, new(big.Int).SetBytes(candidate).Cmp(initial))
	for _, address := range [][]byte{vm.StakingSCAddress, vm.ValidatorSCAddress, vm.ESDTSCAddress,
		vm.GovernanceSCAddress, vm.JailingAddress, vm.EndOfEpochAddress, vm.DelegationManagerSCAddress,
		vm.FirstDelegationSCAddress} {
		require.NotEqual(t, candidate, address)
	}
	require.Positive(t, new(big.Int).SetBytes(createNewAddress(vm.FirstDelegationSCAddress)).Cmp(initial))
}
