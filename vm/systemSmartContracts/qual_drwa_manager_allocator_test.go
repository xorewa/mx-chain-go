package systemSmartContracts

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/require"
)

// The proposal remains unallocated. Part A L912-914/L2271-2276 requires
// reservation, not merely unsignability. Independent integer arithmetic shows
// candidate 99686cf4 belongs to the native delegation allocation sequence
// (06c383cf delegationManager.go L173-175/L243-255/L618-630).
// This tests the real allocator at its mathematical predecessor; it does NOT
// claim a billion-contract deployment, funded reachability or a network run.
func TestQualDRWANativeRegistrationManagerAllocatorCollision(t *testing.T) {
	candidate, err := hex.DecodeString("00000000000000000001000000000000000000000000000000445257ffffffff")
	require.NoError(t, err)
	predecessor, err := hex.DecodeString("00000000000000000001000000000000000000000000000000445257feffffff")
	require.NoError(t, err)
	step := big.NewInt(16777216) // 2^24, independent of mutable nextAddressAdd
	difference := new(big.Int).Sub(new(big.Int).SetBytes(candidate), new(big.Int).SetBytes(vm.FirstDelegationSCAddress))
	increments, remainder := new(big.Int), new(big.Int)
	increments.QuoRem(difference, step, remainder)
	require.Zero(t, remainder.Sign())
	require.Equal(t, big.NewInt(1146247166), increments)
	require.LessOrEqual(t, increments.Uint64(), uint64(^uint32(0)))
	previous := new(big.Int).Mul(new(big.Int).Sub(increments, big.NewInt(1)), step)
	previous.Add(previous, new(big.Int).SetBytes(vm.FirstDelegationSCAddress))
	require.Equal(t, predecessor, previous.FillBytes(make([]byte, 32)))
	require.Equal(t, candidate, createNewAddress(predecessor))
	// Native initial-step control: allocation increments exactly the same step.
	firstNext := new(big.Int).Add(new(big.Int).SetBytes(vm.FirstDelegationSCAddress), step)
	require.Equal(t, firstNext.FillBytes(make([]byte, 32)), createNewAddress(vm.FirstDelegationSCAddress))
}
