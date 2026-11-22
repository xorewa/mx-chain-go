package drwa

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/stretchr/testify/require"
)

// Replacement proposal only: zero VM-type bytes denote NO new VM handler.
// Pinned factories register 0001 on meta and 0500 on shards. Allocation,
// genesis provisioning and future handler admission remain owner decisions.
func TestQualDRWANativeRegistrationManagerReplacementCandidate(t *testing.T) {
	address, err := hex.DecodeString("00000000000000000000000000000000000000000000000000445200ffffffff")
	require.NoError(t, err)
	require.Len(t, address, 32)
	require.True(t, core.IsSmartContractAddress(address))
	require.False(t, core.IsSystemAccountAddress(address))
	require.False(t, core.IsEmptyAddress(address))
	require.Equal(t, []byte{0, 0}, address[8:10])
	primeMinusOne := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(20))
	require.Equal(t, primeMinusOne, qualManagerCurveCharacter(t, address))
	for _, shards := range []uint32{1, 3, 256, 65536, 16777216, ^uint32(0)} {
		t.Run(fmt.Sprint(shards), func(t *testing.T) {
			for _, own := range []uint32{0, core.MetachainShardId} {
				coordinator, createErr := sharding.NewMultiShardCoordinator(shards, own)
				require.NoError(t, createErr)
				require.Equal(t, core.MetachainShardId, coordinator.ComputeId(address))
			}
		})
	}
	keyGenerator := signing.NewKeyGenerator(ed25519.NewEd25519())
	signer := &singlesig.Ed25519Signer{}
	key, err := keyGenerator.PublicKeyFromByteArray(address)
	require.NoError(t, err, "length-only wrapper is not point validation")
	private, healthy := keyGenerator.GeneratePair()
	healthyBytes, err := healthy.ToByteArray()
	require.NoError(t, err)
	require.Equal(t, big.NewInt(1), qualManagerCurveCharacter(t, healthyBytes))
	for _, message := range [][]byte{nil, []byte("DRWA replacement manager candidate proof")} {
		signature, signErr := signer.Sign(private, message)
		require.NoError(t, signErr)
		require.NoError(t, signer.Verify(healthy, message, signature))
		for _, invalid := range [][]byte{nil, make([]byte, 64), bytes.Repeat([]byte{0xff}, 64), signature} {
			require.ErrorIs(t, signer.Verify(key, message, invalid), crypto.ErrEd25519InvalidSignature)
		}
	}
}
