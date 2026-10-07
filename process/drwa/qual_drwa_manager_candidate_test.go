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

// qualManagerCurveCharacter independently checks the curve-decoding condition
// in the locked Go toolchain's edwards25519.Point.SetBytes: x^2=(y^2-1)/(dy^2+1).
// This is an input proof, not DRWA cryptography or a production decoder.
func qualManagerCurveCharacter(t *testing.T, encoded []byte) *big.Int {
	t.Helper()
	require.Len(t, encoded, 32)
	prime := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	le := bytes.Clone(encoded)
	le[31] &= 0x7f
	for i, j := 0, len(le)-1; i < j; i, j = i+1, j-1 {
		le[i], le[j] = le[j], le[i]
	}
	y := new(big.Int).SetBytes(le)
	require.Negative(t, y.Cmp(prime), "candidate/control uses a canonical y encoding")
	d := new(big.Int).ModInverse(big.NewInt(121666), prime)
	require.NotNil(t, d)
	d.Mul(d, big.NewInt(-121665)).Mod(d, prime)
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, prime)
	numerator := new(big.Int).Sub(y2, big.NewInt(1))
	denominator := new(big.Int).Mul(d, y2)
	denominator.Add(denominator, big.NewInt(1)).Mod(denominator, prime)
	inverse := new(big.Int).ModInverse(denominator, prime)
	require.NotNil(t, inverse)
	x2 := new(big.Int).Mul(numerator, inverse)
	x2.Mod(x2, prime)
	exponent := new(big.Int).Rsh(new(big.Int).Sub(prime, big.NewInt(1)), 1)
	return new(big.Int).Exp(x2, exponent, prime)
}

// Candidate only: not an allocated manager, genesis record or admitted profile.
// Part A L912-914/L2271-2276 requires a non-user-signable protocol manager;
// owner selection, allocator collision/provisioning, T14 unforgeable caller
// provenance and all protected receiving routes remain admission obligations.
func TestQualDRWANativeRegistrationManagerCandidate(t *testing.T) {
	address, err := hex.DecodeString("00000000000000000001000000000000000000000000000000445257ffffffff")
	require.NoError(t, err)
	require.Len(t, address, 32)
	require.True(t, core.IsSmartContractAddress(address))
	require.False(t, core.IsSystemAccountAddress(address))
	require.False(t, core.IsEmptyAddress(address))
	require.NotEqual(t, core.ESDTSCAddress, address)
	require.NotEqual(t, core.SystemAccountAddress, address)
	primeMinusOne := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(20))
	require.Equal(t, primeMinusOne, qualManagerCurveCharacter(t, address), "no x coordinate exists; no Ed25519 public key can decode")

	// Native coordinator reads at most four suffix bytes. Cover its width
	// transitions and uint32 maximum; these are fixtures, not admitted topology.
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
	require.NoError(t, err, "native wrapper checks length only; this is not key validity")
	private, healthy := keyGenerator.GeneratePair()
	healthyBytes, err := healthy.ToByteArray()
	require.NoError(t, err)
	require.Equal(t, big.NewInt(1), qualManagerCurveCharacter(t, healthyBytes), "independent curve check has a real valid-key control")
	for _, message := range [][]byte{nil, []byte("DRWA manager candidate proof")} {
		signature, signErr := signer.Sign(private, message)
		require.NoError(t, signErr)
		require.NoError(t, signer.Verify(healthy, message, signature))
		for _, invalid := range [][]byte{nil, make([]byte, 64), bytes.Repeat([]byte{0xff}, 64), signature} {
			require.ErrorIs(t, signer.Verify(key, message, invalid), crypto.ErrEd25519InvalidSignature)
		}
	}
}
