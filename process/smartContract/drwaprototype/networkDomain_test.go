package drwaprototype

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

func TestDeriveNetworkDomainPrototypeDeterministicFixture(t *testing.T) {
	t.Parallel()

	chainID := []byte("local-testnet")
	genesisHash := sequentialPrototypeDigest(161)
	domain, err := DeriveNetworkDomain(chainID, genesisHash)
	require.NoError(t, err)

	preimage := append([]byte("DRWA/NETWORK/v1local-testnet"), genesisHash[:]...)
	require.Equal(t, "445257412f4e4554574f524b2f76316c6f63616c2d746573746e6574a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0", hex.EncodeToString(preimage))
	recomputed := sha256.Sum256(preimage)
	require.Equal(t, recomputed, domain)
	require.Equal(t, "407c9f6aa143c675503bc0651d246e30710f2ea3a150c0a2268d4744a6933741", hex.EncodeToString(domain[:]))
}

func TestDeriveNetworkDomainPrototypeRejectsEmptyChainID(t *testing.T) {
	t.Parallel()

	domain, err := DeriveNetworkDomain(nil, sequentialPrototypeDigest(1))
	require.Equal(t, [prototypeDigestLength]byte{}, domain)
	require.ErrorIs(t, err, ErrInvalidNetworkDomainInput)
}

func TestDeriveNetworkDomainPrototypeCommitsEveryInputByte(t *testing.T) {
	t.Parallel()

	chainID := []byte("local-testnet")
	genesisHash := sequentialPrototypeDigest(161)
	base, err := DeriveNetworkDomain(chainID, genesisHash)
	require.NoError(t, err)

	for index := range chainID {
		changedChainID := append([]byte(nil), chainID...)
		changedChainID[index] ^= 0xff
		changed, deriveErr := DeriveNetworkDomain(changedChainID, genesisHash)
		require.NoError(t, deriveErr)
		require.NotEqualf(t, base, changed, "chain ID byte %d", index)
	}
	for index := range genesisHash {
		changedGenesisHash := genesisHash
		changedGenesisHash[index] ^= 0xff
		changed, deriveErr := DeriveNetworkDomain(chainID, changedGenesisHash)
		require.NoError(t, deriveErr)
		require.NotEqualf(t, base, changed, "genesis hash byte %d", index)
	}
}

func TestDeriveNetworkDomainPrototypeAcceptsFixedWidthZeroHash(t *testing.T) {
	t.Parallel()

	domain, err := DeriveNetworkDomain([]byte("local-testnet"), [prototypeDigestLength]byte{})
	require.NoError(t, err)
	require.NotEqual(t, [prototypeDigestLength]byte{}, domain)
}
