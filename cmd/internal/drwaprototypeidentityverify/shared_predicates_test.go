package drwaprototypeidentityverify

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	coreBlake2b "github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/stretchr/testify/require"
)

func TestSharedBindingPredicateRejectsEveryLoadBearingMutation(t *testing.T) {
	headerBytes, canonicalHash, domain := sharedHeaderIdentity(t)
	require.NotEmpty(t, headerBytes)
	valid := []byte(`{"canonical_metachain_genesis_hash":"` + hex.EncodeToString(canonicalHash[:]) + `","network_domain":"` + hex.EncodeToString(domain[:]) + `"}`)
	require.NoError(t, verifyBindingBytes(valid, canonicalHash, domain))

	wrongHash := canonicalHash
	wrongHash[0] ^= 1
	wrongDomain := domain
	wrongDomain[0] ^= 1
	mutations := map[string][]byte{
		"wrong canonical hash":   []byte(`{"canonical_metachain_genesis_hash":"` + hex.EncodeToString(wrongHash[:]) + `","network_domain":"` + hex.EncodeToString(domain[:]) + `"}`),
		"wrong network domain":   []byte(`{"canonical_metachain_genesis_hash":"` + hex.EncodeToString(canonicalHash[:]) + `","network_domain":"` + hex.EncodeToString(wrongDomain[:]) + `"}`),
		"missing canonical hash": []byte(`{"network_domain":"` + hex.EncodeToString(domain[:]) + `"}`),
		"missing network domain": []byte(`{"canonical_metachain_genesis_hash":"` + hex.EncodeToString(canonicalHash[:]) + `"}`),
		"non-string identity":    []byte(`{"canonical_metachain_genesis_hash":1,"network_domain":2}`),
		"duplicate field":        []byte(`{"canonical_metachain_genesis_hash":"a","canonical_metachain_genesis_hash":"b","network_domain":"c"}`),
		"malformed JSON":         []byte(`{"canonical_metachain_genesis_hash":`),
	}
	for name, value := range mutations {
		t.Run(name, func(t *testing.T) {
			require.Error(t, verifyBindingBytes(value, canonicalHash, domain))
		})
	}
}

func TestSharedHeaderPredicateRejectsEveryLoadBearingMutation(t *testing.T) {
	validBytes, canonicalHash, domain := sharedHeaderIdentity(t)
	_, err := verifyHeader("local-testnet", 0, validBytes, canonicalHash, domain)
	require.NoError(t, err)

	wrongHash := canonicalHash
	wrongHash[0] ^= 1
	wrongDomain := domain
	wrongDomain[0] ^= 1
	_, err = verifyHeader("local-testnet", 0, validBytes, wrongHash, domain)
	require.Error(t, err)
	_, err = verifyHeader("local-testnet", 0, validBytes, canonicalHash, wrongDomain)
	require.Error(t, err)
	_, err = verifyHeader("other-chain", 0, validBytes, canonicalHash, domain)
	require.Error(t, err)
	_, err = verifyHeader("local-testnet", 1, validBytes, canonicalHash, domain)
	require.Error(t, err)
	_, err = verifyHeader("local-testnet", 0, nil, canonicalHash, domain)
	require.Error(t, err)
	_, err = verifyHeader("local-testnet", 0, []byte{0xff}, canonicalHash, domain)
	require.Error(t, err)

	for _, test := range []struct {
		name   string
		mutate func(*block.MetaBlock)
	}{
		{name: "empty state root", mutate: func(header *block.MetaBlock) { header.RootHash = nil }},
		{name: "empty validator root", mutate: func(header *block.MetaBlock) { header.ValidatorStatsRootHash = nil }},
		{name: "wrong chain", mutate: func(header *block.MetaBlock) { header.ChainID = []byte("other-chain") }},
		{name: "wrong epoch", mutate: func(header *block.MetaBlock) { header.Epoch = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			header := sharedMetaHeader()
			test.mutate(header)
			encoded, marshalErr := (&marshal.GogoProtoMarshalizer{}).Marshal(header)
			require.NoError(t, marshalErr)
			hashBytes := coreBlake2b.NewBlake2b().Compute(string(encoded))
			var mutatedCanonicalHash [sha256.Size]byte
			copy(mutatedCanonicalHash[:], hashBytes)
			mutatedDomain, domainErr := drwaprototype.DeriveNetworkDomain(
				[]byte("local-testnet"),
				mutatedCanonicalHash,
			)
			require.NoError(t, domainErr)
			_, verifyErr := verifyHeader("local-testnet", 0, encoded, mutatedCanonicalHash, mutatedDomain)
			require.Error(t, verifyErr)
		})
	}

	// Appending a syntactically valid unknown protobuf field must not be credited as
	// canonical bytes unless unmarshal+remarshal reproduces it exactly.
	noncanonical := append(append([]byte(nil), validBytes...), 0xa0, 0x06, 0x01)
	_, err = verifyHeader("local-testnet", 0, noncanonical, canonicalHash, domain)
	require.Error(t, err)
}

func sharedHeaderIdentity(t *testing.T) ([]byte, [sha256.Size]byte, [sha256.Size]byte) {
	t.Helper()
	encoded, err := (&marshal.GogoProtoMarshalizer{}).Marshal(sharedMetaHeader())
	require.NoError(t, err)
	hashBytes := coreBlake2b.NewBlake2b().Compute(string(encoded))
	var canonicalHash [sha256.Size]byte
	copy(canonicalHash[:], hashBytes)
	domain, err := drwaprototype.DeriveNetworkDomain([]byte("local-testnet"), canonicalHash)
	require.NoError(t, err)
	return encoded, canonicalHash, domain
}

func sharedMetaHeader() *block.MetaBlock {
	return &block.MetaBlock{
		Epoch: 0, ChainID: []byte("local-testnet"),
		RootHash: sharedBytes32(1), ValidatorStatsRootHash: sharedBytes32(33),
	}
}

func sharedBytes32(first byte) []byte {
	value := make([]byte, 32)
	for index := range value {
		value[index] = first + byte(index)
	}
	return value
}
