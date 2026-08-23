package processing

import (
	standardSHA256 "crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing"
	coreSHA256 "github.com/multiversx/mx-chain-core-go/hashing/sha256"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

func TestDerivePrototypeNetworkDomainUsesFinalMetachainGenesisHeader(t *testing.T) {
	t.Parallel()

	chainID := "localnet"
	metaHeader := prototypeMetaGenesisHeader(chainID)
	marshalizer := &marshal.GogoProtoMarshalizer{}
	hasher := coreSHA256.NewSha256()
	canonicalHash, networkDomain, err := derivePrototypeNetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{
			0:                     &block.Header{ShardID: 0, ChainID: []byte(chainID)},
			core.MetachainShardId: metaHeader,
		},
		marshalizer,
		hasher,
	)
	require.NoError(t, err)

	metaBytes, err := marshalizer.Marshal(metaHeader)
	require.NoError(t, err)
	independentCanonicalHash := standardSHA256.Sum256(metaBytes)
	require.Equal(t, independentCanonicalHash, canonicalHash)
	domainPreimage := []byte("DRWA/NETWORK/v1")
	domainPreimage = append(domainPreimage, chainID...)
	domainPreimage = append(domainPreimage, independentCanonicalHash[:]...)
	independentDomain := standardSHA256.Sum256(domainPreimage)
	require.Equal(t, independentDomain, networkDomain)
	require.Equal(t, "aab30a6c58e04a2986a41c1682fd1166abc2817de1db27323eb93dc8adffe130", hex.EncodeToString(canonicalHash[:]))
	require.Equal(t, "9f65a9612175fda274c3b61c8c3aa81d2cf284314976fca5aab74b8f427e744d", hex.EncodeToString(networkDomain[:]))

	changed := prototypeMetaGenesisHeader(chainID)
	changed.ValidatorStatsRootHash[0] ^= 0xff
	changedCanonical, changedDomain, err := derivePrototypeNetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: changed},
		marshalizer,
		hasher,
	)
	require.NoError(t, err)
	require.NotEqual(t, canonicalHash, changedCanonical)
	require.NotEqual(t, networkDomain, changedDomain)
}

func TestDerivePrototypeNetworkDomainRejectsUnavailableOrWrongGenesis(t *testing.T) {
	t.Parallel()

	chainID := "localnet"
	valid := prototypeMetaGenesisHeader(chainID)
	marshalizer := &marshal.GogoProtoMarshalizer{}
	hasher := coreSHA256.NewSha256()
	tests := []struct {
		name        string
		actualChain string
		blocks      map[uint32]data.HeaderHandler
	}{
		{name: "empty chain ID", blocks: map[uint32]data.HeaderHandler{core.MetachainShardId: valid}},
		{name: "missing metachain", actualChain: chainID, blocks: map[uint32]data.HeaderHandler{}},
		{name: "wrong metachain type", actualChain: chainID, blocks: map[uint32]data.HeaderHandler{core.MetachainShardId: &block.Header{ShardID: core.MetachainShardId, ChainID: []byte(chainID)}}},
		{name: "wrong header chain ID", actualChain: "other", blocks: map[uint32]data.HeaderHandler{core.MetachainShardId: valid}},
		{name: "missing validator root", actualChain: chainID, blocks: map[uint32]data.HeaderHandler{core.MetachainShardId: &block.MetaBlock{ChainID: []byte(chainID)}}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			canonicalHash, networkDomain, err := derivePrototypeNetworkDomain(test.actualChain, test.blocks, marshalizer, hasher)
			require.Equal(t, [32]byte{}, canonicalHash)
			require.Equal(t, [32]byte{}, networkDomain)
			require.ErrorIs(t, err, errInvalidPrototypeNetworkGenesis)
		})
	}
}

func TestDerivePrototypeNetworkDomainRejectsMarshalFailure(t *testing.T) {
	t.Parallel()

	canonicalHash, networkDomain, err := derivePrototypeNetworkDomain(
		"localnet",
		map[uint32]data.HeaderHandler{core.MetachainShardId: prototypeMetaGenesisHeader("localnet")},
		marshallerMock.MarshalizerMock{Fail: true},
		coreSHA256.NewSha256(),
	)
	require.Equal(t, [32]byte{}, canonicalHash)
	require.Equal(t, [32]byte{}, networkDomain)
	require.ErrorIs(t, err, errInvalidPrototypeNetworkGenesis)
	require.True(t, errors.Is(err, marshallerMock.ErrMockMarshalizer))
}

func TestDerivePrototypeNetworkDomainRejectsNilHashDependencies(t *testing.T) {
	t.Parallel()

	chainID := "localnet"
	blocks := map[uint32]data.HeaderHandler{core.MetachainShardId: prototypeMetaGenesisHeader(chainID)}
	tests := []struct {
		name        string
		marshalizer marshal.Marshalizer
		hasher      hashing.Hasher
	}{
		{name: "nil marshalizer", hasher: coreSHA256.NewSha256()},
		{name: "nil hasher", marshalizer: &marshal.GogoProtoMarshalizer{}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			canonicalHash, networkDomain, err := derivePrototypeNetworkDomain(chainID, blocks, test.marshalizer, test.hasher)
			require.Equal(t, [32]byte{}, canonicalHash)
			require.Equal(t, [32]byte{}, networkDomain)
			require.ErrorIs(t, err, errInvalidPrototypeNetworkGenesis)
		})
	}
}

func prototypeMetaGenesisHeader(chainID string) *block.MetaBlock {
	return &block.MetaBlock{
		Nonce:                  0,
		Epoch:                  0,
		Round:                  0,
		TimeStamp:              1720000000,
		ChainID:                []byte(chainID),
		RootHash:               prototypeSequentialBytes(1),
		ValidatorStatsRootHash: prototypeSequentialBytes(33),
		PrevHash:               prototypeSequentialBytes(65),
		RandSeed:               prototypeSequentialBytes(97),
		PrevRandSeed:           prototypeSequentialBytes(129),
	}
}

func prototypeSequentialBytes(first byte) []byte {
	value := make([]byte, 32)
	for index := range value {
		value[index] = first + byte(index)
	}
	return value
}
