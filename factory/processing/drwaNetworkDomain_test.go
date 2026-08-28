package processing

import (
	standardSHA256 "crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing"
	coreBlake2b "github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	coreSHA256 "github.com/multiversx/mx-chain-core-go/hashing/sha256"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/stretchr/testify/require"
	standardBlake2b "golang.org/x/crypto/blake2b"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa/networkidentity"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	storageTests "github.com/multiversx/mx-chain-go/testscommon/storage"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

func TestDeriveDRWANetworkDomainUsesFinalMetachainGenesisHeader(t *testing.T) {
	t.Parallel()

	chainID := "localnet"
	metaHeader := drwaMetaGenesisHeader(chainID)
	marshalizer := &marshal.GogoProtoMarshalizer{}
	hasher := coreSHA256.NewSha256()
	canonicalHash, networkDomain, err := deriveDRWANetworkDomain(
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

	changed := drwaMetaGenesisHeader(chainID)
	changed.ValidatorStatsRootHash[0] ^= 0xff
	changedCanonical, changedDomain, err := deriveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: changed},
		marshalizer,
		hasher,
	)
	require.NoError(t, err)
	require.NotEqual(t, canonicalHash, changedCanonical)
	require.NotEqual(t, networkDomain, changedDomain)
}

func TestDeriveDRWANetworkDomainUsesConfiguredBlake2bForCanonicalHash(t *testing.T) {
	t.Parallel()

	chainID := "local-testnet"
	metaHeader := drwaMetaGenesisHeader(chainID)
	marshalizer := &marshal.GogoProtoMarshalizer{}
	canonicalHash, networkDomain, err := deriveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: metaHeader},
		marshalizer,
		coreBlake2b.NewBlake2b(),
	)
	require.NoError(t, err)
	headerBytes, err := marshalizer.Marshal(metaHeader)
	require.NoError(t, err)
	require.Equal(t, standardBlake2b.Sum256(headerBytes), canonicalHash)

	domainPreimage := append([]byte("DRWA/NETWORK/v1"+chainID), canonicalHash[:]...)
	require.Equal(t, standardSHA256.Sum256(domainPreimage), networkDomain)
}

func TestDeriveDRWANetworkDomainRejectsUnavailableOrWrongGenesis(t *testing.T) {
	t.Parallel()

	chainID := "localnet"
	valid := drwaMetaGenesisHeader(chainID)
	missingStateRoot := drwaMetaGenesisHeader(chainID)
	missingStateRoot.RootHash = nil
	missingValidatorRoot := drwaMetaGenesisHeader(chainID)
	missingValidatorRoot.ValidatorStatsRootHash = nil
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
		{name: "missing state root", actualChain: chainID, blocks: map[uint32]data.HeaderHandler{core.MetachainShardId: missingStateRoot}},
		{name: "missing validator root", actualChain: chainID, blocks: map[uint32]data.HeaderHandler{core.MetachainShardId: missingValidatorRoot}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			canonicalHash, networkDomain, err := deriveDRWANetworkDomain(test.actualChain, test.blocks, marshalizer, hasher)
			require.Equal(t, [32]byte{}, canonicalHash)
			require.Equal(t, [32]byte{}, networkDomain)
			require.ErrorIs(t, err, errInvalidDRWANetworkGenesis)
		})
	}
}

func TestDeriveDRWANetworkDomainRejectsMarshalFailure(t *testing.T) {
	t.Parallel()

	canonicalHash, networkDomain, err := deriveDRWANetworkDomain(
		"localnet",
		map[uint32]data.HeaderHandler{core.MetachainShardId: drwaMetaGenesisHeader("localnet")},
		marshallerMock.MarshalizerMock{Fail: true},
		coreSHA256.NewSha256(),
	)
	require.Equal(t, [32]byte{}, canonicalHash)
	require.Equal(t, [32]byte{}, networkDomain)
	require.ErrorIs(t, err, errInvalidDRWANetworkGenesis)
	require.True(t, errors.Is(err, marshallerMock.ErrMockMarshalizer))
}

func TestDeriveDRWANetworkDomainRejectsNilHashDependencies(t *testing.T) {
	t.Parallel()

	chainID := "localnet"
	blocks := map[uint32]data.HeaderHandler{core.MetachainShardId: drwaMetaGenesisHeader(chainID)}
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
			canonicalHash, networkDomain, err := deriveDRWANetworkDomain(chainID, blocks, test.marshalizer, test.hasher)
			require.Equal(t, [32]byte{}, canonicalHash)
			require.Equal(t, [32]byte{}, networkDomain)
			require.ErrorIs(t, err, errInvalidDRWANetworkGenesis)
		})
	}
}

func TestResolveDRWANetworkDomainFreshGenesisPersistsExactSingleMarshal(t *testing.T) {
	t.Parallel()

	const canonicalEpoch = uint32(7)
	chainID := "localnet"
	metaHeader := drwaMetaGenesisHeader(chainID)
	metaHeader.Epoch = canonicalEpoch
	blocks := map[uint32]data.HeaderHandler{core.MetachainShardId: metaHeader}
	baseMarshalizer := &marshal.GogoProtoMarshalizer{}
	marshalCalls := 0
	marshalizer := &marshallerMock.MarshalizerStub{
		MarshalCalled: func(obj interface{}) ([]byte, error) {
			marshalCalls++
			return baseMarshalizer.Marshal(obj)
		},
		UnmarshalCalled: baseMarshalizer.Unmarshal,
	}
	stored := make(map[string][]byte)
	putCalls := 0
	store := newDRWAIdentityMemoryStore(stored, nil, nil, &putCalls)

	canonicalHash, networkDomain, provenance, err := resolveDRWANetworkDomain(
		chainID,
		blocks,
		canonicalEpoch,
		canonicalEpoch,
		store,
		marshalizer,
		coreSHA256.NewSha256(),
	)
	require.NoError(t, err)
	require.Equal(t, 1, marshalCalls, "fresh genesis must marshal the final metachain header exactly once")
	require.Equal(t, 1, putCalls)
	require.Equal(t, drwaNetworkIdentityProvenanceLocalCanonicalGenesis, provenance)

	envelope := stored[string(drwaNetworkIdentityKey(canonicalEpoch))]
	identity, err := decodeDRWANetworkIdentity(envelope, []byte(chainID))
	require.NoError(t, err)
	require.Equal(t, canonicalEpoch, identity.epoch)
	require.Equal(t, provenance, identity.provenance)
	require.Equal(t, []byte(chainID), identity.chainID)
	headerBytes, err := baseMarshalizer.Marshal(metaHeader)
	require.NoError(t, err)
	require.Equal(t, headerBytes, identity.headerBytes)
	require.Equal(t, standardSHA256.Sum256(headerBytes), canonicalHash)
	require.Equal(t, canonicalHash, identity.canonicalHash)
	require.NotEqual(t, [32]byte{}, networkDomain)
	require.Equal(t, networkDomain, identity.networkDomain)
}

func TestResolveDRWANetworkDomainRestartLoadsRetainedIdentityNotPlaceholder(t *testing.T) {
	t.Parallel()

	const canonicalEpoch = uint32(0)
	chainID := "localnet"
	metaHeader := drwaMetaGenesisHeader(chainID)
	baseMarshalizer := &marshal.GogoProtoMarshalizer{}
	headerBytes, err := baseMarshalizer.Marshal(metaHeader)
	require.NoError(t, err)
	envelope, err := encodeDRWANetworkIdentity(drwaIdentityForHeaderBytes(
		chainID,
		canonicalEpoch,
		drwaNetworkIdentityProvenanceEmergencyMigration,
		headerBytes,
	))
	require.NoError(t, err)
	stored := map[string][]byte{string(drwaNetworkIdentityKey(canonicalEpoch)): envelope}
	putCalls := 0
	store := newDRWAIdentityMemoryStore(stored, nil, nil, &putCalls)
	placeholder := &block.MetaBlock{Epoch: canonicalEpoch}

	canonicalHash, networkDomain, provenance, err := resolveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: placeholder},
		canonicalEpoch,
		40,
		store,
		baseMarshalizer,
		coreSHA256.NewSha256(),
	)
	require.NoError(t, err)
	require.Equal(t, standardSHA256.Sum256(headerBytes), canonicalHash)
	require.NotEqual(t, [32]byte{}, networkDomain)
	require.Equal(t, drwaNetworkIdentityProvenanceEmergencyMigration, provenance)
	require.Zero(t, putCalls, "restart path is load-only")

	secondHash, secondDomain, secondProvenance, err := resolveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: placeholder},
		canonicalEpoch,
		41,
		store,
		baseMarshalizer,
		coreSHA256.NewSha256(),
	)
	require.NoError(t, err)
	require.Equal(t, canonicalHash, secondHash)
	require.Equal(t, networkDomain, secondDomain)
	require.Equal(t, provenance, secondProvenance)
	require.Zero(t, putCalls, "first and second restart paths must perform no repair or relocation write")
}

func TestResolveDRWANetworkDomainMissingIdentityRejectsPlaceholderWithoutWrite(t *testing.T) {
	t.Parallel()

	putCalls := 0
	store := newDRWAIdentityMemoryStore(make(map[string][]byte), nil, nil, &putCalls)
	canonicalHash, networkDomain, provenance, err := resolveDRWANetworkDomain(
		"localnet",
		map[uint32]data.HeaderHandler{core.MetachainShardId: &block.MetaBlock{}},
		0,
		40,
		store,
		&marshal.GogoProtoMarshalizer{},
		coreSHA256.NewSha256(),
	)
	require.ErrorIs(t, err, errInvalidDRWANetworkIdentity)
	require.Equal(t, [32]byte{}, canonicalHash)
	require.Equal(t, [32]byte{}, networkDomain)
	require.Zero(t, provenance)
	require.Zero(t, putCalls)
}

func TestResolveDRWANetworkDomainRejectsReadWriteAndIdentityMismatches(t *testing.T) {
	t.Parallel()

	chainID := "localnet"
	metaHeader := drwaMetaGenesisHeader(chainID)
	blocks := map[uint32]data.HeaderHandler{core.MetachainShardId: metaHeader}
	marshalizer := &marshal.GogoProtoMarshalizer{}
	headerBytes, err := marshalizer.Marshal(metaHeader)
	require.NoError(t, err)
	validEnvelope, err := encodeDRWANetworkIdentity(drwaIdentityForHeaderBytes(
		chainID,
		0,
		drwaNetworkIdentityProvenanceLocalCanonicalGenesis,
		headerBytes,
	))
	require.NoError(t, err)

	readFailure := errors.New("read failure")
	_, _, _, err = resolveDRWANetworkDomain(
		chainID, blocks, 0, 0,
		newDRWAIdentityMemoryStore(nil, readFailure, nil, nil),
		marshalizer, coreSHA256.NewSha256(),
	)
	require.ErrorIs(t, err, readFailure)

	writeFailure := errors.New("write failure")
	_, _, _, err = resolveDRWANetworkDomain(
		chainID, blocks, 0, 0,
		newDRWAIdentityMemoryStore(make(map[string][]byte), nil, writeFailure, nil),
		marshalizer, coreSHA256.NewSha256(),
	)
	require.ErrorIs(t, err, writeFailure)

	wrongStoredEpochHeader := drwaMetaGenesisHeader(chainID)
	wrongStoredEpochHeader.Epoch = 1
	wrongStoredEpochHeaderBytes, err := marshalizer.Marshal(wrongStoredEpochHeader)
	require.NoError(t, err)
	wrongEpochEnvelope, err := encodeDRWANetworkIdentity(drwaIdentityForHeaderBytes(
		chainID,
		1,
		drwaNetworkIdentityProvenanceLocalCanonicalGenesis,
		wrongStoredEpochHeaderBytes,
	))
	require.NoError(t, err)
	_, _, _, err = resolveDRWANetworkDomain(
		chainID, blocks, 0, 4,
		newDRWAIdentityMemoryStore(map[string][]byte{string(drwaNetworkIdentityKey(0)): wrongEpochEnvelope}, nil, nil, nil),
		marshalizer, coreSHA256.NewSha256(),
	)
	require.ErrorIs(t, err, errInvalidDRWANetworkIdentity)
	require.Contains(t, err.Error(), "stored epoch 1, expected 0")

	wrongChainEnvelope := append([]byte(nil), validEnvelope...)
	wrongChainEnvelope[14] ^= 0xff
	_, _, _, err = resolveDRWANetworkDomain(
		chainID, blocks, 0, 4,
		newDRWAIdentityMemoryStore(map[string][]byte{string(drwaNetworkIdentityKey(0)): wrongChainEnvelope}, nil, nil, nil),
		marshalizer, coreSHA256.NewSha256(),
	)
	require.ErrorIs(t, err, errInvalidDRWANetworkIdentity)
	require.Contains(t, err.Error(), "chain ID mismatch")

	wrongCanonicalHashEnvelope := append([]byte(nil), validEnvelope...)
	wrongCanonicalHashEnvelope[14+len(chainID)] ^= 0xff
	_, _, _, err = resolveDRWANetworkDomain(
		chainID, blocks, 0, 4,
		newDRWAIdentityMemoryStore(map[string][]byte{string(drwaNetworkIdentityKey(0)): wrongCanonicalHashEnvelope}, nil, nil, nil),
		marshalizer, coreSHA256.NewSha256(),
	)
	require.ErrorIs(t, err, errInvalidDRWANetworkIdentity)
	require.Contains(t, err.Error(), "canonical hash mismatch")

	wrongNetworkDomainEnvelope := append([]byte(nil), validEnvelope...)
	wrongNetworkDomainEnvelope[14+len(chainID)+32] ^= 0xff
	_, _, _, err = resolveDRWANetworkDomain(
		chainID, blocks, 0, 4,
		newDRWAIdentityMemoryStore(map[string][]byte{string(drwaNetworkIdentityKey(0)): wrongNetworkDomainEnvelope}, nil, nil, nil),
		marshalizer, coreSHA256.NewSha256(),
	)
	require.ErrorIs(t, err, errInvalidDRWANetworkIdentity)
	require.Contains(t, err.Error(), "network domain mismatch")

	replacementHeader := drwaMetaGenesisHeader(chainID)
	replacementHeader.TimeStamp++
	replacementHeaderBytes, marshalErr := marshalizer.Marshal(replacementHeader)
	require.NoError(t, marshalErr)
	replacementRecord := drwaIdentityForHeaderBytes(
		chainID,
		0,
		drwaNetworkIdentityProvenanceLocalCanonicalGenesis,
		replacementHeaderBytes,
	)
	validRecord, marshalErr := decodeDRWANetworkIdentity(validEnvelope, []byte(chainID))
	require.NoError(t, marshalErr)
	replacementRecord.canonicalHash = validRecord.canonicalHash
	replacementRecord.networkDomain = validRecord.networkDomain
	replacementEnvelope, marshalErr := encodeDRWANetworkIdentity(replacementRecord)
	require.NoError(t, marshalErr)
	_, _, _, err = resolveDRWANetworkDomain(
		chainID, blocks, 0, 4,
		newDRWAIdentityMemoryStore(map[string][]byte{string(drwaNetworkIdentityKey(0)): replacementEnvelope}, nil, nil, nil),
		marshalizer, coreSHA256.NewSha256(),
	)
	require.ErrorIs(t, err, errInvalidDRWANetworkIdentity)
	require.Contains(t, err.Error(), "canonical hash mismatch", "a same-chain/same-epoch header replacement cannot retain the old tuple identities")

	wrongHeaderEpoch := drwaMetaGenesisHeader(chainID)
	wrongHeaderEpoch.Epoch = 1
	wrongHeaderEpochBytes, marshalErr := marshalizer.Marshal(wrongHeaderEpoch)
	require.NoError(t, marshalErr)
	wrongHeaderEpochEnvelope, marshalErr := encodeDRWANetworkIdentity(drwaIdentityForHeaderBytes(
		chainID,
		0,
		drwaNetworkIdentityProvenanceLocalCanonicalGenesis,
		wrongHeaderEpochBytes,
	))
	require.NoError(t, marshalErr)
	_, _, _, err = resolveDRWANetworkDomain(
		chainID, blocks, 0, 4,
		newDRWAIdentityMemoryStore(map[string][]byte{string(drwaNetworkIdentityKey(0)): wrongHeaderEpochEnvelope}, nil, nil, nil),
		marshalizer, coreSHA256.NewSha256(),
	)
	require.ErrorIs(t, err, errInvalidDRWANetworkIdentity)

	changed := drwaMetaGenesisHeader(chainID)
	changed.RootHash[0] ^= 0xff
	_, _, _, err = resolveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: changed},
		0,
		0,
		newDRWAIdentityMemoryStore(map[string][]byte{string(drwaNetworkIdentityKey(0)): validEnvelope}, nil, nil, nil),
		marshalizer,
		coreSHA256.NewSha256(),
	)
	require.ErrorIs(t, err, errInvalidDRWANetworkIdentity)
}

func TestResolveDRWANetworkDomainDocumentsCoherentWholeTupleReplacementResidual(t *testing.T) {
	t.Parallel()

	chainID := "localnet"
	oldGeneration := drwaMetaGenesisHeader(chainID)
	oldGeneration.TimeStamp--
	marshalizer := &marshal.GogoProtoMarshalizer{}
	headerBytes, err := marshalizer.Marshal(oldGeneration)
	require.NoError(t, err)
	envelope, err := encodeDRWANetworkIdentity(drwaIdentityForHeaderBytes(
		chainID,
		0,
		drwaNetworkIdentityProvenanceLocalCanonicalGenesis,
		headerBytes,
	))
	require.NoError(t, err)

	hash, domain, provenance, err := resolveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: &block.MetaBlock{}},
		0,
		40,
		newDRWAIdentityMemoryStore(map[string][]byte{string(drwaNetworkIdentityKey(0)): envelope}, nil, nil, nil),
		marshalizer,
		coreSHA256.NewSha256(),
	)
	require.NoError(t, err, "coherent whole-store replacement after genesis is the explicitly accepted protocol residual")
	require.Equal(t, standardSHA256.Sum256(headerBytes), hash)
	require.NotEqual(t, [32]byte{}, domain)
	require.Equal(t, drwaNetworkIdentityProvenanceLocalCanonicalGenesis, provenance)
}

func TestResolveDRWANetworkDomainFreshGenesisRejectsEmergencyMigrationProvenance(t *testing.T) {
	t.Parallel()

	chainID := "local-testnet"
	header := drwaMetaGenesisHeader(chainID)
	marshalizer := &marshal.GogoProtoMarshalizer{}
	hasher := coreSHA256.NewSha256()
	canonicalHash, expectedDomain, headerBytes, err := marshalAndDeriveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: header},
		0,
		true,
		marshalizer,
		hasher,
	)
	require.NoError(t, err)

	emergencyEnvelope, err := encodeDRWANetworkIdentity(drwaIdentityForHeaderBytes(
		chainID,
		0,
		drwaNetworkIdentityProvenanceEmergencyMigration,
		headerBytes,
	))
	require.NoError(t, err)
	store := newDRWAIdentityMemoryStore(
		map[string][]byte{string(drwaNetworkIdentityKey(0)): emergencyEnvelope},
		nil,
		nil,
		nil,
	)

	actualHash, actualDomain, provenance, err := resolveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: header},
		0,
		0,
		store,
		marshalizer,
		hasher,
	)
	require.ErrorIs(t, err, errInvalidDRWANetworkIdentity)
	require.Contains(t, err.Error(), "fresh genesis cannot consume EMERGENCY_MIGRATION provenance")
	require.Equal(t, [32]byte{}, actualHash)
	require.Equal(t, [32]byte{}, actualDomain)
	require.Equal(t, drwaNetworkIdentityProvenance(0), provenance)
	require.NotEqual(t, [32]byte{}, canonicalHash)
	require.NotEqual(t, [32]byte{}, expectedDomain)
}

func TestResolveDRWANetworkDomainFreshGenesisRejectsUnavailableCandidateWithRetainedLocalRecord(t *testing.T) {
	t.Parallel()

	chainID := "local-testnet"
	header := drwaMetaGenesisHeader(chainID)
	marshalizer := &marshal.GogoProtoMarshalizer{}
	hasher := coreSHA256.NewSha256()
	_, _, headerBytes, err := marshalAndDeriveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: header},
		0,
		true,
		marshalizer,
		hasher,
	)
	require.NoError(t, err)
	localEnvelope, err := encodeDRWANetworkIdentity(drwaIdentityForHeaderBytes(
		chainID,
		0,
		drwaNetworkIdentityProvenanceLocalCanonicalGenesis,
		headerBytes,
	))
	require.NoError(t, err)
	store := newDRWAIdentityMemoryStore(
		map[string][]byte{string(drwaNetworkIdentityKey(0)): localEnvelope},
		nil,
		nil,
		nil,
	)

	invalidCandidate := drwaMetaGenesisHeader(chainID)
	invalidCandidate.ValidatorStatsRootHash = nil
	actualHash, actualDomain, provenance, err := resolveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: invalidCandidate},
		0,
		0,
		store,
		marshalizer,
		hasher,
	)
	require.ErrorIs(t, err, errInvalidDRWANetworkIdentity)
	require.Contains(t, err.Error(), "validate fresh local canonical genesis")
	require.Equal(t, [32]byte{}, actualHash)
	require.Equal(t, [32]byte{}, actualDomain)
	require.Equal(t, drwaNetworkIdentityProvenance(0), provenance)
}

func TestResolveDRWANetworkDomainOrdinaryAndHardforkRecordsCoexist(t *testing.T) {
	t.Parallel()

	chainID := "localnet"
	marshalizer := &marshal.GogoProtoMarshalizer{}
	hasher := coreSHA256.NewSha256()
	stored := make(map[string][]byte)
	store := newDRWAIdentityMemoryStore(stored, nil, nil, nil)

	ordinary := drwaMetaGenesisHeader(chainID)
	ordinary.Epoch = 0
	ordinaryHash, ordinaryDomain, ordinarySource, err := resolveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: ordinary},
		0, 0, store, marshalizer, hasher,
	)
	require.NoError(t, err)
	require.Equal(t, drwaNetworkIdentityProvenanceLocalCanonicalGenesis, ordinarySource)

	hardfork := drwaMetaGenesisHeader(chainID)
	hardfork.Epoch = 17
	hardfork.TimeStamp++
	hardforkHash, hardforkDomain, hardforkSource, err := resolveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: hardfork},
		17, 17, store, marshalizer, hasher,
	)
	require.NoError(t, err)
	require.Equal(t, drwaNetworkIdentityProvenanceLocalCanonicalGenesis, hardforkSource)
	require.NotEqual(t, ordinaryHash, hardforkHash)
	require.NotEqual(t, ordinaryDomain, hardforkDomain)
	require.Len(t, stored, 2)

	loadedOrdinaryHash, loadedOrdinaryDomain, _, err := resolveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: &block.MetaBlock{}},
		0, 22, store, marshalizer, hasher,
	)
	require.NoError(t, err)
	require.Equal(t, ordinaryHash, loadedOrdinaryHash)
	require.Equal(t, ordinaryDomain, loadedOrdinaryDomain)

	loadedHardforkHash, loadedHardforkDomain, _, err := resolveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: &block.MetaBlock{}},
		17, 22, store, marshalizer, hasher,
	)
	require.NoError(t, err)
	require.Equal(t, hardforkHash, loadedHardforkHash)
	require.Equal(t, hardforkDomain, loadedHardforkDomain)
}

func TestResolveDRWANetworkDomainRejectsNonCanonicalProtobufOrder(t *testing.T) {
	t.Parallel()

	chainID := "localnet"
	metaHeader := drwaMetaGenesisHeader(chainID)
	metaHeader.Nonce = 1
	marshalizer := &marshal.GogoProtoMarshalizer{}
	headerBytes, err := marshalizer.Marshal(metaHeader)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(headerBytes), 3)
	require.Equal(t, byte(0x08), headerBytes[0])
	require.Equal(t, byte(0x01), headerBytes[1])
	reordered := append(append([]byte(nil), headerBytes[2:]...), headerBytes[:2]...)

	probe := &block.MetaBlock{}
	require.NoError(t, marshalizer.Unmarshal(probe, reordered), "mutation must remain parseable")
	canonical, err := marshalizer.Marshal(probe)
	require.NoError(t, err)
	require.NotEqual(t, reordered, canonical)

	envelope, err := encodeDRWANetworkIdentity(drwaIdentityForHeaderBytes(
		chainID,
		0,
		drwaNetworkIdentityProvenanceEmergencyMigration,
		reordered,
	))
	require.NoError(t, err)
	_, _, _, err = resolveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: &block.MetaBlock{}},
		0, 5,
		newDRWAIdentityMemoryStore(map[string][]byte{string(drwaNetworkIdentityKey(0)): envelope}, nil, nil, nil),
		marshalizer,
		coreSHA256.NewSha256(),
	)
	require.ErrorIs(t, err, errInvalidDRWANetworkIdentity)
}

func TestDRWANetworkIdentityEnvelopeRejectsEveryMalformedClass(t *testing.T) {
	t.Parallel()

	chainID := "localnet"
	valid, err := encodeDRWANetworkIdentity(drwaIdentityForHeaderBytes(
		chainID,
		9,
		drwaNetworkIdentityProvenanceLocalCanonicalGenesis,
		[]byte("header"),
	))
	require.NoError(t, err)
	headerLengthOffset := 14 + len(chainID) + 32 + 32

	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "truncated", mutate: func(value []byte) []byte { return value[:13] }},
		{name: "wrong magic", mutate: func(value []byte) []byte { value[0] ^= 0xff; return value }},
		{name: "wrong version", mutate: func(value []byte) []byte { value[4]++; return value }},
		{name: "unknown provenance", mutate: func(value []byte) []byte { value[9] = 0xff; return value }},
		{name: "zero chain ID length", mutate: func(value []byte) []byte { binary.BigEndian.PutUint32(value[10:14], 0); return value }},
		{name: "wrong chain ID", mutate: func(value []byte) []byte { value[14] ^= 0xff; return value }},
		{name: "zero header length", mutate: func(value []byte) []byte {
			binary.BigEndian.PutUint32(value[headerLengthOffset:headerLengthOffset+4], 0)
			return value
		}},
		{name: "trailing byte", mutate: func(value []byte) []byte { return append(value, 0) }},
		{name: "declared chain length too large", mutate: func(value []byte) []byte { binary.BigEndian.PutUint32(value[10:14], 999); return value }},
		{name: "declared header length too large", mutate: func(value []byte) []byte {
			binary.BigEndian.PutUint32(value[headerLengthOffset:headerLengthOffset+4], 999)
			return value
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			mutated := test.mutate(append([]byte(nil), valid...))
			_, decodeErr := decodeDRWANetworkIdentity(mutated, []byte(chainID))
			require.ErrorIs(t, decodeErr, errInvalidDRWANetworkIdentity)
		})
	}

	invalidProvenance := drwaIdentityForHeaderBytes(chainID, 9, 99, []byte("header"))
	_, err = encodeDRWANetworkIdentity(invalidProvenance)
	require.ErrorIs(t, err, errInvalidDRWANetworkIdentity)
	missingHeader := drwaIdentityForHeaderBytes(chainID, 9, drwaNetworkIdentityProvenanceLocalCanonicalGenesis, []byte("header"))
	missingHeader.headerBytes = nil
	_, err = encodeDRWANetworkIdentity(missingHeader)
	require.ErrorIs(t, err, errInvalidDRWANetworkIdentity)
}

func TestResolveDRWANetworkDomainUsesOnlySelectedV2KeyAndLeavesExtrasUntouched(t *testing.T) {
	t.Parallel()

	chainID := "localnet"
	header := drwaMetaGenesisHeader(chainID)
	marshalizer := &marshal.GogoProtoMarshalizer{}
	headerBytes, err := marshalizer.Marshal(header)
	require.NoError(t, err)
	selected, err := encodeDRWANetworkIdentity(drwaIdentityForHeaderBytes(
		chainID,
		0,
		drwaNetworkIdentityProvenanceEmergencyMigration,
		headerBytes,
	))
	require.NoError(t, err)
	legacyValue := []byte("retained-v1-evidence")
	extraKey := []byte("unrelated-extra-key")
	extraValue := []byte("unrelated-extra-value")
	stored := map[string][]byte{
		string(drwaNetworkIdentityKey(0)):    selected,
		string(networkidentity.LegacyKey(0)): legacyValue,
		string(extraKey):                     extraValue,
	}
	beforeLegacy := append([]byte(nil), stored[string(networkidentity.LegacyKey(0))]...)
	beforeExtra := append([]byte(nil), stored[string(extraKey)]...)

	_, _, provenance, err := resolveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: &block.MetaBlock{}},
		0,
		4,
		newDRWAIdentityMemoryStore(stored, nil, nil, nil),
		marshalizer,
		coreSHA256.NewSha256(),
	)
	require.NoError(t, err)
	require.Equal(t, drwaNetworkIdentityProvenanceEmergencyMigration, provenance)
	require.Equal(t, beforeLegacy, stored[string(networkidentity.LegacyKey(0))])
	require.Equal(t, beforeExtra, stored[string(extraKey)])

	stored[string(drwaNetworkIdentityKey(0))] = []byte("malformed-selected-v2")
	_, _, _, err = resolveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: &block.MetaBlock{}},
		0,
		4,
		newDRWAIdentityMemoryStore(stored, nil, nil, nil),
		marshalizer,
		coreSHA256.NewSha256(),
	)
	require.ErrorIs(t, err, errInvalidDRWANetworkIdentity)
	require.Equal(t, beforeLegacy, stored[string(networkidentity.LegacyKey(0))], "extras cannot rescue or be changed by malformed selected v2")
	require.Equal(t, beforeExtra, stored[string(extraKey)], "extras cannot rescue or be changed by malformed selected v2")

	delete(stored, string(drwaNetworkIdentityKey(0)))
	_, _, _, err = resolveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: &block.MetaBlock{}},
		0,
		4,
		newDRWAIdentityMemoryStore(stored, nil, nil, nil),
		marshalizer,
		coreSHA256.NewSha256(),
	)
	require.ErrorIs(t, err, errInvalidDRWANetworkIdentity)
	require.Contains(t, err.Error(), "retained identity missing")
}

func TestDRWANetworkIdentityDecodeBorrowsExactHeaderRegion(t *testing.T) {
	t.Parallel()

	chainID := "localnet"
	envelope, err := encodeDRWANetworkIdentity(drwaIdentityForHeaderBytes(
		chainID,
		9,
		drwaNetworkIdentityProvenanceLocalCanonicalGenesis,
		[]byte("header"),
	))
	require.NoError(t, err)

	identity, err := decodeDRWANetworkIdentity(envelope, []byte(chainID))
	require.NoError(t, err)
	headerOffset := 14 + len(chainID) + 32 + 32 + 4
	require.Same(t, &envelope[headerOffset], &identity.headerBytes[0])
	require.Same(t, &envelope[14], &identity.chainID[0])
}

func TestResolveDRWANetworkDomainCrashDurableReopen(t *testing.T) {
	if os.Getenv("DRWA_PROTOTYPE_IDENTITY_CRASH_CHILD") == "1" {
		dbPath := os.Getenv("DRWA_PROTOTYPE_IDENTITY_CRASH_DB")
		chainID := "localnet"
		store := newDRWAIdentitySerialStore(t, dbPath)
		_, _, provenance, err := resolveDRWANetworkDomain(
			chainID,
			map[uint32]data.HeaderHandler{core.MetachainShardId: drwaMetaGenesisHeader(chainID)},
			0,
			0,
			store,
			&marshal.GogoProtoMarshalizer{},
			coreSHA256.NewSha256(),
		)
		require.NoError(t, err)
		require.Equal(t, drwaNetworkIdentityProvenanceLocalCanonicalGenesis, provenance)
		// Intentionally bypass every defer and CloseAll after the synchronous Put.
		os.Exit(0)
	}

	// Do not run in parallel: the child exits immediately after the production
	// resolver's synchronous Put, without closing either storage unit or DB.
	dbPath := filepath.Join(t.TempDir(), "prototype-network-identity")
	chainID := "localnet"
	metaHeader := drwaMetaGenesisHeader(chainID)
	blocks := map[uint32]data.HeaderHandler{core.MetachainShardId: metaHeader}
	marshalizer := &marshal.GogoProtoMarshalizer{}
	hasher := coreSHA256.NewSha256()
	firstHash, firstDomain, _, err := marshalAndDeriveDRWANetworkDomain(
		chainID, blocks, 0, true, marshalizer, hasher,
	)
	require.NoError(t, err)

	cmd := exec.Command(os.Args[0], "-test.run=^TestResolveDRWANetworkDomainCrashDurableReopen$")
	cmd.Env = append(
		os.Environ(),
		"DRWA_PROTOTYPE_IDENTITY_CRASH_CHILD=1",
		"DRWA_PROTOTYPE_IDENTITY_CRASH_DB="+dbPath,
	)
	require.NoError(t, cmd.Run())

	secondStore := newDRWAIdentitySerialStore(t, dbPath)
	t.Cleanup(func() { require.NoError(t, secondStore.CloseAll()) })
	placeholder := map[uint32]data.HeaderHandler{core.MetachainShardId: &block.MetaBlock{Epoch: 0}}
	secondHash, secondDomain, secondProvenance, err := resolveDRWANetworkDomain(
		chainID, placeholder, 0, 1, secondStore, marshalizer, hasher,
	)
	require.NoError(t, err)
	require.Equal(t, firstHash, secondHash)
	require.Equal(t, firstDomain, secondDomain)
	require.Equal(t, drwaNetworkIdentityProvenanceLocalCanonicalGenesis, secondProvenance)
}

func TestProcessComponentsFactoryDRWACanonicalEpoch(t *testing.T) {
	t.Parallel()

	pcf := &processComponentsFactory{config: config.Config{EpochStartConfig: config.EpochStartConfig{GenesisEpoch: 7}}}
	require.Equal(t, uint32(7), pcf.drwaCanonicalEpoch())
	pcf.config.Hardfork.AfterHardFork = true
	pcf.config.Hardfork.StartEpoch = 19
	require.Equal(t, uint32(19), pcf.drwaCanonicalEpoch())
}

func TestProcessComponentsFactoryRejectsIdentityBeforeBlockProcessorConstruction(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	sourcePath := filepath.Join(filepath.Dir(currentFile), "processComponents.go")
	source, err := os.ReadFile(sourcePath)
	require.NoError(t, err)

	createStart := strings.Index(string(source), "func (pcf *processComponentsFactory) Create()")
	createEnd := strings.Index(string(source), "func (pcf *processComponentsFactory) drwaCanonicalEpoch()")
	require.GreaterOrEqual(t, createStart, 0)
	require.Greater(t, createEnd, createStart)
	createBody := string(source[createStart:createEnd])
	identityResolve := strings.Index(createBody, "resolveDRWANetworkDomain(")
	identityReturn := strings.Index(createBody[identityResolve:], "if err != nil {\n\t\treturn nil, err\n\t}")
	blockProcessor := strings.Index(createBody, "pcf.newBlockProcessor(")
	require.GreaterOrEqual(t, identityResolve, 0)
	require.GreaterOrEqual(t, identityReturn, 0, "identity failure must return from Create")
	require.Greater(t, blockProcessor, identityResolve, "identity resolution must precede block-processor construction")
}

func TestDRWANetworkIdentityObservationIsExactAndMachineParseable(t *testing.T) {
	chainID := []byte("localnet")
	header := drwaMetaGenesisHeader(string(chainID))
	headerBytes, err := (&marshal.GogoProtoMarshalizer{}).Marshal(header)
	require.NoError(t, err)
	identity := drwaIdentityForHeaderBytes(
		string(chainID),
		0,
		drwaNetworkIdentityProvenanceLocalCanonicalGenesis,
		headerBytes,
	)
	envelope, err := encodeDRWANetworkIdentity(identity)
	require.NoError(t, err)
	envelopeSHA := standardSHA256.Sum256(envelope)
	observation := formatDRWANetworkIdentityObservation(
		0,
		0,
		chainID,
		drwaNetworkIdentityKey(0),
		envelope,
		identity.canonicalHash,
		identity.networkDomain,
		identity.provenance,
	)
	require.Equal(t, fmt.Sprintf(
		"DRWA_PROTOTYPE_NETWORK_IDENTITY_V2 schema=2 canonical_epoch=0 bootstrap_epoch=0 chain_id_hex=%x storage_key_hex=%x envelope_sha256=%x canonical_hash=%x network_domain=%x provenance=LOCAL_CANONICAL_GENESIS DRWA_PROTOTYPE_NETWORK_IDENTITY_V2_END",
		chainID,
		drwaNetworkIdentityKey(0),
		envelopeSHA,
		identity.canonicalHash,
		identity.networkDomain,
	), observation)
}

func newDRWAIdentityMemoryStore(
	values map[string][]byte,
	getErr error,
	putErr error,
	putCalls *int,
) dataRetriever.StorageService {
	if values == nil {
		values = make(map[string][]byte)
	}

	return &storageTests.ChainStorerStub{
		GetCalled: func(unitType dataRetriever.UnitType, key []byte) ([]byte, error) {
			if unitType != dataRetriever.DRWANetworkIdentityUnit {
				return nil, fmt.Errorf("unexpected unit %s", unitType)
			}
			if getErr != nil {
				return nil, getErr
			}
			value, ok := values[string(key)]
			if !ok {
				return nil, storage.ErrKeyNotFound
			}
			return append([]byte(nil), value...), nil
		},
		PutCalled: func(unitType dataRetriever.UnitType, key []byte, value []byte) error {
			if unitType != dataRetriever.DRWANetworkIdentityUnit {
				return fmt.Errorf("unexpected unit %s", unitType)
			}
			if putCalls != nil {
				(*putCalls)++
			}
			if putErr != nil {
				return putErr
			}
			values[string(key)] = append([]byte(nil), value...)
			return nil
		},
	}
}

func newDRWAIdentitySerialStore(t *testing.T, dbPath string) *dataRetriever.ChainStorer {
	t.Helper()

	cache, err := storageunit.NewCache(storageunit.CacheConfig{
		Name:     "prototype-network-identity-test",
		Type:     storageunit.LRUCache,
		Capacity: 4,
	})
	require.NoError(t, err)
	persister, err := storageunit.NewDB(storageunit.ArgDB{
		DBType:            storageunit.LvlDBSerial,
		Path:              dbPath,
		BatchDelaySeconds: 2,
		MaxBatchSize:      1,
		MaxOpenFiles:      10,
	})
	require.NoError(t, err)
	unit, err := storageunit.NewStorageUnit(cache, persister)
	require.NoError(t, err)
	chainStore := dataRetriever.NewChainStorer()
	chainStore.AddStorer(dataRetriever.DRWANetworkIdentityUnit, unit)
	return chainStore
}

func drwaMetaGenesisHeader(chainID string) *block.MetaBlock {
	return &block.MetaBlock{
		Nonce:                  0,
		Epoch:                  0,
		Round:                  0,
		TimeStamp:              1720000000,
		ChainID:                []byte(chainID),
		RootHash:               drwaSequentialBytes(1),
		ValidatorStatsRootHash: drwaSequentialBytes(33),
		PrevHash:               drwaSequentialBytes(65),
		RandSeed:               drwaSequentialBytes(97),
		PrevRandSeed:           drwaSequentialBytes(129),
	}
}

func drwaIdentityForHeaderBytes(
	chainID string,
	epoch uint32,
	provenance drwaNetworkIdentityProvenance,
	headerBytes []byte,
) drwaNetworkIdentity {
	canonicalHash := standardSHA256.Sum256(headerBytes)
	domainPreimage := append([]byte("DRWA/NETWORK/v1"), []byte(chainID)...)
	domainPreimage = append(domainPreimage, canonicalHash[:]...)
	networkDomain := standardSHA256.Sum256(domainPreimage)

	return drwaNetworkIdentity{
		epoch:         epoch,
		provenance:    provenance,
		chainID:       []byte(chainID),
		canonicalHash: canonicalHash,
		networkDomain: networkDomain,
		headerBytes:   headerBytes,
	}
}

func drwaSequentialBytes(first byte) []byte {
	value := make([]byte, 32)
	for index := range value {
		value[index] = first + byte(index)
	}
	return value
}
