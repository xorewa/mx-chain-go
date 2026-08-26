package processing

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"

	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype/networkidentity"
	"github.com/multiversx/mx-chain-go/storage"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

var (
	errInvalidPrototypeNetworkGenesis  = errors.New("invalid non-normative DRWA prototype network genesis")
	errInvalidPrototypeNetworkIdentity = networkidentity.ErrInvalid
)

type prototypeNetworkIdentityProvenance = networkidentity.Provenance

const (
	prototypeNetworkIdentityProvenanceLocalCanonicalGenesis = networkidentity.LocalCanonicalGenesis
	prototypeNetworkIdentityProvenanceEmergencyMigration    = networkidentity.EmergencyMigration
)

type prototypeNetworkIdentity struct {
	epoch         uint32
	provenance    prototypeNetworkIdentityProvenance
	chainID       []byte
	canonicalHash [32]byte
	networkDomain [32]byte
	headerBytes   []byte
}

func derivePrototypeNetworkDomain(
	chainID string,
	genesisBlocks map[uint32]data.HeaderHandler,
	marshalizer marshal.Marshalizer,
	hasher hashing.Hasher,
) ([32]byte, [32]byte, error) {
	canonicalHash, networkDomain, _, err := marshalAndDerivePrototypeNetworkDomain(
		chainID,
		genesisBlocks,
		0,
		false,
		marshalizer,
		hasher,
	)
	return canonicalHash, networkDomain, err
}

func marshalAndDerivePrototypeNetworkDomain(
	chainID string,
	genesisBlocks map[uint32]data.HeaderHandler,
	expectedEpoch uint32,
	checkEpoch bool,
	marshalizer marshal.Marshalizer,
	hasher hashing.Hasher,
) ([32]byte, [32]byte, []byte, error) {
	if len(chainID) == 0 {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: empty chain ID", errInvalidPrototypeNetworkGenesis)
	}
	if marshalizer == nil || marshalizer.IsInterfaceNil() {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: nil marshalizer", errInvalidPrototypeNetworkGenesis)
	}
	if hasher == nil || hasher.IsInterfaceNil() {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: nil hasher", errInvalidPrototypeNetworkGenesis)
	}
	genesisHeader, exists := genesisBlocks[core.MetachainShardId]
	if !exists || genesisHeader == nil || genesisHeader.IsInterfaceNil() {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: missing metachain header", errInvalidPrototypeNetworkGenesis)
	}
	genesisMetaHeader, ok := genesisHeader.(data.MetaHeaderHandler)
	if !ok || genesisMetaHeader.IsInterfaceNil() {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: wrong metachain header type", errInvalidPrototypeNetworkGenesis)
	}
	if !bytes.Equal(genesisMetaHeader.GetChainID(), []byte(chainID)) {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: metachain header chain ID", errInvalidPrototypeNetworkGenesis)
	}
	if checkEpoch && genesisMetaHeader.GetEpoch() != expectedEpoch {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf(
			"%w: metachain header epoch %d, expected %d",
			errInvalidPrototypeNetworkGenesis,
			genesisMetaHeader.GetEpoch(),
			expectedEpoch,
		)
	}
	if len(genesisMetaHeader.GetRootHash()) == 0 {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: metachain state root unavailable", errInvalidPrototypeNetworkGenesis)
	}
	if len(genesisMetaHeader.GetValidatorStatsRootHash()) == 0 {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: validator-statistics root unavailable", errInvalidPrototypeNetworkGenesis)
	}

	headerBytes, err := marshalizer.Marshal(genesisMetaHeader)
	if err != nil {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: marshal final metachain header: %w", errInvalidPrototypeNetworkGenesis, err)
	}
	canonicalHashBytes := hasher.Compute(string(headerBytes))
	if len(canonicalHashBytes) != 32 {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: canonical hash length %d", errInvalidPrototypeNetworkGenesis, len(canonicalHashBytes))
	}
	canonicalHash := [32]byte{}
	copy(canonicalHash[:], canonicalHashBytes)
	networkDomain, err := drwaprototype.DeriveNetworkDomain([]byte(chainID), canonicalHash)
	if err != nil {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: derive domain: %w", errInvalidPrototypeNetworkGenesis, err)
	}

	return canonicalHash, networkDomain, headerBytes, nil
}

func resolvePrototypeNetworkDomain(
	chainID string,
	genesisBlocks map[uint32]data.HeaderHandler,
	canonicalEpoch uint32,
	bootstrapEpoch uint32,
	storageService dataRetriever.StorageService,
	marshalizer marshal.Marshalizer,
	hasher hashing.Hasher,
) ([32]byte, [32]byte, prototypeNetworkIdentityProvenance, error) {
	if storageService == nil || storageService.IsInterfaceNil() {
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf("%w: nil storage service", errInvalidPrototypeNetworkIdentity)
	}

	key := prototypeNetworkIdentityKey(canonicalEpoch)
	storedEnvelope, getErr := storageService.Get(dataRetriever.PrototypeNetworkIdentityUnit, key)
	switch {
	case getErr == nil:
		identity, err := decodePrototypeNetworkIdentity(storedEnvelope, []byte(chainID))
		if err != nil {
			return [32]byte{}, [32]byte{}, 0, err
		}
		if identity.epoch != canonicalEpoch {
			return [32]byte{}, [32]byte{}, 0, fmt.Errorf(
				"%w: stored epoch %d, expected %d",
				errInvalidPrototypeNetworkIdentity,
				identity.epoch,
				canonicalEpoch,
			)
		}

		canonicalHash, networkDomain, err := derivePrototypeNetworkDomainFromStoredHeader(
			chainID,
			identity,
			marshalizer,
			hasher,
		)
		if err != nil {
			return [32]byte{}, [32]byte{}, 0, err
		}

		// A crash after the fresh-genesis Put can re-enter with the same fully formed
		// local header. Require byte identity instead of silently accepting a mismatch.
		if bootstrapEpoch == canonicalEpoch {
			if identity.provenance != prototypeNetworkIdentityProvenanceLocalCanonicalGenesis {
				return [32]byte{}, [32]byte{}, 0, fmt.Errorf(
					"%w: fresh genesis cannot consume %s provenance",
					errInvalidPrototypeNetworkIdentity,
					identity.provenance.String(),
				)
			}
			_, _, candidateBytes, candidateErr := marshalAndDerivePrototypeNetworkDomain(
				chainID,
				genesisBlocks,
				canonicalEpoch,
				true,
				marshalizer,
				hasher,
			)
			if candidateErr != nil {
				return [32]byte{}, [32]byte{}, 0, fmt.Errorf(
					"%w: validate fresh local canonical genesis: %w",
					errInvalidPrototypeNetworkIdentity,
					candidateErr,
				)
			}
			if !bytes.Equal(candidateBytes, identity.headerBytes) {
				return [32]byte{}, [32]byte{}, 0, fmt.Errorf(
					"%w: local canonical genesis differs from retained identity",
					errInvalidPrototypeNetworkIdentity,
				)
			}
		}
		log.Info(formatPrototypeNetworkIdentityObservation(
			canonicalEpoch,
			bootstrapEpoch,
			[]byte(chainID),
			key,
			storedEnvelope,
			canonicalHash,
			networkDomain,
			identity.provenance,
		))

		return canonicalHash, networkDomain, identity.provenance, nil
	case !errors.Is(getErr, storage.ErrKeyNotFound):
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf("%w: read retained identity: %w", errInvalidPrototypeNetworkIdentity, getErr)
	}
	if bootstrapEpoch != canonicalEpoch {
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf(
			"%w: retained identity missing on restart at epoch %d for canonical epoch %d",
			errInvalidPrototypeNetworkIdentity,
			bootstrapEpoch,
			canonicalEpoch,
		)
	}

	canonicalHash, networkDomain, headerBytes, err := marshalAndDerivePrototypeNetworkDomain(
		chainID,
		genesisBlocks,
		canonicalEpoch,
		true,
		marshalizer,
		hasher,
	)
	if err != nil {
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf(
			"%w: missing retained identity and local canonical genesis unavailable: %w",
			errInvalidPrototypeNetworkIdentity,
			err,
		)
	}

	identity := prototypeNetworkIdentity{
		epoch:         canonicalEpoch,
		provenance:    prototypeNetworkIdentityProvenanceLocalCanonicalGenesis,
		chainID:       []byte(chainID),
		canonicalHash: canonicalHash,
		networkDomain: networkDomain,
		headerBytes:   headerBytes,
	}
	envelope, err := encodePrototypeNetworkIdentity(identity)
	if err != nil {
		return [32]byte{}, [32]byte{}, 0, err
	}
	err = storageService.Put(dataRetriever.PrototypeNetworkIdentityUnit, key, envelope)
	if err != nil {
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf("%w: persist local canonical genesis: %w", errInvalidPrototypeNetworkIdentity, err)
	}
	log.Info(formatPrototypeNetworkIdentityObservation(
		canonicalEpoch,
		bootstrapEpoch,
		[]byte(chainID),
		key,
		envelope,
		canonicalHash,
		networkDomain,
		identity.provenance,
	))

	return canonicalHash, networkDomain, identity.provenance, nil
}

func formatPrototypeNetworkIdentityObservation(
	canonicalEpoch uint32,
	bootstrapEpoch uint32,
	chainID []byte,
	key []byte,
	envelope []byte,
	canonicalHash [32]byte,
	networkDomain [32]byte,
	provenance prototypeNetworkIdentityProvenance,
) string {
	envelopeSHA := sha256.Sum256(envelope)
	return fmt.Sprintf(
		"DRWA_PROTOTYPE_NETWORK_IDENTITY_V2 schema=%d canonical_epoch=%d bootstrap_epoch=%d chain_id_hex=%x storage_key_hex=%x envelope_sha256=%x canonical_hash=%x network_domain=%x provenance=%s DRWA_PROTOTYPE_NETWORK_IDENTITY_V2_END",
		networkidentity.Version,
		canonicalEpoch,
		bootstrapEpoch,
		chainID,
		key,
		envelopeSHA,
		canonicalHash,
		networkDomain,
		provenance.String(),
	)
}

func derivePrototypeNetworkDomainFromStoredHeader(
	chainID string,
	identity prototypeNetworkIdentity,
	marshalizer marshal.Marshalizer,
	hasher hashing.Hasher,
) ([32]byte, [32]byte, error) {
	metaHeader := &block.MetaBlock{}
	err := marshalizer.Unmarshal(metaHeader, identity.headerBytes)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: unmarshal retained metachain header: %w", errInvalidPrototypeNetworkIdentity, err)
	}

	canonicalHash, networkDomain, remarshalBytes, err := marshalAndDerivePrototypeNetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: metaHeader},
		identity.epoch,
		true,
		marshalizer,
		hasher,
	)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: validate retained metachain header: %w", errInvalidPrototypeNetworkIdentity, err)
	}
	if !bytes.Equal(remarshalBytes, identity.headerBytes) {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: retained metachain header is not canonical", errInvalidPrototypeNetworkIdentity)
	}
	if canonicalHash != identity.canonicalHash {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: retained canonical hash mismatch", errInvalidPrototypeNetworkIdentity)
	}
	if networkDomain != identity.networkDomain {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: retained network domain mismatch", errInvalidPrototypeNetworkIdentity)
	}

	return canonicalHash, networkDomain, nil
}

func prototypeNetworkIdentityKey(epoch uint32) []byte {
	return networkidentity.Key(epoch)
}

func encodePrototypeNetworkIdentity(identity prototypeNetworkIdentity) ([]byte, error) {
	return networkidentity.Encode(networkidentity.Record{
		SchemaVersion: networkidentity.Version,
		Epoch:         identity.epoch,
		Provenance:    identity.provenance,
		ChainID:       identity.chainID,
		CanonicalHash: identity.canonicalHash,
		NetworkDomain: identity.networkDomain,
		HeaderBytes:   identity.headerBytes,
	})
}

func decodePrototypeNetworkIdentity(envelope []byte, expectedChainID []byte) (prototypeNetworkIdentity, error) {
	record, err := networkidentity.Decode(envelope, expectedChainID)
	if err != nil {
		return prototypeNetworkIdentity{}, err
	}
	return prototypeNetworkIdentity{
		epoch:         record.Epoch,
		provenance:    record.Provenance,
		chainID:       record.ChainID,
		canonicalHash: record.CanonicalHash,
		networkDomain: record.NetworkDomain,
		headerBytes:   record.HeaderBytes,
	}, nil
}
