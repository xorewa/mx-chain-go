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
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa/networkidentity"
	"github.com/multiversx/mx-chain-go/storage"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

var (
	errInvalidDRWANetworkGenesis  = errors.New("invalid non-normative DRWA prototype network genesis")
	errInvalidDRWANetworkIdentity = networkidentity.ErrInvalid
)

type drwaNetworkIdentityProvenance = networkidentity.Provenance

const (
	drwaNetworkIdentityProvenanceLocalCanonicalGenesis = networkidentity.LocalCanonicalGenesis
	drwaNetworkIdentityProvenanceEmergencyMigration    = networkidentity.EmergencyMigration
)

type drwaNetworkIdentity struct {
	epoch         uint32
	provenance    drwaNetworkIdentityProvenance
	chainID       []byte
	canonicalHash [32]byte
	networkDomain [32]byte
	headerBytes   []byte
}

func deriveDRWANetworkDomain(
	chainID string,
	genesisBlocks map[uint32]data.HeaderHandler,
	marshalizer marshal.Marshalizer,
	hasher hashing.Hasher,
) ([32]byte, [32]byte, error) {
	canonicalHash, networkDomain, _, err := marshalAndDeriveDRWANetworkDomain(
		chainID,
		genesisBlocks,
		0,
		false,
		marshalizer,
		hasher,
	)
	return canonicalHash, networkDomain, err
}

func marshalAndDeriveDRWANetworkDomain(
	chainID string,
	genesisBlocks map[uint32]data.HeaderHandler,
	expectedEpoch uint32,
	checkEpoch bool,
	marshalizer marshal.Marshalizer,
	hasher hashing.Hasher,
) ([32]byte, [32]byte, []byte, error) {
	if len(chainID) == 0 {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: empty chain ID", errInvalidDRWANetworkGenesis)
	}
	if marshalizer == nil || marshalizer.IsInterfaceNil() {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: nil marshalizer", errInvalidDRWANetworkGenesis)
	}
	if hasher == nil || hasher.IsInterfaceNil() {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: nil hasher", errInvalidDRWANetworkGenesis)
	}
	genesisHeader, exists := genesisBlocks[core.MetachainShardId]
	if !exists || genesisHeader == nil || genesisHeader.IsInterfaceNil() {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: missing metachain header", errInvalidDRWANetworkGenesis)
	}
	genesisMetaHeader, ok := genesisHeader.(data.MetaHeaderHandler)
	if !ok || genesisMetaHeader.IsInterfaceNil() {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: wrong metachain header type", errInvalidDRWANetworkGenesis)
	}
	if !bytes.Equal(genesisMetaHeader.GetChainID(), []byte(chainID)) {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: metachain header chain ID", errInvalidDRWANetworkGenesis)
	}
	if checkEpoch && genesisMetaHeader.GetEpoch() != expectedEpoch {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf(
			"%w: metachain header epoch %d, expected %d",
			errInvalidDRWANetworkGenesis,
			genesisMetaHeader.GetEpoch(),
			expectedEpoch,
		)
	}
	if len(genesisMetaHeader.GetRootHash()) == 0 {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: metachain state root unavailable", errInvalidDRWANetworkGenesis)
	}
	if len(genesisMetaHeader.GetValidatorStatsRootHash()) == 0 {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: validator-statistics root unavailable", errInvalidDRWANetworkGenesis)
	}

	headerBytes, err := marshalizer.Marshal(genesisMetaHeader)
	if err != nil {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: marshal final metachain header: %w", errInvalidDRWANetworkGenesis, err)
	}
	canonicalHashBytes := hasher.Compute(string(headerBytes))
	if len(canonicalHashBytes) != 32 {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: canonical hash length %d", errInvalidDRWANetworkGenesis, len(canonicalHashBytes))
	}
	canonicalHash := [32]byte{}
	copy(canonicalHash[:], canonicalHashBytes)
	networkDomain, err := drwa.DeriveNetworkDomain([]byte(chainID), canonicalHash)
	if err != nil {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("%w: derive domain: %w", errInvalidDRWANetworkGenesis, err)
	}

	return canonicalHash, networkDomain, headerBytes, nil
}

func resolveDRWANetworkDomain(
	chainID string,
	genesisBlocks map[uint32]data.HeaderHandler,
	canonicalEpoch uint32,
	bootstrapEpoch uint32,
	storageService dataRetriever.StorageService,
	marshalizer marshal.Marshalizer,
	hasher hashing.Hasher,
) ([32]byte, [32]byte, drwaNetworkIdentityProvenance, error) {
	if storageService == nil || storageService.IsInterfaceNil() {
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf("%w: nil storage service", errInvalidDRWANetworkIdentity)
	}

	key := drwaNetworkIdentityKey(canonicalEpoch)
	storedEnvelope, getErr := storageService.Get(dataRetriever.DRWANetworkIdentityUnit, key)
	switch {
	case getErr == nil:
		identity, err := decodeDRWANetworkIdentity(storedEnvelope, []byte(chainID))
		if err != nil {
			return [32]byte{}, [32]byte{}, 0, err
		}
		if identity.epoch != canonicalEpoch {
			return [32]byte{}, [32]byte{}, 0, fmt.Errorf(
				"%w: stored epoch %d, expected %d",
				errInvalidDRWANetworkIdentity,
				identity.epoch,
				canonicalEpoch,
			)
		}

		canonicalHash, networkDomain, err := deriveDRWANetworkDomainFromStoredHeader(
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
			if identity.provenance != drwaNetworkIdentityProvenanceLocalCanonicalGenesis {
				return [32]byte{}, [32]byte{}, 0, fmt.Errorf(
					"%w: fresh genesis cannot consume %s provenance",
					errInvalidDRWANetworkIdentity,
					identity.provenance.String(),
				)
			}
			_, _, candidateBytes, candidateErr := marshalAndDeriveDRWANetworkDomain(
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
					errInvalidDRWANetworkIdentity,
					candidateErr,
				)
			}
			if !bytes.Equal(candidateBytes, identity.headerBytes) {
				return [32]byte{}, [32]byte{}, 0, fmt.Errorf(
					"%w: local canonical genesis differs from retained identity",
					errInvalidDRWANetworkIdentity,
				)
			}
		}
		log.Info(formatDRWANetworkIdentityObservation(
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
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf("%w: read retained identity: %w", errInvalidDRWANetworkIdentity, getErr)
	}
	if bootstrapEpoch != canonicalEpoch {
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf(
			"%w: retained identity missing on restart at epoch %d for canonical epoch %d",
			errInvalidDRWANetworkIdentity,
			bootstrapEpoch,
			canonicalEpoch,
		)
	}

	canonicalHash, networkDomain, headerBytes, err := marshalAndDeriveDRWANetworkDomain(
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
			errInvalidDRWANetworkIdentity,
			err,
		)
	}

	identity := drwaNetworkIdentity{
		epoch:         canonicalEpoch,
		provenance:    drwaNetworkIdentityProvenanceLocalCanonicalGenesis,
		chainID:       []byte(chainID),
		canonicalHash: canonicalHash,
		networkDomain: networkDomain,
		headerBytes:   headerBytes,
	}
	envelope, err := encodeDRWANetworkIdentity(identity)
	if err != nil {
		return [32]byte{}, [32]byte{}, 0, err
	}
	err = storageService.Put(dataRetriever.DRWANetworkIdentityUnit, key, envelope)
	if err != nil {
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf("%w: persist local canonical genesis: %w", errInvalidDRWANetworkIdentity, err)
	}
	log.Info(formatDRWANetworkIdentityObservation(
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

func formatDRWANetworkIdentityObservation(
	canonicalEpoch uint32,
	bootstrapEpoch uint32,
	chainID []byte,
	key []byte,
	envelope []byte,
	canonicalHash [32]byte,
	networkDomain [32]byte,
	provenance drwaNetworkIdentityProvenance,
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

func deriveDRWANetworkDomainFromStoredHeader(
	chainID string,
	identity drwaNetworkIdentity,
	marshalizer marshal.Marshalizer,
	hasher hashing.Hasher,
) ([32]byte, [32]byte, error) {
	metaHeader := &block.MetaBlock{}
	err := marshalizer.Unmarshal(metaHeader, identity.headerBytes)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: unmarshal retained metachain header: %w", errInvalidDRWANetworkIdentity, err)
	}

	canonicalHash, networkDomain, remarshalBytes, err := marshalAndDeriveDRWANetworkDomain(
		chainID,
		map[uint32]data.HeaderHandler{core.MetachainShardId: metaHeader},
		identity.epoch,
		true,
		marshalizer,
		hasher,
	)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: validate retained metachain header: %w", errInvalidDRWANetworkIdentity, err)
	}
	if !bytes.Equal(remarshalBytes, identity.headerBytes) {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: retained metachain header is not canonical", errInvalidDRWANetworkIdentity)
	}
	if canonicalHash != identity.canonicalHash {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: retained canonical hash mismatch", errInvalidDRWANetworkIdentity)
	}
	if networkDomain != identity.networkDomain {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: retained network domain mismatch", errInvalidDRWANetworkIdentity)
	}

	return canonicalHash, networkDomain, nil
}

func drwaNetworkIdentityKey(epoch uint32) []byte {
	return networkidentity.Key(epoch)
}

func encodeDRWANetworkIdentity(identity drwaNetworkIdentity) ([]byte, error) {
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

func decodeDRWANetworkIdentity(envelope []byte, expectedChainID []byte) (drwaNetworkIdentity, error) {
	record, err := networkidentity.Decode(envelope, expectedChainID)
	if err != nil {
		return drwaNetworkIdentity{}, err
	}
	return drwaNetworkIdentity{
		epoch:         record.Epoch,
		provenance:    record.Provenance,
		chainID:       record.ChainID,
		canonicalHash: record.CanonicalHash,
		networkDomain: record.NetworkDomain,
		headerBytes:   record.HeaderBytes,
	}, nil
}
