package processing

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"

	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

var errInvalidPrototypeNetworkGenesis = errors.New("invalid non-normative DRWA prototype network genesis")

func derivePrototypeNetworkDomain(
	chainID string,
	genesisBlocks map[uint32]data.HeaderHandler,
	marshalizer marshal.Marshalizer,
	hasher hashing.Hasher,
) ([32]byte, [32]byte, error) {
	if len(chainID) == 0 {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: empty chain ID", errInvalidPrototypeNetworkGenesis)
	}
	if marshalizer == nil || marshalizer.IsInterfaceNil() {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: nil marshalizer", errInvalidPrototypeNetworkGenesis)
	}
	if hasher == nil || hasher.IsInterfaceNil() {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: nil hasher", errInvalidPrototypeNetworkGenesis)
	}
	genesisHeader, exists := genesisBlocks[core.MetachainShardId]
	if !exists || genesisHeader == nil || genesisHeader.IsInterfaceNil() {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: missing metachain header", errInvalidPrototypeNetworkGenesis)
	}
	genesisMetaHeader, ok := genesisHeader.(data.MetaHeaderHandler)
	if !ok || genesisMetaHeader.IsInterfaceNil() {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: wrong metachain header type", errInvalidPrototypeNetworkGenesis)
	}
	if !bytes.Equal(genesisMetaHeader.GetChainID(), []byte(chainID)) {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: metachain header chain ID", errInvalidPrototypeNetworkGenesis)
	}
	if len(genesisMetaHeader.GetValidatorStatsRootHash()) == 0 {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: validator-statistics root unavailable", errInvalidPrototypeNetworkGenesis)
	}

	canonicalHashBytes, err := core.CalculateHash(marshalizer, hasher, genesisMetaHeader)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: hash final metachain header: %w", errInvalidPrototypeNetworkGenesis, err)
	}
	if len(canonicalHashBytes) != 32 {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: canonical hash length %d", errInvalidPrototypeNetworkGenesis, len(canonicalHashBytes))
	}
	canonicalHash := [32]byte{}
	copy(canonicalHash[:], canonicalHashBytes)
	networkDomain, err := drwaprototype.DeriveNetworkDomain([]byte(chainID), canonicalHash)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: derive domain: %w", errInvalidPrototypeNetworkGenesis, err)
	}

	return canonicalHash, networkDomain, nil
}
