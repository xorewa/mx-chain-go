package common

import (
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/hashing"
)

var errInvalidDRWANetworkDomain = errors.New("invalid DRWA network domain inputs")

// ComputeDRWANetworkDomain computes the DRWA-defined drwa_network_domain from
// Part A 2.6: H("DRWA/NETWORK/v1" || chain_id || canonical_genesis_block_hash).
// The caller must supply the canonical METACHAIN genesis hash under the selected
// native hasher, after genesis is fixed. This computation does not authenticate
// that source, persist an identity, admit configuration or authorize startup.
// AM-001 still requires a trusted synchronous non-pruned identity/recovery path.
// No domain is stored as a genesis-state input. There is no ordinary-path caller.
func ComputeDRWANetworkDomain(chainID, canonicalMetachainGenesisHash []byte, hasher hashing.Hasher) ([]byte, error) {
	if check.IfNil(hasher) {
		return nil, core.ErrNilHasher
	}
	if len(chainID) == 0 || hasher.Size() <= 0 || len(canonicalMetachainGenesisHash) != hasher.Size() {
		return nil, errInvalidDRWANetworkDomain
	}
	preimage := append([]byte("DRWA/NETWORK/v1"), chainID...)
	preimage = append(preimage, canonicalMetachainGenesisHash...)
	return hasher.Compute(string(preimage)), nil
}
