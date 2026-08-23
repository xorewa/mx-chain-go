package drwaprototype

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B
//
// SHA-256 and the fixed canonical-genesis-hash width in this file are S1 prototype choices.

const prototypeNetworkDomainPrefix = "DRWA/NETWORK/v1"

// ErrInvalidNetworkDomainInput signals an invalid S1 prototype network-domain input.
var ErrInvalidNetworkDomainInput = errors.New("invalid non-normative DRWA prototype network-domain input")

// DeriveNetworkDomain returns the replaceable S1 derivation of the frozen architecture §2.6
// network domain. The caller remains responsible for supplying the actual canonical genesis hash.
func DeriveNetworkDomain(
	chainID []byte,
	canonicalGenesisBlockHash [prototypeDigestLength]byte,
) ([prototypeDigestLength]byte, error) {
	if len(chainID) == 0 {
		return [prototypeDigestLength]byte{}, fmt.Errorf("%w: empty chain identifier", ErrInvalidNetworkDomainInput)
	}

	hasher := sha256.New()
	_, _ = hasher.Write([]byte(prototypeNetworkDomainPrefix))
	_, _ = hasher.Write(chainID)
	_, _ = hasher.Write(canonicalGenesisBlockHash[:])
	digest := [prototypeDigestLength]byte{}
	copy(digest[:], hasher.Sum(nil))

	return digest, nil
}
