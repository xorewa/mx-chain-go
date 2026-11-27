package drwa

import (
	"bytes"
	"errors"
	"fmt"

	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
)

var errInvalidAuthoritySignatures = errors.New("invalid DRWA authority signatures")

// minimumProgrammeAuthorityThreshold implements only the selected within-set
// floor (Part A L1172-1189). It applies neither to native transaction signatures
// nor to technical-root constitutions. The quotient/remainder form avoids 3*n
// overflowing even when n is the largest uint64; it selects no roster bound.
func minimumProgrammeAuthorityThreshold(n uint64) (uint64, error) {
	if n < 5 {
		return 0, errInvalidAuthoritySignatures
	}
	return (n/5)*3 + ((n%5)*3+4)/5, nil
}

// validateProgrammeAuthorityThreshold also applies when a roster is first
// referenced, before a separate possession proof is presented (Part A L1189).
func validateProgrammeAuthorityThreshold(n, threshold uint64) error {
	minimum, err := minimumProgrammeAuthorityThreshold(n)
	if err != nil {
		return err
	}
	if threshold < minimum || threshold > n {
		return errInvalidAuthoritySignatures
	}
	return nil
}

// verifyProgrammeAuthoritySignatures is an unwired construction candidate for
// the ordered Ed25519 check in Part A L1129-1131/L1167-1189. It reuses the exact
// native key generator and signer (node 06c383cf factory/crypto/cryptoComponents.go
// L166-167; crypto-go v1.3.3 signing/key.go L71-87 and singlesig/ed25519.go).
// No disabled/injected signer or validator BLS verifier is accepted.
//
// A successful result proves signatures over the supplied bounded digest only.
// It does not establish lawful roster enrollment, purpose, domain, current set
// version, independent role pairs, mandatory members, successor eligibility,
// appointment, withdrawal, replay, certificate time or business authorization.
// The eventual native ingress must derive the canonical digest and exact roster
// from its separately qualified authority/codec construction. In particular,
// caller-supplied keys are never a lawful authority source. The bounded A38
// construction reuses this check; no native transaction route or default
// authority producer is installed by that construction.
// Both bounds must come from the owning admitted profile before production use.
func verifyProgrammeAuthoritySignatures(
	scheme string,
	threshold uint64,
	members [][]byte,
	signerIndices []uint64,
	signatures [][]byte,
	digest []byte,
	maxMembers uint64,
	maxDigestBytes uint64,
) error {
	if scheme != "ED25519_M_OF_N" {
		return errInvalidAuthoritySignatures
	}
	n := uint64(len(members))
	if n > maxMembers {
		return errInvalidAuthoritySignatures
	}
	if err := validateProgrammeAuthorityThreshold(n, threshold); err != nil {
		return err
	}
	if len(digest) == 0 || uint64(len(digest)) > maxDigestBytes {
		return errInvalidAuthoritySignatures
	}
	if len(signerIndices) != len(signatures) || uint64(len(signatures)) < threshold {
		return errInvalidAuthoritySignatures
	}

	publicKeys, err := programmeAuthorityPublicKeys(members)
	if err != nil {
		return err
	}

	signer := &singlesig.Ed25519Signer{}
	for i, index := range signerIndices {
		if index >= n || (i > 0 && index <= signerIndices[i-1]) {
			return errInvalidAuthoritySignatures
		}
		// Verify every supplied signature, including any beyond the threshold.
		// Native Verify owns signature length, key and cryptographic rejection.
		// Strictly increasing in-roster indices bound verification to n calls;
		// an oversized signature list reaches rejection before an (n+1)th call.
		if err = signer.Verify(publicKeys[index], digest, signatures[i]); err != nil {
			return fmt.Errorf("%w: %w", errInvalidAuthoritySignatures, err)
		}
	}
	return nil
}

// Callers bound roster cardinality and byte lengths before this native parsing.
// Parsing establishes key representation, never appointment or possession.
func programmeAuthorityPublicKeys(members [][]byte) ([]crypto.PublicKey, error) {
	keygen := signing.NewKeyGenerator(ed25519.NewEd25519())
	seen := make(map[string]struct{}, len(members))
	publicKeys := make([]crypto.PublicKey, len(members))
	for i, member := range members {
		if _, exists := seen[string(member)]; exists {
			return nil, errInvalidAuthoritySignatures
		}
		seen[string(member)] = struct{}{}
		key, err := keygen.PublicKeyFromByteArray(member)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errInvalidAuthoritySignatures, err)
		}
		publicKeys[i] = key
	}
	return publicKeys, nil
}

// validateProgrammeAuthorityIndependentPair checks only the distinct-set and
// disjoint-full-roster requirement in Part A L1180-1187/L1335-1336. Both rosters
// and stable IDs must already have been resolved from the lawful constitution;
// neither requester-provided material nor separation itself appoints a role.
// Roster bounds, native key parsing, within-set uniqueness, thresholds and every
// supplied signature remain separate verifyProgrammeAuthoritySignatures checks.
// This read-only primitive selects no purpose, pair, fallback, codec or authority
// version. A new version of the same stable set cannot fill an independent slot.
func validateProgrammeAuthorityIndependentPair(leftID, rightID []byte, leftMembers, rightMembers [][]byte) error {
	if len(leftID) == 0 || len(rightID) == 0 || bytes.Equal(leftID, rightID) ||
		len(leftMembers) == 0 || len(rightMembers) == 0 {
		return errInvalidAuthoritySignatures
	}
	for _, member := range leftMembers {
		if len(member) == 0 {
			return errInvalidAuthoritySignatures
		}
	}
	for _, member := range rightMembers {
		if len(member) == 0 {
			return errInvalidAuthoritySignatures
		}
	}
	for _, left := range leftMembers {
		for _, right := range rightMembers {
			if bytes.Equal(left, right) {
				return errInvalidAuthoritySignatures
			}
		}
	}
	return nil
}
