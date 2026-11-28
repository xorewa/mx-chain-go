package drwa

import "github.com/multiversx/mx-chain-core-go/core"

// readCanonicalEvidence composes the T12 experimental consent observation
// with the SP2-22 canonical result reader. The native admission owner selects
// committedB, origin and the account's owning producer shard at the consuming
// instant, using the admitted epoch's shard mapping. Witness coordinates are
// never a substitute for that selection. All witness bytes share one bound.
// This is not a key-possession proof, an approval, or an admission-stage owner;
// the caller must establish each of those prerequisites independently.
func (c *PrivilegedConsentCandidate) readCanonicalEvidence(r *canonicalResultReader,
	committedB []byte, consumer, producer uint32, origin []byte,
	expected PrivilegedConsentScope, w canonicalResultWitness, eoaProof [][]byte, byteLimit int) error {
	if c == nil || r == nil || producer == core.MetachainShardId {
		return ErrPrivilegedConsent
	}
	remaining, err := canonicalWitnessRemaining(w, byteLimit)
	if err != nil {
		return err
	}
	for _, node := range eoaProof {
		if len(node) == 0 || len(node) > remaining {
			return ErrInvalidAccountWitness
		}
		remaining -= len(node)
	}
	projection, err := r.readBoundedContext(committedB, consumer, producer, origin, w)
	if err != nil {
		return err
	}
	return c.ReadEvidence(r.accounts, projection.carryingHash, producer, expected,
		PrivilegedConsentWitness{AccountItemWitness: w.Account, EOAProof: eoaProof}, byteLimit)
}
