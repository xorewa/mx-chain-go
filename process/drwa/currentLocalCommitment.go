package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/core/check"
)

// currentLocalCommitmentHost belongs to the same admitted complete CEB
// decoder as currentLocalHost. The commitment is over the complete references
// actually resolved and hash-checked by that reader, never a caller-selected
// subset or an asserted readiness bit. No commitment format is selected here.
type currentLocalCommitmentHost interface {
	currentLocalHost
	DependencyCommitment(body []byte, references []currentLocalReference) ([]byte, error)
}

// verifyDependencyCommitment checks the expected commitment from an already
// authenticated current-CEB consumer's transition context. It is read-only;
// its caller must hold the same native owner and revalidate before writing.
func (r *currentLocalDependencies) verifyDependencyCommitment(view *currentLocalView, expected []byte) error {
	if r == nil || r.codec == nil || check.IfNil(r.codec.hasher) || view == nil || view.owner != r ||
		len(expected) == 0 || len(expected) != r.codec.hasher.Size() {
		return errCurrentLocalDependency
	}
	host, ok := r.host.(currentLocalCommitmentHost)
	if !ok || check.IfNil(host) || len(view.references) == 0 {
		return errCurrentLocalDependency
	}
	refs := make([]currentLocalReference, len(view.references))
	for i, ref := range view.references {
		refs[i] = cloneCurrentLocalReference(ref)
	}
	actual, err := host.DependencyCommitment(bytes.Clone(view.body), refs)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return errCurrentLocalDependency
	}
	return r.unchanged(view)
}
