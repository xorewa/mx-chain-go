package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
)

// ReadEvidence authenticates the exact consent tuple and actual no-code/nonce
// account facts in the caller-selected owning-shard result, using T06 unchanged.
// committedH and producingShard MUST come from an admitted canonical route, not
// from the witness. This method establishes no finality, cross-shard fence,
// possession signature, programme approval, CEB readiness or stage acceptance.
// Call it separately at every required instant (A L2637-2643; ledger L29).
// Unchanged key possession does not bypass this suitability/action observation.
// It neither reads remote execution state nor checks guardian presence.
// Generic nonce/epoch equality is an EXPERIMENTAL conservative freshness rule:
// any intervening native transaction or epoch advancement requires new consent.
// Historical H cannot establish a later instant whose selected H differs.
func (c *PrivilegedConsentCandidate) ReadEvidence(r *ResultAccountReader,
	committedH []byte, producingShard uint32, expected PrivilegedConsentScope,
	w AccountItemWitness, proofByteLimit int) error {
	if r == nil || producingShard == core.MetachainShardId || !c.validAddress(expected.Address) {
		return ErrPrivilegedConsent
	}
	fields := [][]byte{expected.Domain, expected.Token, expected.Program, expected.Target, expected.Roles, expected.Address}
	for _, field := range fields {
		if len(field) == 0 || len(field) > c.maxFieldBytes {
			return ErrPrivilegedConsent
		}
	}
	if !bytes.Equal(expected.Domain, c.domain) {
		return ErrPrivilegedConsent
	}
	value, err := r.Read(committedH, producingShard, expected.Address,
		bytes.Clone(experimentalPrivilegedConsentKey), w, proofByteLimit)
	if err != nil {
		return err
	}
	// T06 already authenticated account/item membership. Reuse its proof cache
	// and native account factory to inspect the same root's account facts; do not
	// introduce a second account/proof decoder or change T06's byte-reader API.
	r.mut.Lock()
	defer r.mut.Unlock()
	root, err := r.executionRoot(producingShard, w)
	if err != nil {
		return err
	}
	tr, err := r.proofTrie.Recreate(holders.NewDefaultRootHashesHolder(root))
	if err != nil {
		return err
	}
	raw, _, err := tr.Get(expected.Address)
	if err != nil {
		return err
	}
	account, err := r.accountFactory.CreateAccount(expected.Address)
	if err != nil {
		return err
	}
	user, ok := account.(state.UserAccountHandler)
	if !ok || r.args.Marshaller.Unmarshal(user, raw) != nil || len(user.GetCodeHash()) != 0 {
		return ErrPrivilegedConsent
	}
	s := &block.HeaderV3{}
	if r.args.Marshaller.Unmarshal(s, w.ExecutedHeader) != nil {
		return ErrPrivilegedConsent
	}
	if !bytes.Equal(value, encodeExperimentalConsent(expected, user.GetNonce(), s.Epoch)) {
		return ErrPrivilegedConsent
	}
	return nil
}
