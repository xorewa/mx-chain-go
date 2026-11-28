package drwa

import "bytes"

// privilegedFixedTargetIdentity is an owning-stage readback of the already
// authenticated, persisted action and target. It is not a storage or wire
// encoding. The owner of the action must supply the exact committed identity
// (including its plan digest), not reconstruct it from an incoming witness.
type privilegedFixedTargetIdentity struct {
	domain, token, program, target, actionID, planDigest []byte
}

// privilegedAdmissionSelection describes one independently selected admission
// instant. The selection is made from the owning stage's admitted native
// context, never by the account witness. Each admission calls the reader again;
// neither this value nor a successful read is a reusable authorization.
type privilegedAdmissionSelection struct {
	committedB, origin []byte
	consumer, producer uint32
	scope              PrivilegedConsentScope
}

// checkPrivilegedFixedTarget preserves the owner's exact action, target and
// plan across preparation, currentization and recovery. The selected identity
// comes from the stage's authenticated action context; the scope is the
// privilege binding required at that instant. Role/address bindings are
// authenticated separately by the exact consent reader. No completion,
// reachability, cancellation or resume is established by identity equality.
func checkPrivilegedFixedTarget(fixed, selected privilegedFixedTargetIdentity, scope PrivilegedConsentScope) error {
	for _, pair := range [][2][]byte{
		{fixed.domain, selected.domain}, {fixed.token, selected.token},
		{fixed.program, selected.program}, {fixed.target, selected.target},
		{fixed.actionID, selected.actionID}, {fixed.planDigest, selected.planDigest},
		{fixed.domain, scope.Domain}, {fixed.token, scope.Token},
		{fixed.program, scope.Program}, {fixed.target, scope.Target},
	} {
		if len(pair[0]) == 0 || !bytes.Equal(pair[0], pair[1]) {
			return ErrPrivilegedConsent
		}
	}
	return nil
}

// readFixedTargetCanonicalEvidence is the privileged-account component for the
// fixed-target lifecycle owner (SP2-52). It compares the persisted identity
// and the current admitted stage context before reading the exact native
// account facts. The caller must hold the original owning transition boundary
// and separately establish role/possession, approvals, selected root and
// reachability. Unavailable or unequal inputs cannot change the fixed target;
// a successful fresh read does not terminalize the action or clear ownership.
func (c *PrivilegedConsentCandidate) readFixedTargetCanonicalEvidence(r *canonicalResultReader,
	fixed, selected privilegedFixedTargetIdentity, instant privilegedAdmissionSelection,
	w canonicalResultWitness, eoaProof [][]byte, byteLimit int) error {
	if err := checkPrivilegedFixedTarget(fixed, selected, instant.scope); err != nil {
		return err
	}
	return c.readCanonicalEvidence(r, instant.committedB, instant.consumer, instant.producer,
		instant.origin, instant.scope, w, eoaProof, byteLimit)
}
