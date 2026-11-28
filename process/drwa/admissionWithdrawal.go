package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
)

// SP2-31, F04 (Part A E.8, L2390-2396, L2411): authorised withdrawal of an
// exact issuer/programme admission decision, and its effect on every later
// covered registration and activation.
//
// Effectivity is the permanent withdrawal record of the exact decision in the
// metachain state the covered transition executes against. Execution order
// decides; a covered action that completed before it is not touched; a removed
// block removes its withdrawal together with everything that executed after
// it. No status is cached and no expiry substitutes for the record.

// admissionDecisionStatus is what one state holds about one exact decision.
type admissionDecisionStatus string

const (
	admissionDecisionAbsent    admissionDecisionStatus = "ABSENT"
	admissionDecisionAdmitted  admissionDecisionStatus = "ADMITTED"
	admissionDecisionWithdrawn admissionDecisionStatus = "WITHDRAWN"
)

// admissionWithdrawalOutcome is what one executed withdrawal did. A refused
// attempt returns an error and admissionWithdrawalRefused; it wrote nothing.
type admissionWithdrawalOutcome int

const (
	admissionWithdrawalRefused admissionWithdrawalOutcome = iota
	admissionWithdrawalEffective
	admissionWithdrawalAlreadyEffective
)

// decisionStatus reads the status of exactly this decision (scope, issuer,
// version and complete body) from the executing state. A stored decision or
// withdrawal record with other bytes under the same identity is an error, not
// a status. It is a read: an observer that reports it as final must itself
// know that the state it read is canonically final.
func (s *scopedAdmissionRecords) decisionStatus(d scopedAdmissionDecision) (admissionDecisionStatus, error) {
	status, _, err := s.decisionState(d)
	return status, err
}

// decisionState is decisionStatus together with the decision identity.
func (s *scopedAdmissionRecords) decisionState(d scopedAdmissionDecision) (admissionDecisionStatus, []byte, error) {
	scope, body, err := s.decisionBody(d)
	if err != nil {
		return "", nil, err
	}
	id, err := s.decisionID(scope, d)
	if err != nil {
		return "", nil, err
	}
	account, err := s.codec.state.systemAccount()
	if err != nil {
		return "", nil, err
	}
	stored, _, err := account.RetrieveValue(s.key("decision", id))
	if err != nil {
		return "", nil, err
	}
	withdrawn, _, err := account.RetrieveValue(s.key("withdrawn", id))
	if err != nil {
		return "", nil, err
	}
	switch {
	case len(stored) == 0 && len(withdrawn) == 0:
		return admissionDecisionAbsent, id, nil
	case !bytes.Equal(stored, body) || (len(withdrawn) != 0 && !bytes.Equal(withdrawn, body)):
		return "", nil, errScopedAdmission
	case len(withdrawn) != 0:
		return admissionDecisionWithdrawn, id, nil
	}
	return admissionDecisionAdmitted, id, nil
}

// scopedWithdrawalAuthority holds what the scoped authority check of a
// withdrawal needs: the same evaluated-header source as the records, the
// certificate codec, the trusted reader of the programme's authority view and
// the profile limits. The reader is supplied by the row that builds the
// canonical authority reader; none is built in.
type scopedWithdrawalAuthority struct {
	codec  *registrationRecords
	reader scopedAuthorityReader
	limits scopedAuthorityLimits
}

// scopedWithdrawalMandate authorises exactly one withdrawal through the
// adopted row P04: the programme's current admission authority signs the
// withdrawal certificate over the canonical decision identity. The certificate
// payload is the records' own withdrawal digest (scope, decision identity,
// decision body and current scope head), so a certificate made under another
// head, for another decision or for another body never verifies.
type scopedWithdrawalMandate struct {
	source     HeaderTimeSource
	authority  scopedWithdrawalAuthority
	domain, id []byte
	issuer     []byte
	proofs     []scopedAuthorityProof
}

func (m *scopedWithdrawalMandate) IsInterfaceNil() bool { return m == nil }

func (m *scopedWithdrawalMandate) Verify(purpose string, scope, _, digest, _ []byte) error {
	if purpose != "WITHDRAW" {
		return errScopedAdmission
	}
	request := scopedAuthorityRequest{use: scopedAdmissionWithdrawal, phase: scopedDirect, locus: core.MetachainShardId,
		targetShard: core.MetachainShardId, domain: bytes.Clone(m.domain), scope: bytes.Clone(scope), subject: bytes.Clone(m.id),
		action: bytes.Clone(m.id), owner: bytes.Clone(m.issuer), digest: bytes.Clone(digest)}
	return verifyScopedAuthority(m.source, m.authority.codec, m.authority.reader, request, m.proofs, m.authority.limits)
}

// withdrawAuthorized is the withdrawal operation: it verifies the certificates
// through the scoped authority check and then runs the records' withdrawal in
// the caller's journal. It reports whether this execution made the withdrawal
// effective or found it effective already; an exact repeat writes nothing. It
// withdraws one decision of one issuer in one programme scope and nothing else.
func (s *scopedAdmissionRecords) withdrawAuthorized(context *HeaderTimeContext, d scopedAdmissionDecision,
	proofs []scopedAuthorityProof, authority scopedWithdrawalAuthority) (admissionWithdrawalOutcome, error) {
	if s == nil || s.codec == nil || authority.codec == nil || check.IfNil(authority.reader) || check.IfNil(s.timeSource) {
		return admissionWithdrawalRefused, errScopedAdmission
	}
	before, id, err := s.decisionState(d)
	if err != nil {
		return admissionWithdrawalRefused, err
	}
	if before == admissionDecisionAbsent {
		return admissionWithdrawalRefused, errScopedAdmission
	}
	mandate := &scopedWithdrawalMandate{source: s.timeSource, authority: authority, domain: s.domain, id: id, issuer: d.issuer, proofs: proofs}
	local := *s
	local.mandates = mandate
	if err = local.withdraw(context, d, id); err != nil {
		return admissionWithdrawalRefused, err
	}
	if before == admissionDecisionWithdrawn {
		return admissionWithdrawalAlreadyEffective, nil
	}
	return admissionWithdrawalEffective, nil
}

// admissionConsumption binds the covered transitions of one registration
// owner to the scoped admission records of the same store.
type admissionConsumption struct {
	records   *scopedAdmissionRecords
	approvals *registrationApprovalCodec
	owner     []byte
	role      []byte
}

// WithAdmissionWithdrawal binds the F04 consumption check to this registration
// owner: registration and activation of its intent then require the
// intent-bound admission decision to be current, unexpired, stored and not
// withdrawn in the executing state, before any other verifier runs and before
// any write. owner is the programme scope owner and admissionRole the role of
// the admission authority, both from the native subject, never from the
// transaction. The native ingress of SP2-38 must call it once per owner.
func (a *RegistrationAdmission) WithAdmissionWithdrawal(records *scopedAdmissionRecords, approvals *registrationApprovalCodec,
	owner, admissionRole []byte) error {
	if a == nil || a.owner == nil || a.owner.records == nil || a.admission != nil || records == nil || records.codec == nil ||
		approvals == nil || approvals.source == nil || approvals.source.state == nil || a.owner.records.state == nil ||
		records.codec.state == nil || records.codec.state.accounts != a.owner.records.state.accounts ||
		approvals.source.state.accounts != a.owner.records.state.accounts || !bytes.Equal(records.domain, a.domain) ||
		len(owner) != len(core.SystemAccountAddress) || len(admissionRole) == 0 {
		return errInvalidRegistrationRecord
	}
	a.admission = &admissionConsumption{records: records, approvals: approvals, owner: bytes.Clone(owner), role: bytes.Clone(admissionRole)}
	return nil
}

// coveredAdmission is the consumption check of a covered transition. Without
// a binding it checks nothing: the owner then relies on its external verifier,
// as before this row.
func (a *RegistrationAdmission) coveredAdmission(context *HeaderTimeContext, intent bootstrapIntentBody) error {
	if a.admission == nil {
		return nil
	}
	return a.admission.approvals.intentAdmission(a.admission.records, context, intent, a.admission.owner, a.admission.role)
}

// intentAdmission checks the admission decision embedded in an intent exactly
// as bootstrap-intent retention does: the decision is decoded against the
// native scope, the programme's current REGISTER_TOKEN_ADMISSION head is read,
// and the stored decision must be that head's, unexpired at the evaluated
// header time and not withdrawn.
func (c *registrationApprovalCodec) intentAdmission(records *scopedAdmissionRecords, context *HeaderTimeContext,
	intent bootstrapIntentBody, owner, admissionRole []byte) error {
	d, scope, err := c.decodeBootstrapAdmissionDecision(records, intent, owner)
	if err != nil {
		return err
	}
	bodies, err := newAuthorityBodyCodec(c.source, authorityBodyBounds{c.bounds.bytes, c.bounds.fieldBytes, c.bounds.roleBytes, c.bounds.maxMembers})
	if err != nil {
		return err
	}
	_, reference, err := records.readAuthorityPurposeHead(context, d.owner, d.program, registrationAdmissionPurpose, admissionRole, bodies)
	if err != nil {
		return err
	}
	head := scopedAdmissionCurrentHead{context: context, accounts: c.source.state.accounts, scope: scope, version: reference}
	return records.checkDecisionAt(context, d, &head)
}
