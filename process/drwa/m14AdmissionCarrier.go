package drwa

import (
	"bytes"
	"encoding/binary"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/state"
)

const (
	m14AdmissionIssuePurpose    = "PROGRAMME_ADMISSION_ISSUE"
	m14AdmissionWithdrawPurpose = "PROGRAMME_ADMISSION_WITHDRAW"
	m14AdmissionIssueTag        = "DRWA/PROGRAMME_ADMISSION_ISSUE/candidate1"
	m14AdmissionWithdrawTag     = "DRWA/PROGRAMME_ADMISSION_WITHDRAW/candidate1"
)

// The native owner must supply these exact authenticated coordinates and the
// resolved B9 of the current REGISTER_TOKEN_ADMISSION purpose head.
type m14AdmissionSubject struct {
	owner, programme, issuer, currentReference []byte
	current                                    *authorityBody
	at                                         HeaderMilliseconds
}

// This is scoped, signed carrier data, not an admission, withdrawal mandate,
// proof of lawful succession, or authority to write either protected row.
type m14AdmissionCarrier struct {
	decision                  scopedAdmissionDecision
	decisionID, body, message []byte
	signerIndices             []uint64
}

func (c *registrationApprovalCodec) verifyM14AdmissionCarrier(records *scopedAdmissionRecords,
	purpose string, subject m14AdmissionSubject, raw []byte) (*m14AdmissionCarrier, error) {
	var tag string
	switch purpose {
	case m14AdmissionIssuePurpose:
		tag = m14AdmissionIssueTag
	case m14AdmissionWithdrawPurpose:
		tag = m14AdmissionWithdrawTag
	default:
		return nil, errScopedAdmission
	}
	if !c.ownsBootstrapProofRecords(records) || subject.current == nil ||
		len(subject.currentReference) != c.codec.hasher.Size() || len(records.domain) > c.bounds.fieldBytes ||
		len(subject.programme) == 0 || len(subject.programme) > c.bounds.fieldBytes {
		return nil, errScopedAdmission
	}
	carrier, err := c.fields(raw, 2, c.bounds.bytes)
	if err != nil {
		return nil, err
	}
	envelope, err := c.fields(carrier[1], 3, c.bounds.bytes)
	if err != nil {
		return nil, err
	}
	m, err := c.fields(envelope[0], 14, c.bounds.bytes)
	if err != nil {
		return nil, err
	}
	d, scope, err := c.decodeScopedAdmissionDecision(records, carrier[0], subject.owner, subject.programme, subject.issuer)
	if err != nil {
		return nil, err
	}
	id, err := records.decisionID(scope, d)
	if err != nil {
		return nil, err
	}
	current := subject.current
	if len(id) != c.codec.hasher.Size() || !bytes.Equal(current.owner, subject.owner) ||
		!bytes.Equal(current.programme, subject.programme) || len(current.role) == 0 || len(current.role) > c.bounds.roleBytes ||
		len(current.id) == 0 || len(current.id) > c.bounds.fieldBytes || len(current.version) != 8 ||
		len(current.hash) != c.codec.hasher.Size() || len(m[12]) != 8 || len(m[13]) != 8 {
		return nil, errScopedAdmission
	}
	nb, na := binary.BigEndian.Uint64(m[12]), binary.BigEndian.Uint64(m[13])
	if nb > uint64(subject.at) || uint64(subject.at) > na || na-nb > c.bounds.maxValidity ||
		(purpose == m14AdmissionIssuePurpose && (na > uint64(d.validUntil) || !bytes.Equal(d.authority, subject.currentReference))) {
		return nil, errScopedAdmission
	}
	message, err := c.codec.frame([]byte(tag), records.domain, []byte(purpose), scope, d.issuer,
		id, carrier[0], subject.currentReference, current.role, current.id, current.version, current.hash, m[12], m[13])
	if err != nil || !bytes.Equal(envelope[0], message) {
		return nil, errScopedAdmission
	}
	indices, err := c.verifyAuthorityEnvelopeSignatures(envelope, current)
	if err != nil {
		return nil, err
	}
	return &m14AdmissionCarrier{decision: d, decisionID: bytes.Clone(id), body: carrier[0], message: message, signerIndices: indices}, nil
}

// m14AdmissionPredecessor describes the candidate-local record state and its
// corresponding action. The original operation still owns authority, any
// write and the budget. None of these outcomes establishes canonical effect.
type m14AdmissionPredecessor uint8

const (
	m14AdmissionDenied m14AdmissionPredecessor = iota
	m14AdmissionNewPositive
	m14AdmissionNewTombstone
	m14AdmissionAlreadyRecorded
	m14AdmissionAlreadyWithdrawn
)

// classifyM14AdmissionPredecessor reads the exact D6 keys from the original
// operation's system account. Callers must first verify the carrier, current
// head, mandate and proof window; this read cannot substitute for those gates.
func (s *scopedAdmissionRecords) classifyM14AdmissionPredecessor(account state.UserAccountHandler,
	purpose string, carrier *m14AdmissionCarrier) (m14AdmissionPredecessor, error) {
	if s == nil || s.codec == nil || check.IfNil(account) || carrier == nil ||
		len(carrier.decisionID) != s.codec.hasher.Size() || len(carrier.body) == 0 || len(carrier.body) > s.limits.recordBytes ||
		(purpose != m14AdmissionIssuePurpose && purpose != m14AdmissionWithdrawPurpose) {
		return m14AdmissionDenied, errScopedAdmission
	}

	positive, _, err := account.RetrieveValue(s.key("decision", carrier.decisionID))
	if err != nil {
		return m14AdmissionDenied, err
	}
	hasPositive := len(positive) != 0
	if hasPositive && !bytes.Equal(positive, carrier.body) {
		return m14AdmissionDenied, errScopedAdmission
	}
	tombstone, _, err := account.RetrieveValue(s.key("withdrawn", carrier.decisionID))
	if err != nil {
		return m14AdmissionDenied, err
	}
	if len(tombstone) != 0 {
		if purpose == m14AdmissionWithdrawPurpose && hasPositive && bytes.Equal(tombstone, carrier.body) {
			return m14AdmissionAlreadyWithdrawn, nil
		}
		return m14AdmissionDenied, errScopedAdmission
	}
	if purpose == m14AdmissionIssuePurpose {
		if hasPositive {
			return m14AdmissionAlreadyRecorded, nil
		}
		return m14AdmissionNewPositive, nil
	}
	if hasPositive {
		return m14AdmissionNewTombstone, nil
	}
	return m14AdmissionDenied, errScopedAdmission
}
