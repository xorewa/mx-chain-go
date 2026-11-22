package drwa

import (
	"bytes"
	"encoding/binary"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// Owner-selected bounded construction; no released format or native admission.
const authorityBodyTag = "DRWA/AUTHORITY_SET_VERSION/candidate1"
const authorityBodyHashTag = "DRWA/AUTHORITY_SET_VERSION_HASH/candidate1"
const initialAppointmentTag = "DRWA/INITIAL_PROGRAMME_APPOINTMENT/candidate1"

type authorityBodyBounds struct{ bytes, fieldBytes, roleBytes, maxMembers int }
type authorityBodyCodec struct {
	source *registrationRecords
	codec  *registrationRecords
	bounds authorityBodyBounds
}

// This is decoded DATA, never an appointment/lineage capability. All fields and
// keys derive from the same body. No RegistrationVerifier or ingress uses it.
type authorityBody struct {
	raw, hash, id, version, role, owner, programme []byte
	predecessorVersion, predecessorHash            []byte
	threshold                                      uint64
	members                                        [][]byte
}
type initialAppointment struct {
	owner, programme, commitment []byte
	admission, independent       *authorityBody
}

func newAuthorityBodyCodec(records *registrationRecords, b authorityBodyBounds) (*authorityBodyCodec, error) {
	if records == nil || check.IfNil(records.marshaller) || check.IfNil(records.hasher) || records.hasher.Size() <= 0 ||
		b.bytes <= 0 || b.bytes > records.maxBytes || b.fieldBytes < records.hasher.Size() || b.fieldBytes > b.bytes ||
		b.roleBytes <= 0 || b.roleBytes > b.fieldBytes || b.maxMembers < 5 || b.maxMembers > b.bytes/2 {
		return nil, errInvalidRegistrationRecord
	}
	local := *records
	local.maxBytes = b.bytes
	return &authorityBodyCodec{source: records, codec: &local, bounds: b}, nil
}

func (c *authorityBodyCodec) fields(raw []byte, count, leaf int) ([][]byte, error) {
	return registrationBoundedFields(c.codec, raw, count, count, leaf)
}

func (c *authorityBodyCodec) decode(raw []byte) (*authorityBody, error) {
	f, err := c.fields(raw, 9, c.bounds.bytes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(f[0], []byte(authorityBodyTag)) || len(f[1]) == 0 || len(f[1]) > c.bounds.fieldBytes ||
		len(f[2]) != 8 || !bytes.Equal(f[3], []byte("ED25519_M_OF_N")) || len(f[4]) != 8 ||
		(len(f[7]) == 0) != (len(f[8]) == 0) ||
		(len(f[7]) != 0 && (len(f[7]) != 8 || len(f[8]) != c.codec.hasher.Size())) {
		return nil, errInvalidRegistrationRecord
	}
	scope, err := c.fields(f[6], 3, c.bounds.fieldBytes)
	if err != nil || len(scope[0]) == 0 || len(scope[0]) > c.bounds.roleBytes ||
		len(scope[1]) != len(core.SystemAccountAddress) || len(scope[2]) == 0 {
		return nil, errInvalidRegistrationRecord
	}
	members, err := registrationBoundedFields(c.codec, f[5], 5, c.bounds.maxMembers, c.bounds.fieldBytes)
	if err != nil {
		return nil, err
	}
	threshold := binary.BigEndian.Uint64(f[4])
	if validateProgrammeAuthorityThreshold(uint64(len(members)), threshold) != nil {
		return nil, errInvalidRegistrationRecord
	}
	if _, err = programmeAuthorityPublicKeys(members); err != nil {
		return nil, err
	}
	preimage, err := c.codec.frame([]byte(authorityBodyHashTag), raw)
	if err != nil {
		return nil, err
	}
	digest := c.codec.hasher.Compute(string(preimage))
	if len(digest) != c.codec.hasher.Size() {
		return nil, errInvalidRegistrationRecord
	}
	return &authorityBody{raw: bytes.Clone(raw), hash: bytes.Clone(digest), id: f[1], version: f[2], threshold: threshold,
		members: members, role: scope[0], owner: scope[1], programme: scope[2], predecessorVersion: f[7], predecessorHash: f[8]}, nil
}

// selectIntentPA checks data from the ORIGINAL intent, not installed PA state.
// Caller still needs canonical-final intent authentication and the separate PA
// possession proof. Unsupported historical bodies deny; none are skipped.
func (c *authorityBodyCodec) selectIntentPA(intent bootstrapIntentBody, owner, programme []byte) (*authorityBody, error) {
	if len(intent.proposedProgramAuthoritySetBodies) == 0 ||
		len(intent.proposedProgramAuthoritySetBodies) != len(intent.proposedProgramAuthoritySetHashes) {
		return nil, errInvalidRegistrationRecord
	}
	// Set-list bounds belong to the original intent grammar, not roster size.
	// Existing frame checks total bytes before invoking the native allocator.
	if _, err := c.codec.authorityList(intent.proposedProgramAuthoritySetBodies); err != nil {
		return nil, err
	}
	if _, err := c.codec.authorityList(intent.proposedProgramAuthoritySetHashes); err != nil {
		return nil, err
	}
	var selected *authorityBody
	for i, raw := range intent.proposedProgramAuthoritySetBodies {
		body, err := c.decode(raw)
		if err != nil || !bytes.Equal(body.hash, intent.proposedProgramAuthoritySetHashes[i]) {
			return nil, errInvalidRegistrationRecord
		}
		if bytes.Equal(body.role, []byte(registrationPARole)) {
			if selected != nil || !bytes.Equal(body.owner, owner) || !bytes.Equal(body.programme, programme) {
				return nil, errInvalidRegistrationRecord
			}
			selected = body
		}
	}
	if selected == nil {
		return nil, errInvalidRegistrationRecord
	}
	return selected, nil
}

// G6 only parses initial appointment DATA. A hash, portal session or successful
// parse is not native genesis authorization; no loader/installer is supplied.
func (c *authorityBodyCodec) decodeInitial(raw, admissionRole, independentRole []byte) (*initialAppointment, error) {
	f, err := c.fields(raw, 6, c.bounds.bytes)
	if err != nil || !bytes.Equal(f[0], []byte(initialAppointmentTag)) || len(f[1]) != len(core.SystemAccountAddress) ||
		len(f[2]) == 0 || len(f[2]) > c.bounds.fieldBytes || len(f[5]) != c.codec.hasher.Size() ||
		len(admissionRole) == 0 || len(independentRole) == 0 {
		return nil, errInvalidRegistrationRecord
	}
	a, err := c.decode(f[3])
	if err != nil {
		return nil, err
	}
	i, err := c.decode(f[4])
	if err != nil {
		return nil, err
	}
	for j, body := range []*authorityBody{a, i} {
		role := admissionRole
		if j == 1 {
			role = independentRole
		}
		if !bytes.Equal(body.role, role) || !bytes.Equal(body.owner, f[1]) || !bytes.Equal(body.programme, f[2]) ||
			len(body.predecessorVersion) != 0 || body.threshold != 3 || len(body.members) != 5 {
			return nil, errInvalidRegistrationRecord
		}
	}
	if bytes.Equal(a.id, i.id) {
		return nil, errInvalidRegistrationRecord
	}
	for _, ak := range a.members {
		for _, ik := range i.members {
			if bytes.Equal(ak, ik) {
				return nil, errInvalidRegistrationRecord
			}
		}
	}
	return &initialAppointment{owner: f[1], programme: f[2], commitment: f[5], admission: a, independent: i}, nil
}

func (s *scopedAdmissionRecords) authorityPurposeKey(scope []byte, purpose string) ([]byte, error) {
	if purpose != "REGISTER_TOKEN_ADMISSION" && purpose != "REGISTER_TOKEN" {
		return nil, errScopedAdmission
	}
	id, err := s.digest("SCOPE", scope, []byte(purpose))
	if err != nil {
		return nil, err
	}
	return s.key("current", id), nil
}

// inspectAuthorityPurposeHead is a read-only P component, NOT a lawful authority
// provider. It reads this owning native store under its existing header lease,
// checks immutable bytes and the expected purpose role, and returns only DATA.
// Actual expected-role mapping, appointment/current-lineage authentication,
// canonical proof/history/funding and original ingress still gate every use.
// There is no old shared-slot fallback, migration, writer or public caller.
func (s *scopedAdmissionRecords) inspectAuthorityPurposeHead(context *HeaderTimeContext, owner, programme []byte,
	purpose string, expectedRole []byte, bodies *authorityBodyCodec) (*authorityBody, error) {
	body, _, err := s.readAuthorityPurposeHead(context, owner, programme, purpose, expectedRole, bodies)
	return body, err
}

// readAuthorityPurposeHead retains the exact outer VERSION reference in
// addition to the decoded body's separate set ID, version and hash.
func (s *scopedAdmissionRecords) readAuthorityPurposeHead(context *HeaderTimeContext, owner, programme []byte,
	purpose string, expectedRole []byte, bodies *authorityBodyCodec) (*authorityBody, []byte, error) {
	if s == nil || s.codec == nil || check.IfNil(s.timeSource) || bodies == nil || bodies.source != s.codec || len(expectedRole) == 0 {
		return nil, nil, errScopedAdmission
	}
	var result *authorityBody
	var reference []byte
	_, err := withHeaderTime(s.timeSource, context, func() (*vmcommon.VMOutput, error) {
		if _, _, e := scopedAdmissionTime(context); e != nil {
			return nil, e
		}
		scope, e := s.scope(owner, programme)
		if e != nil {
			return nil, e
		}
		key, e := s.authorityPurposeKey(scope, purpose)
		if e != nil {
			return nil, e
		}
		account, e := s.codec.state.systemAccount()
		if e != nil {
			return nil, e
		}
		read := func(key []byte, count int) ([][]byte, error) {
			raw, _, e := account.RetrieveValue(key)
			if e != nil {
				return nil, e
			}
			return bodies.fields(raw, count, bodies.bounds.bytes)
		}
		pointer, e := read(key, 2)
		if e != nil || !bytes.Equal(pointer[0], scope) || len(pointer[1]) != s.codec.hasher.Size() {
			return nil, errScopedAdmission
		}
		version, e := read(s.key("version", pointer[1]), 3)
		if e != nil || !bytes.Equal(version[0], scope) ||
			(len(version[1]) != 0 && len(version[1]) != s.codec.hasher.Size()) {
			return nil, errScopedAdmission
		}
		id, e := s.digest("VERSION", version...)
		if e != nil || !bytes.Equal(id, pointer[1]) {
			return nil, errScopedAdmission
		}
		body, e := bodies.decode(version[2])
		if e != nil {
			return nil, e
		}
		if !bytes.Equal(body.role, expectedRole) || !bytes.Equal(body.owner, owner) || !bytes.Equal(body.programme, programme) {
			return nil, errScopedAdmission
		}
		if len(version[1]) == 0 {
			if len(body.predecessorVersion) != 0 {
				return nil, errScopedAdmission
			}
		} else {
			previous, e := read(s.key("version", version[1]), 3)
			if e != nil || !bytes.Equal(previous[0], scope) ||
				(len(previous[1]) != 0 && len(previous[1]) != s.codec.hasher.Size()) {
				return nil, errScopedAdmission
			}
			previousID, e := s.digest("VERSION", previous...)
			if e != nil || !bytes.Equal(previousID, version[1]) {
				return nil, errScopedAdmission
			}
			p, e := bodies.decode(previous[2])
			if e != nil {
				return nil, e
			}
			if (len(previous[1]) == 0) != (len(p.predecessorVersion) == 0) {
				return nil, errScopedAdmission
			}
			// An immutable set ID/version cannot name a conflicting body. This
			// selects no numeric successor progression or appointment policy.
			if bytes.Equal(body.version, p.version) && !bytes.Equal(body.hash, p.hash) {
				return nil, errScopedAdmission
			}
			if !bytes.Equal(body.id, p.id) || !bytes.Equal(body.role, p.role) || !bytes.Equal(body.owner, p.owner) || !bytes.Equal(body.programme, p.programme) ||
				!bytes.Equal(body.predecessorVersion, p.version) || !bytes.Equal(body.predecessorHash, p.hash) {
				return nil, errScopedAdmission
			}
		}
		result = body
		reference = bytes.Clone(pointer[1])
		return nil, nil
	})
	if err != nil {
		return nil, nil, err
	}
	return result, reference, nil
}

// initialPurposeWrites derives the existing VERSION/P records from selected
// G6 DATA only. It authenticates neither genesis nor the creating sender.
func (s *scopedAdmissionRecords) initialPurposeWrites(a *initialAppointment) ([]scopedAdmissionWrite, error) {
	scope, err := s.scope(a.owner, a.programme)
	if err != nil {
		return nil, err
	}
	writes := make([]scopedAdmissionWrite, 0, 4)
	for i, body := range []*authorityBody{a.admission, a.independent} {
		id, err := s.digest("VERSION", scope, nil, body.raw)
		if err != nil {
			return nil, err
		}
		version, err := s.codec.frame(scope, nil, body.raw)
		if err != nil {
			return nil, err
		}
		pointer, err := s.codec.frame(scope, id)
		if err != nil {
			return nil, err
		}
		purpose := "REGISTER_TOKEN_ADMISSION"
		if i == 1 {
			purpose = "REGISTER_TOKEN"
		}
		key, err := s.authorityPurposeKey(scope, purpose)
		if err != nil {
			return nil, err
		}
		writes = append(writes, scopedAdmissionWrite{s.key("version", id), version}, scopedAdmissionWrite{key, pointer})
	}
	return writes, nil
}
