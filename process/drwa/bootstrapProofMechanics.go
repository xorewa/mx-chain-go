package drwa

import (
	"bytes"
	"encoding/binary"
	"slices"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

const (
	bootstrapAuthorityPurpose        = "BOOTSTRAP_INTENT"
	bootstrapAuthorityCertificateTag = "DRWA/BOOTSTRAP_INTENT_AUTHORITY_CERTIFICATE/candidate1"
	bootstrapAuthorityRoleMapTag     = "DRWA/BOOTSTRAP_INTENT_ROLE_MAP/candidate1"
	bootstrapAdmissionPurpose        = "BOOTSTRAP_INTENT_ADMISSION"
	bootstrapAdmissionCertificateTag = "DRWA/BOOTSTRAP_INTENT_ADMISSION_CERTIFICATE/candidate1"
	bootstrapAdmissionRoleMapTag     = "DRWA/BOOTSTRAP_INTENT_ADMISSION_ROLE_MAP/candidate1"
	bootstrapPAPossessionPurpose     = "BOOTSTRAP_INTENT_PA_POSSESSION"
	bootstrapPAPossessionTag         = "DRWA/BOOTSTRAP_INTENT_PA_POSSESSION/candidate1"
	registrationAdmissionPurpose     = "REGISTER_TOKEN_ADMISSION"
)

// The native owner supplies the intent and the separately resolved current
// appointment. The A126 verifier derives the message, window and signer indices
// before giving the binding to the provider. None of these fields appoints a role.
type bootstrapProofBinding struct {
	purpose, role, owner, intent, authority, lineage, message []byte
	notBefore, notAfter                                       uint64
	signerIndices                                             []uint64
}

// The original owner supplies the authenticated programme owner and roles.
// The admission decision comes only from the immutable intent.
type bootstrapAdmissionProofInput struct {
	owner, intent                       []byte
	admissionRole, independentAuthority []byte
}

type bootstrapIndependentProof struct {
	role, lineage, envelope []byte
}

// bootstrapIntentProofInputs supplies the native owner's invocation-local
// proof dependencies. It grants no authority and is never retained by a writer.
type bootstrapIntentProofInputs struct {
	codec                               *registrationApprovalCodec
	records                             *scopedAdmissionRecords
	provider                            bootstrapProofProvider
	admission                           bootstrapAdmissionProofInput
	independentRole, independentLineage []byte
}

// The provider binds the exact verified purpose, authority, intent and signer
// indices to the original operation. It authenticates the A126 current prior
// appointment or the R2 admission head as applicable, including D01 separation
// and mandatory signer rules. For R2 PA, lineage is absent: the original intent
// selects the roster for possession only. Verification is read-only. The
// provider cannot substitute one signed proof for another or for the issuer.
type bootstrapProofProvider interface {
	VerifyBootstrapBinding(bootstrapProofBinding, []byte, []byte, HeaderMilliseconds, uint32) error
	IsInterfaceNil() bool
}

// verifyBootstrapAdmissionPA checks both private R2 families under the
// original operation. The independently appointed A126 certificate and the
// issuer signature are separate prerequisites. No public carrier or provider
// is installed by these checks.
func (c *registrationApprovalCodec) verifyBootstrapAdmissionPA(operation *rollbackOperation,
	records *scopedAdmissionRecords, context *HeaderTimeContext, provider bootstrapProofProvider,
	in bootstrapAdmissionProofInput, admissionProof, paProof []byte) error {
	return c.withBootstrapProofOperation(operation, records, context, func(at HeaderMilliseconds, epoch uint32) error {
		return c.verifyBootstrapAdmissionPAInHeader(records, context, provider, in, admissionProof, paProof, nil, at, epoch)
	})
}

// verifyBootstrapIntentArguments consumes the two adopted raw arguments using
// the original operation. The roles, decision and appointments come from the
// native owner, independently of the unsigned proof bundle.
func (c *registrationApprovalCodec) verifyBootstrapIntentArguments(operation *rollbackOperation,
	records *scopedAdmissionRecords, context *HeaderTimeContext, provider bootstrapProofProvider,
	in bootstrapAdmissionProofInput, independentRole, independentLineage []byte, args [][]byte) error {
	return c.withBootstrapProofOperation(operation, records, context, func(at HeaderMilliseconds, epoch uint32) error {
		return c.verifyBootstrapIntentArgumentsInHeader(records, context, provider, in, independentRole, independentLineage, args, at, epoch)
	})
}

// verifyBootstrapIntentArgumentsInHeader is called only within the verified
// owning operation and evaluated header interval, before any retention.
func (c *registrationApprovalCodec) verifyBootstrapIntentArgumentsInHeader(
	records *scopedAdmissionRecords, context *HeaderTimeContext, provider bootstrapProofProvider,
	in bootstrapAdmissionProofInput, independentRole, independentLineage []byte, args [][]byte, at HeaderMilliseconds, epoch uint32) error {
	if !c.ownsBootstrapProofRecords(records) || len(args) != 2 ||
		len(args[0]) == 0 || len(args[0]) > c.source.maxBytes || len(args[0]) > c.bounds.bytes ||
		len(independentRole) == 0 || len(independentRole) > c.bounds.roleBytes ||
		len(independentLineage) == 0 || len(independentLineage) > c.bounds.bytes ||
		len(in.independentAuthority) == 0 || len(in.independentAuthority) > c.bounds.bytes {
		return errInvalidRegistrationRecord
	}
	// The original proof limit covers all encoded DATA tags and lengths in Q.
	// Each inner envelope also fits its existing verifier byte limit.
	proofs, err := registrationBoundedFields(c.source, args[1], 3, 3, c.bounds.bytes)
	if err != nil {
		return err
	}
	for _, proof := range proofs {
		if len(proof) == 0 {
			return errInvalidRegistrationRecord
		}
	}
	in.intent = bytes.Clone(args[0])
	independent := &bootstrapIndependentProof{independentRole, independentLineage, proofs[2]}
	return c.verifyBootstrapAdmissionPAInHeader(records, context, provider, in, proofs[0], proofs[1], independent, at, epoch)
}

func (c *registrationApprovalCodec) ownsBootstrapProofRecords(records *scopedAdmissionRecords) bool {
	return c != nil && c.source != nil && c.source.state != nil && c.codec != nil &&
		records != nil && records.codec == c.source
}

func (c *registrationApprovalCodec) withBootstrapProofOperation(operation *rollbackOperation,
	records *scopedAdmissionRecords, context *HeaderTimeContext, verify func(HeaderMilliseconds, uint32) error) error {
	if !c.ownsBootstrapProofRecords(records) || operation == nil {
		return errInvalidRegistrationRecord
	}
	return operation.withWrite(records.boundary, c.source.state.accounts, func() error {
		_, err := withHeaderTime(records.timeSource, context, func() (*vmcommon.VMOutput, error) {
			at, epoch, e := scopedAdmissionTime(context)
			if e != nil {
				return nil, e
			}
			return nil, verify(at, epoch)
		})
		return err
	})
}

func (c *registrationApprovalCodec) verifyBootstrapAdmissionPAInHeader(records *scopedAdmissionRecords,
	context *HeaderTimeContext, provider bootstrapProofProvider, in bootstrapAdmissionProofInput,
	admissionProof, paProof []byte, independent *bootstrapIndependentProof, at HeaderMilliseconds, epoch uint32) error {
	if check.IfNil(provider) || check.IfNil(records.timeSource) || records.timeSource.GetAccountsAdapter() != c.source.state.accounts ||
		len(in.owner) != len(core.SystemAccountAddress) ||
		len(in.intent) == 0 || len(in.intent) > c.bounds.bytes || len(in.admissionRole) == 0 || len(in.admissionRole) > c.bounds.roleBytes ||
		len(admissionProof) == 0 || len(admissionProof) > c.bounds.bytes || len(paProof) == 0 || len(paProof) > c.bounds.bytes {
		return errInvalidRegistrationRecord
	}
	return verifyRegistrationState(records.boundary.stores, func() error {
		var binding bootstrapProofBinding
		if independent != nil {
			binding = cloneBootstrapProofBinding(bootstrapProofBinding{
				purpose: []byte(bootstrapAuthorityPurpose), role: independent.role, owner: in.owner,
				intent: in.intent, authority: in.independentAuthority, lineage: independent.lineage,
			})
		}
		if err := c.verifyBootstrapAdmissionPAAt(records, context, provider, in, binding.role, admissionProof, bytes.Clone(paProof), at, epoch); err != nil || independent == nil {
			return err
		}
		return c.verifyBootstrapProofAt(provider, binding, independent.envelope, at, epoch, true)
	})
}

func (c *registrationApprovalCodec) verifyBootstrapAdmissionPAAt(records *scopedAdmissionRecords,
	context *HeaderTimeContext, provider bootstrapProofProvider, in bootstrapAdmissionProofInput,
	independentRole, admissionProof, paProof []byte, at HeaderMilliseconds, epoch uint32) error {
	rawIntent := bytes.Clone(in.intent)
	fields, err := c.fields(rawIntent, 16, c.bounds.bytes)
	if err != nil {
		return err
	}
	for _, list := range [][]byte{fields[11], fields[12]} {
		if _, err = registrationFrameFieldCount(list, c.bounds.bytes/2, c.bounds.fieldBytes); err != nil {
			return err
		}
	}
	intent, err := c.codec.decodeBody(rawIntent)
	if err != nil {
		return err
	}
	d, scope, err := c.decodeBootstrapAdmissionDecision(records, intent, in.owner)
	if err != nil {
		return err
	}
	_, digest, id, err := c.codec.identity(intent)
	if err != nil {
		return err
	}
	bodies, err := newAuthorityBodyCodec(c.source, authorityBodyBounds{c.bounds.bytes, c.bounds.fieldBytes, c.bounds.roleBytes, c.bounds.maxMembers})
	if err != nil {
		return err
	}
	admission, reference, err := records.readAuthorityPurposeHead(context, d.owner, d.program, registrationAdmissionPurpose, in.admissionRole, bodies)
	if err != nil {
		return err
	}
	head := scopedAdmissionCurrentHead{context: context, accounts: c.source.state.accounts, scope: scope, version: reference}
	if err = records.checkDecisionAt(context, d, &head); err != nil {
		return err
	}
	pa, err := bodies.selectIntentPA(intent, d.owner, d.program)
	if err != nil {
		return err
	}
	independent, err := c.bootstrapIndependentAuthority(records, context, bodies, d, in.independentAuthority, independentRole)
	if err != nil {
		return err
	}
	if !bytes.Equal(independent.owner, d.owner) || !bytes.Equal(independent.programme, d.program) ||
		!bootstrapAuthoritiesDisjoint(admission, pa) || !bootstrapAuthoritiesDisjoint(admission, independent) ||
		!bootstrapAuthoritiesDisjoint(pa, independent) {
		return errInvalidRegistrationRecord
	}
	commitment, err := c.bootstrapIntentCommitment(intent)
	if err != nil {
		return err
	}
	row, err := c.codec.frame([]byte(registrationAdmissionPurpose), admission.role, admission.id, admission.version, admission.hash)
	if err != nil {
		return err
	}
	projection, err := c.bootstrapFrameHash([]byte(bootstrapAdmissionRoleMapTag), intent.networkDomain, d.owner, d.program, row)
	if err != nil {
		return err
	}
	// Detach coordinates used again after the admission provider returns.
	owner, programme := bytes.Clone(d.owner), bytes.Clone(d.program)
	verify := func(purpose, tag string, authority *authorityBody, binding, lineage, raw []byte) error {
		envelope, e := c.fields(raw, 3, c.bounds.bytes)
		if e != nil {
			return e
		}
		m, e := c.fields(envelope[0], 12, c.bounds.bytes)
		if e != nil {
			return e
		}
		if len(m[10]) != 8 || len(m[11]) != 8 {
			return errInvalidRegistrationRecord
		}
		nb, na := binary.BigEndian.Uint64(m[10]), binary.BigEndian.Uint64(m[11])
		if !c.bootstrapWindowValid(nb, na, at, intent.expiry) {
			return errInvalidRegistrationRecord
		}
		dep, e := c.codec.frame(authority.role, scope, authority.id, authority.version, authority.hash, binding)
		if e != nil {
			return e
		}
		message, e := c.codec.frame([]byte(tag), intent.networkDomain, []byte(purpose), owner, programme,
			intent.issuer, id, digest, commitment, dep, m[10], m[11])
		if e != nil || !bytes.Equal(envelope[0], message) {
			return errInvalidRegistrationRecord
		}
		indices, e := c.verifyAuthorityEnvelopeSignatures(envelope, authority)
		if e != nil {
			return e
		}
		p := bootstrapProofBinding{purpose: []byte(purpose), role: authority.role, owner: owner, intent: rawIntent,
			authority: authority.raw, lineage: lineage, message: message, notBefore: nb, notAfter: na, signerIndices: indices}
		return verifyRegistrationState(records.boundary.stores, func() error {
			return provider.VerifyBootstrapBinding(cloneBootstrapProofBinding(p), bytes.Clone(id), bytes.Clone(digest), at, epoch)
		})
	}
	if err = verify(bootstrapAdmissionPurpose, bootstrapAdmissionCertificateTag, admission, projection, reference, admissionProof); err != nil {
		return err
	}
	return verify(bootstrapPAPossessionPurpose, bootstrapPAPossessionTag, pa, digest, nil, paProof)
}

// D6 binds the exact embedded bytes to the native subject. Parsing establishes
// neither positive admission nor authority: the exact stored row, withdrawal,
// VERSION and lawful appointment checks are still required by the consumer.
func (c *registrationApprovalCodec) decodeBootstrapAdmissionDecision(records *scopedAdmissionRecords,
	intent bootstrapIntentBody, owner []byte) (scopedAdmissionDecision, []byte, error) {
	var d scopedAdmissionDecision
	if !bytes.Equal(intent.networkDomain, records.domain) {
		return d, nil, errScopedAdmission
	}
	return c.decodeScopedAdmissionDecision(records, intent.issuerProgramAdmissionDecision, owner, intent.programID, intent.issuer)
}

func (c *registrationApprovalCodec) decodeScopedAdmissionDecision(records *scopedAdmissionRecords,
	raw, owner, programme, issuer []byte) (scopedAdmissionDecision, []byte, error) {
	var d scopedAdmissionDecision
	if len(issuer) != len(core.SystemAccountAddress) {
		return d, nil, errScopedAdmission
	}
	scope, err := records.scope(owner, programme)
	if err != nil {
		return d, nil, err
	}
	fields, err := c.fields(raw, 6, c.bounds.bytes)
	if err != nil {
		return d, nil, err
	}
	if !bytes.Equal(fields[0], scope) || !bytes.Equal(fields[1], issuer) ||
		len(fields[2]) == 0 || len(fields[2]) > c.bounds.fieldBytes || len(fields[3]) == 0 || len(fields[3]) > c.bounds.fieldBytes ||
		len(fields[4]) != c.codec.hasher.Size() || len(fields[5]) != 8 {
		return d, nil, errScopedAdmission
	}
	d = scopedAdmissionDecision{owner: bytes.Clone(owner), program: bytes.Clone(programme), issuer: fields[1],
		version: fields[2], commitment: fields[3], authority: fields[4], validUntil: HeaderMilliseconds(binary.BigEndian.Uint64(fields[5]))}
	return d, scope, nil
}

func (c *registrationApprovalCodec) bootstrapIndependentAuthority(records *scopedAdmissionRecords, context *HeaderTimeContext,
	bodies *authorityBodyCodec, d scopedAdmissionDecision, suppliedBody, role []byte) (*authorityBody, error) {
	if len(role) == 0 {
		// The private R2-only verifier uses this body for roster separation;
		// it does not verify or authorize the independent proof.
		return bodies.decode(suppliedBody)
	}
	// A126 extends the separately appointed REGISTER_TOKEN role. Its owned
	// bundle must use that native purpose head at this use. The provider still
	// authenticates the appointment, eligibility and lineage of the exact body.
	current, _, err := records.readAuthorityPurposeHead(context, d.owner, d.program, "REGISTER_TOKEN", role, bodies)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(current.raw, suppliedBody) {
		return nil, errScopedAdmission
	}
	return current, nil
}

func cloneBootstrapProofBinding(b bootstrapProofBinding) bootstrapProofBinding {
	b.purpose, b.role, b.owner = bytes.Clone(b.purpose), bytes.Clone(b.role), bytes.Clone(b.owner)
	b.intent, b.authority, b.lineage = bytes.Clone(b.intent), bytes.Clone(b.authority), bytes.Clone(b.lineage)
	b.message, b.signerIndices = bytes.Clone(b.message), slices.Clone(b.signerIndices)
	return b
}

// verifyBootstrapProof exercises the generic mechanics with an opaque expected
// message. A126 consumers use verifyBootstrapAuthorityCertificate.
func (c *registrationApprovalCodec) verifyBootstrapProof(operation *rollbackOperation, boundary *RollbackContainment,
	source HeaderTimeSource, context *HeaderTimeContext, provider bootstrapProofProvider, b bootstrapProofBinding, raw []byte) error {
	return c.verifyBootstrapProofWith(operation, boundary, source, context, provider, b, raw, false)
}

// verifyBootstrapAuthorityCertificate checks the A126 independent Step 1
// certificate against native current-at-use inputs. This is one obligation
// within ingress. It installs no provider and never writes admission state.
func (c *registrationApprovalCodec) verifyBootstrapAuthorityCertificate(operation *rollbackOperation, boundary *RollbackContainment,
	source HeaderTimeSource, context *HeaderTimeContext, provider bootstrapProofProvider, b bootstrapProofBinding, raw []byte) error {
	// Only the envelope supplies a candidate window. The provider receives
	// the derived expected message and indices, never caller-asserted values.
	b.message, b.signerIndices = nil, nil
	return c.verifyBootstrapProofWith(operation, boundary, source, context, provider, b, raw, true)
}

func (c *registrationApprovalCodec) verifyBootstrapProofWith(operation *rollbackOperation, boundary *RollbackContainment,
	source HeaderTimeSource, context *HeaderTimeContext, provider bootstrapProofProvider, b bootstrapProofBinding, raw []byte, a126 bool) error {
	if c == nil || c.source == nil || c.source.state == nil || boundary == nil || operation == nil {
		return errInvalidRegistrationRecord
	}
	return operation.withWrite(boundary, c.source.state.accounts, func() error {
		if c.codec == nil || check.IfNil(source) || check.IfNil(provider) || context == nil || c.bounds.maxValidity == 0 ||
			check.IfNil(c.codec.marshaller) || check.IfNil(c.codec.hasher) || source.GetAccountsAdapter() != c.source.state.accounts ||
			len(raw) == 0 || len(raw) > c.bounds.bytes || len(b.purpose) == 0 || len(b.purpose) > c.bounds.fieldBytes ||
			len(b.role) == 0 || len(b.role) > c.bounds.roleBytes || len(b.owner) != len(core.SystemAccountAddress) {
			return errInvalidRegistrationRecord
		}
		for _, value := range [][]byte{b.intent, b.authority, b.lineage} {
			if len(value) == 0 || len(value) > c.bounds.bytes {
				return errInvalidRegistrationRecord
			}
		}
		if a126 {
			if string(b.purpose) != bootstrapAuthorityPurpose {
				return errInvalidRegistrationRecord
			}
		} else if len(b.message) == 0 || len(b.message) > c.bounds.bytes {
			return errInvalidRegistrationRecord
		}
		b, raw = cloneBootstrapProofBinding(b), bytes.Clone(raw)
		_, err := withHeaderTime(source, context, func() (*vmcommon.VMOutput, error) {
			at, epoch, e := scopedAdmissionTime(context)
			if e != nil {
				return nil, e
			}
			e = verifyRegistrationState(boundary.stores, func() error {
				return c.verifyBootstrapProofAt(provider, b, raw, at, epoch, a126)
			})
			return nil, e
		})
		return err
	})
}

func (c *registrationApprovalCodec) verifyBootstrapProofAt(provider bootstrapProofProvider, b bootstrapProofBinding, raw []byte, at HeaderMilliseconds, epoch uint32, a126 bool) error {
	envelope, err := c.fields(raw, 3, c.bounds.bytes)
	if err != nil {
		return err
	}
	intent, err := c.codec.decodeBody(b.intent)
	if err != nil {
		return err
	}
	_, digest, id, err := c.codec.identity(intent)
	if err != nil {
		return err
	}
	bodies, err := newAuthorityBodyCodec(c.codec, authorityBodyBounds{c.bounds.bytes, c.bounds.fieldBytes, c.bounds.roleBytes, c.bounds.maxMembers})
	if err != nil {
		return err
	}
	authority, err := bodies.decode(b.authority)
	if err != nil {
		return err
	}
	if !bytes.Equal(authority.role, b.role) || !bytes.Equal(authority.owner, b.owner) || !bytes.Equal(authority.programme, intent.programID) {
		return errInvalidRegistrationRecord
	}
	if a126 {
		if err = c.bindBootstrapAuthorityMessage(&b, envelope[0], bodies, authority, intent, id, digest); err != nil {
			return err
		}
	} else if _, err = registrationBoundedFields(c.codec, b.message, 1, c.bounds.bytes/2, c.bounds.fieldBytes); err != nil {
		return err
	}
	if !bytes.Equal(envelope[0], b.message) || !c.bootstrapWindowValid(b.notBefore, b.notAfter, at, intent.expiry) {
		return errInvalidRegistrationRecord
	}
	positions, err := c.verifyAuthorityEnvelopeSignatures(envelope, authority)
	if err != nil {
		return err
	}
	if a126 {
		b.signerIndices = positions
	}
	return provider.VerifyBootstrapBinding(cloneBootstrapProofBinding(b), bytes.Clone(id), bytes.Clone(digest), at, epoch)
}

func (c *registrationApprovalCodec) bootstrapWindowValid(nb, na uint64, at, expiry HeaderMilliseconds) bool {
	return nb <= na && uint64(at) >= nb && uint64(at) <= na && na <= uint64(expiry) && na-nb <= c.bounds.maxValidity
}

func (c *registrationApprovalCodec) verifyAuthorityEnvelopeSignatures(envelope [][]byte, authority *authorityBody) ([]uint64, error) {
	indices, err := c.list(envelope[1], 8)
	if err != nil {
		return nil, err
	}
	signatures, err := c.list(envelope[2], c.bounds.fieldBytes)
	if err != nil || len(indices) != len(signatures) {
		return nil, errInvalidRegistrationRecord
	}
	positions := make([]uint64, len(indices))
	for i, index := range indices {
		if len(index) != 8 {
			return nil, errInvalidRegistrationRecord
		}
		positions[i] = binary.BigEndian.Uint64(index)
	}
	signedDigest, err := c.hash(envelope[0])
	if err != nil {
		return nil, err
	}
	if err = verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", authority.threshold, authority.members, positions, signatures,
		signedDigest, uint64(c.bounds.maxMembers), uint64(c.bounds.fieldBytes)); err != nil {
		return nil, err
	}
	return positions, nil
}

func (c *registrationApprovalCodec) bindBootstrapAuthorityMessage(b *bootstrapProofBinding, message []byte,
	bodies *authorityBodyCodec, authority *authorityBody, intent bootstrapIntentBody, id, digest []byte) error {
	fields, err := c.fields(message, 12, c.bounds.bytes)
	if err != nil {
		return err
	}
	if len(fields[10]) != 8 || len(fields[11]) != 8 ||
		len(intent.networkDomain) > c.bounds.fieldBytes || len(intent.programID) > c.bounds.fieldBytes ||
		len(id) != c.codec.hasher.Size() || len(digest) != c.codec.hasher.Size() {
		return errInvalidRegistrationRecord
	}
	// The existing PA selector checks every proposed body/hash pair in
	// immutable intent order. Possession and lawful admission remain separate.
	pa, err := bodies.selectIntentPA(intent, b.owner, intent.programID)
	if err != nil {
		return err
	}
	if !bootstrapAuthoritiesDisjoint(pa, authority) {
		return errInvalidRegistrationRecord
	}
	scope, err := c.codec.frame(intent.networkDomain, b.owner, intent.programID)
	if err != nil {
		return err
	}
	commitment, err := c.bootstrapIntentCommitment(intent)
	if err != nil {
		return err
	}
	row, err := c.codec.frame(b.purpose, authority.role, authority.id, authority.version, authority.hash)
	if err != nil {
		return err
	}
	projection, err := c.bootstrapFrameHash([]byte(bootstrapAuthorityRoleMapTag), intent.networkDomain, b.owner, intent.programID, row)
	if err != nil {
		return err
	}
	dependency, err := c.codec.frame(authority.role, scope, authority.id, authority.version, authority.hash, projection)
	if err != nil {
		return err
	}
	b.notBefore, b.notAfter = binary.BigEndian.Uint64(fields[10]), binary.BigEndian.Uint64(fields[11])
	b.message, err = c.codec.frame([]byte(bootstrapAuthorityCertificateTag), intent.networkDomain, b.purpose,
		b.owner, intent.programID, intent.issuer, id, digest, commitment, dependency, fields[10], fields[11])
	return err
}

func bootstrapAuthoritiesDisjoint(first, second *authorityBody) bool {
	if bytes.Equal(first.id, second.id) || bytes.Equal(first.role, second.role) {
		return false
	}
	members := make(map[string]struct{}, len(first.members))
	for _, member := range first.members {
		members[string(member)] = struct{}{}
	}
	for _, member := range second.members {
		if _, shared := members[string(member)]; shared {
			return false
		}
	}
	return true
}

func (c *registrationApprovalCodec) bootstrapIntentCommitment(intent bootstrapIntentBody) ([]byte, error) {
	hashes, err := c.codec.authorityList(intent.proposedProgramAuthoritySetHashes)
	if err != nil {
		return nil, err
	}
	return c.bootstrapFrameHash(intent.issuerProgramAdmissionDecision, hashes)
}

func (c *registrationApprovalCodec) bootstrapFrameHash(fields ...[]byte) ([]byte, error) {
	raw, err := c.codec.frame(fields...)
	if err != nil {
		return nil, err
	}
	return c.hash(raw)
}
