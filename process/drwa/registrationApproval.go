package drwa

import (
	"bytes"
	"encoding/binary"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
)

// A38 construction bytes only. No public ingress, authority appointment,
// released encoding, profile default or RegistrationVerifier is installed.
const registrationApprovalTag = "DRWA/REGISTER_TOKEN_APPROVAL/candidate2"
const registrationRoleMapTag = "DRWA/REGISTER_TOKEN_ROLE_MAP/candidate1"
const registrationPARole = "Program Administration Authority"

type registrationApprovalBounds struct {
	bytes, fieldBytes, roleBytes, familyBytes, maxMembers int
	maxValidity                                           uint64
}

type registrationApprovalCodec struct {
	source *registrationRecords
	codec  *registrationRecords
	bounds registrationApprovalBounds
}

// These private inputs must come from different authenticated native producers:
// admission/current scoped lineage; PA/immutable intent body schema; independent/
// current-at-use lawful scoped lineage. Presence of this struct authenticates
// nothing. No production caller supplies it yet; fixtures are non-authoritative.
// In particular the PA body schema, real appointments, native address/origin,
// support, historical context and original operation lease remain real-use gates.
type registrationApprovalAuthority struct {
	role, scope, setID, version, body, bodyHash []byte
	threshold                                   uint64
	members                                     [][]byte
}

type registrationApprovalContext struct {
	network, scopeOwner, programme, issuer, intentID, intentHash []byte
	intentBody, manager, profile                                 []byte
	at                                                           HeaderMilliseconds
	admission, pa, independent                                   registrationApprovalAuthority
}

type registrationCreationBody struct {
	family, profileHash, name, ticker, digest []byte
	decimals                                  uint32
}

func newRegistrationApprovalCodec(records *registrationRecords, b registrationApprovalBounds) (*registrationApprovalCodec, error) {
	if records == nil || check.IfNil(records.marshaller) || check.IfNil(records.hasher) ||
		records.hasher.Size() <= 0 || b.bytes <= 0 || b.bytes > records.maxBytes ||
		b.fieldBytes < records.hasher.Size() || b.fieldBytes > b.bytes ||
		b.roleBytes <= 0 || b.roleBytes > b.fieldBytes || b.familyBytes <= 0 || b.familyBytes > b.fieldBytes ||
		b.maxMembers < 5 || b.maxMembers > b.bytes/2 || b.maxValidity == 0 {
		return nil, errInvalidRegistrationRecord
	}
	local := *records
	local.maxBytes = b.bytes
	return &registrationApprovalCodec{source: records, codec: &local, bounds: b}, nil
}

func (c *registrationApprovalCodec) fields(raw []byte, count, maxField int) ([][]byte, error) {
	return registrationBoundedFields(c.codec, raw, count, count, maxField)
}
func (c *registrationApprovalCodec) list(raw []byte, maxField int) ([][]byte, error) {
	return registrationBoundedFields(c.codec, raw, 1, c.bounds.maxMembers, maxField)
}

func (c *registrationApprovalCodec) hash(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > c.bounds.bytes {
		return nil, errInvalidRegistrationRecord
	}
	digest := c.codec.hasher.Compute(string(raw))
	if len(digest) != c.codec.hasher.Size() {
		return nil, errInvalidRegistrationRecord
	}
	return digest, nil
}

func (c *registrationApprovalCodec) decodeCreation(raw []byte, intent bootstrapIntentBody, manager, profile []byte) (*registrationCreationBody, error) {
	f, err := c.fields(raw, 6, c.bounds.fieldBytes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(f[0], []byte("DRWA/TOKEN_CREATION_BODY/v1")) ||
		len(f[1]) == 0 || len(f[1]) > c.bounds.familyBytes || len(f[2]) != c.codec.hasher.Size() ||
		len(f[3]) == 0 || len(f[4]) == 0 || len(f[5]) != 4 || len(manager) != len(core.SystemAccountAddress) ||
		len(profile) == 0 || len(profile) > c.bounds.bytes || !bytes.Equal(f[1], intent.requestedTokenFamily) ||
		!bytes.Equal(f[2], intent.creationProfile) {
		return nil, errInvalidRegistrationRecord
	}
	if _, err = c.fields(profile, 14, c.bounds.fieldBytes); err != nil {
		return nil, err
	}
	digest, err := c.hash(raw)
	if err != nil {
		return nil, err
	}
	decimals := binary.BigEndian.Uint32(f[5])
	if _, err = c.codec.creationProperties(intent, manager, f[1], profile, f[3], f[4], decimals, digest); err != nil {
		return nil, err
	}
	return &registrationCreationBody{f[1], f[2], f[3], f[4], digest, decimals}, nil
}

func (c *registrationApprovalCodec) context(ctx *registrationApprovalContext) (bootstrapIntentBody, []byte, error) {
	bad := func() (bootstrapIntentBody, []byte, error) {
		return bootstrapIntentBody{}, nil, errInvalidRegistrationRecord
	}
	if ctx == nil || len(ctx.network) == 0 || len(ctx.network) > c.bounds.fieldBytes ||
		len(ctx.programme) == 0 || len(ctx.programme) > c.bounds.fieldBytes ||
		len(ctx.scopeOwner) != len(core.SystemAccountAddress) || len(ctx.issuer) != len(core.SystemAccountAddress) ||
		len(ctx.intentID) != c.codec.hasher.Size() || len(ctx.intentHash) != c.codec.hasher.Size() {
		return bad()
	}
	intentFields, err := c.fields(ctx.intentBody, 16, c.bounds.bytes)
	if err != nil {
		return bad()
	}
	for _, index := range []int{11, 12} {
		if len(intentFields[index]) == 0 {
			return bad()
		}
		if _, err = registrationFrameFieldCount(intentFields[index], c.bounds.bytes/2, c.bounds.fieldBytes); err != nil {
			return bad()
		}
	}
	body, err := c.codec.decodeBody(ctx.intentBody)
	if err != nil {
		return bad()
	}
	_, digest, id, err := c.codec.identity(body)
	if err != nil || !bytes.Equal(digest, ctx.intentHash) || !bytes.Equal(id, ctx.intentID) ||
		!bytes.Equal(body.networkDomain, ctx.network) || !bytes.Equal(body.programID, ctx.programme) ||
		!bytes.Equal(body.issuer, ctx.issuer) {
		return bad()
	}
	scope, err := c.codec.frame(ctx.network, ctx.scopeOwner, ctx.programme)
	if err != nil {
		return bad()
	}
	sets := []*registrationApprovalAuthority{&ctx.admission, &ctx.pa, &ctx.independent}
	seenKeys := make(map[string]struct{})
	for i, set := range sets {
		if len(set.role) == 0 || len(set.role) > c.bounds.roleBytes || !bytes.Equal(set.scope, scope) ||
			len(set.setID) == 0 || len(set.setID) > c.bounds.fieldBytes || len(set.version) != 8 ||
			len(set.body) == 0 || len(set.body) > c.bounds.fieldBytes || len(set.bodyHash) != c.codec.hasher.Size() ||
			len(set.members) > c.bounds.maxMembers || validateProgrammeAuthorityThreshold(uint64(len(set.members)), set.threshold) != nil {
			return bad()
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(set.setID, sets[j].setID) {
				return bad()
			}
		}
		// The native authority producer owns the version-body hash preimage.
		// This construction compares its authenticated identity; it does not
		// redefine that identity as a hash of these opaque body bytes.
		for _, key := range set.members {
			if len(key) == 0 || len(key) > c.bounds.fieldBytes {
				return bad()
			}
			if _, duplicate := seenKeys[string(key)]; duplicate {
				return bad()
			}
			seenKeys[string(key)] = struct{}{}
		}
	}
	if !bytes.Equal(ctx.pa.role, []byte(registrationPARole)) {
		return bad()
	}
	paMatches := 0
	for i, proposed := range body.proposedProgramAuthoritySetBodies {
		if bytes.Equal(proposed, ctx.pa.body) && bytes.Equal(body.proposedProgramAuthoritySetHashes[i], ctx.pa.bodyHash) {
			paMatches++
		}
	}
	if paMatches != 1 {
		return bad()
	}
	// Parse the other two rosters, not their signatures. This envelope's
	// signatures can be satisfied ONLY by the independent roster below.
	for _, set := range sets[:2] {
		if _, err := programmeAuthorityPublicKeys(set.members); err != nil {
			return bad()
		}
	}
	return body, scope, nil
}

func (c *registrationApprovalCodec) roleMap(ctx *registrationApprovalContext) ([]byte, []byte, error) {
	if ctx == nil {
		return nil, nil, errInvalidRegistrationRecord
	}
	row := func(purpose string, set registrationApprovalAuthority) ([]byte, error) {
		return c.codec.frame([]byte(purpose), set.role, set.setID, set.version, set.bodyHash)
	}
	a, err := row("REGISTER_TOKEN_ADMISSION", ctx.admission)
	if err != nil {
		return nil, nil, err
	}
	i, err := row("REGISTER_TOKEN", ctx.independent)
	if err != nil {
		return nil, nil, err
	}
	encoded, err := c.codec.frame([]byte(registrationRoleMapTag), ctx.network, ctx.scopeOwner, ctx.programme, a, i)
	if err != nil {
		return nil, nil, err
	}
	digest, err := c.hash(encoded)
	return encoded, digest, err
}

// independentApprovalPreimage constructs only the existing M14 signing data.
// Caller-supplied tuples are not native authority: the original owner still owes
// admitted lineage/appointment, original intent, support, funding and lifetime.
func (c *registrationApprovalCodec) independentApprovalPreimage(creation []byte, ctx *registrationApprovalContext,
	notBefore, notAfter uint64) ([]byte, []byte, error) {
	if c == nil || c.codec == nil || ctx == nil || c.bounds.maxValidity == 0 ||
		check.IfNil(c.codec.marshaller) || check.IfNil(c.codec.hasher) {
		return nil, nil, errInvalidRegistrationRecord
	}
	body, scope, err := c.context(ctx)
	if err != nil {
		return nil, nil, err
	}
	decoded, err := c.decodeCreation(creation, body, ctx.manager, ctx.profile)
	if err != nil {
		return nil, nil, err
	}
	if notBefore > notAfter || uint64(ctx.at) < notBefore || uint64(ctx.at) > notAfter ||
		notAfter > uint64(body.expiry) || notAfter-notBefore > c.bounds.maxValidity {
		return nil, nil, errInvalidRegistrationRecord
	}
	_, mapHash, err := c.roleMap(ctx)
	if err != nil {
		return nil, nil, err
	}
	sets := []registrationApprovalAuthority{ctx.admission, ctx.pa, ctx.independent}
	deps := make([][]byte, len(sets))
	for i, set := range sets {
		binding := mapHash
		if i == 1 {
			binding = ctx.intentHash
		}
		deps[i], err = c.codec.frame(set.role, scope, set.setID, set.version, set.bodyHash, binding)
		if err != nil {
			return nil, nil, err
		}
	}
	message, err := c.codec.frame([]byte(registrationApprovalTag), ctx.network, []byte("REGISTER_TOKEN"),
		ctx.scopeOwner, ctx.programme, ctx.issuer, ctx.intentID, ctx.intentHash, decoded.digest,
		deps[0], deps[1], deps[2], binary.BigEndian.AppendUint64(nil, notBefore), binary.BigEndian.AppendUint64(nil, notAfter))
	if err != nil {
		return nil, nil, err
	}
	digest, err := c.hash(message)
	if err != nil {
		return nil, nil, err
	}
	return message, digest, nil
}

// verifyIndependent is a pure construction check, NOT a RegistrationVerifier
// or native admission adapter. The original lease must keep all inputs stable;
// real context/body-schema/appointment producers and other proof functions are
// mandatory before any real consumer. No requester can select this context.
func (c *registrationApprovalCodec) verifyIndependent(raw, creation []byte, ctx *registrationApprovalContext) error {
	if c == nil || c.codec == nil || ctx == nil || c.bounds.maxValidity == 0 ||
		check.IfNil(c.codec.marshaller) || check.IfNil(c.codec.hasher) {
		return errInvalidRegistrationRecord
	}
	envelope, err := c.fields(raw, 3, c.bounds.bytes)
	if err != nil {
		return err
	}
	m, err := c.fields(envelope[0], 14, c.bounds.bytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(m[0], []byte(registrationApprovalTag)) || !bytes.Equal(m[2], []byte("REGISTER_TOKEN")) ||
		len(m[1]) == 0 || len(m[1]) > c.bounds.fieldBytes || len(m[4]) == 0 || len(m[4]) > c.bounds.fieldBytes ||
		len(m[3]) != len(core.SystemAccountAddress) || len(m[5]) != len(core.SystemAccountAddress) ||
		len(m[6]) != c.codec.hasher.Size() || len(m[7]) != c.codec.hasher.Size() || len(m[8]) != c.codec.hasher.Size() ||
		len(m[12]) != 8 || len(m[13]) != 8 {
		return errInvalidRegistrationRecord
	}
	deps := make([][][]byte, 3)
	for i := range deps {
		deps[i], err = c.fields(m[9+i], 6, c.bounds.bytes)
		if err != nil {
			return err
		}
		f := deps[i]
		if len(f[0]) == 0 || len(f[0]) > c.bounds.roleBytes || len(f[2]) == 0 || len(f[2]) > c.bounds.fieldBytes ||
			len(f[3]) != 8 || len(f[4]) != c.codec.hasher.Size() || len(f[5]) != c.codec.hasher.Size() {
			return errInvalidRegistrationRecord
		}
	}
	positions, err := c.list(envelope[1], 8)
	if err != nil {
		return err
	}
	signatures, err := c.list(envelope[2], c.bounds.fieldBytes)
	if err != nil || len(positions) != len(signatures) {
		return errInvalidRegistrationRecord
	}
	indices := make([]uint64, len(positions))
	for i, p := range positions {
		if len(p) != 8 {
			return errInvalidRegistrationRecord
		}
		indices[i] = binary.BigEndian.Uint64(p)
		if i > 0 && indices[i] <= indices[i-1] {
			return errInvalidRegistrationRecord
		}
	}
	expected, digest, err := c.independentApprovalPreimage(creation, ctx, binary.BigEndian.Uint64(m[12]), binary.BigEndian.Uint64(m[13]))
	if err != nil {
		return err
	}
	if !bytes.Equal(envelope[0], expected) {
		return errInvalidRegistrationRecord
	}
	return verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", ctx.independent.threshold, ctx.independent.members,
		indices, signatures, digest, uint64(c.bounds.maxMembers), uint64(c.bounds.fieldBytes))
}

// Owner-selected A11 R3 construction. This tag does not replace independent
// approval M14 or allocate any other purpose's proof grammar.
const registrationAuthorityCertificateTag = "DRWA/REGISTER_TOKEN_AUTHORITY_CERTIFICATE/candidate1"

// checkCertificateBodies binds each supplied tuple to its SAME bounded B9 body,
// including the PA selected from the ORIGINAL intent. This is data consistency,
// never appointment/current-lineage authentication or an admission producer.
func (c *registrationApprovalCodec) checkCertificateBodies(ctx *registrationApprovalContext, intent bootstrapIntentBody) error {
	bodies, err := newAuthorityBodyCodec(c.codec, authorityBodyBounds{c.bounds.bytes, c.bounds.fieldBytes, c.bounds.roleBytes, c.bounds.maxMembers})
	if err != nil {
		return err
	}
	for _, set := range []registrationApprovalAuthority{ctx.admission, ctx.pa, ctx.independent} {
		body, err := bodies.decode(set.body)
		if err != nil {
			return err
		}
		if !bytes.Equal(body.role, set.role) || !bytes.Equal(body.owner, ctx.scopeOwner) ||
			!bytes.Equal(body.programme, ctx.programme) || !bytes.Equal(body.id, set.setID) ||
			!bytes.Equal(body.version, set.version) || !bytes.Equal(body.hash, set.bodyHash) ||
			body.threshold != set.threshold || len(body.members) != len(set.members) {
			return errInvalidRegistrationRecord
		}
		for i, member := range body.members {
			if !bytes.Equal(member, set.members[i]) {
				return errInvalidRegistrationRecord
			}
		}
	}
	pa, err := bodies.selectIntentPA(intent, ctx.scopeOwner, ctx.programme)
	if err != nil {
		return err
	}
	if !bytes.Equal(pa.raw, ctx.pa.body) {
		return errInvalidRegistrationRecord
	}
	return nil
}

// authorityCertificatePreimage constructs the exact selected M12 and its
// configured digest. Output is DATA for signing, never native authority,
// appointment/currentness, canonical OPEN status or permission to execute.
// It reuses the same explicit bounds, original PA body and role-map projection
// as the consumer. Missing profile bounds never acquire a signing default.
func (c *registrationApprovalCodec) authorityCertificatePreimage(creation []byte, ctx *registrationApprovalContext,
	purpose string, nb, na uint64) ([]byte, []byte, error) {
	if c == nil || c.codec == nil || ctx == nil || c.bounds.maxValidity == 0 ||
		check.IfNil(c.codec.marshaller) || check.IfNil(c.codec.hasher) ||
		(purpose != "REGISTER_TOKEN_ADMISSION" && purpose != "PROGRAM_ADMINISTRATION") {
		return nil, nil, errInvalidRegistrationRecord
	}
	body, scope, err := c.context(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err = c.checkCertificateBodies(ctx, body); err != nil {
		return nil, nil, err
	}
	decoded, err := c.decodeCreation(creation, body, ctx.manager, ctx.profile)
	if err != nil {
		return nil, nil, err
	}
	if nb > na || uint64(ctx.at) < nb || uint64(ctx.at) > na || na > uint64(body.expiry) || na-nb > c.bounds.maxValidity {
		return nil, nil, errInvalidRegistrationRecord
	}
	set, binding := ctx.pa, ctx.intentHash
	if purpose == "REGISTER_TOKEN_ADMISSION" {
		set = ctx.admission
		_, binding, err = c.roleMap(ctx)
		if err != nil {
			return nil, nil, err
		}
	}
	dependency, err := c.codec.frame(set.role, scope, set.setID, set.version, set.bodyHash, binding)
	if err != nil {
		return nil, nil, err
	}
	message, err := c.codec.frame([]byte(registrationAuthorityCertificateTag), ctx.network, []byte(purpose), ctx.scopeOwner,
		ctx.programme, ctx.issuer, ctx.intentID, ctx.intentHash, decoded.digest, dependency,
		binary.BigEndian.AppendUint64(nil, nb), binary.BigEndian.AppendUint64(nil, na))
	if err != nil {
		return nil, nil, err
	}
	digest, err := c.hash(message)
	if err != nil {
		return nil, nil, err
	}
	return message, digest, nil
}

// verifyAuthorityCertificate verifies only the selected purpose-separated
// admission/PA construction, not native authority or registration admission.
// The ORIGINAL native owner must separately authenticate canonical OPEN status,
// the embedded admission decision's current/unexpired/unwithdrawn conditions,
// supported lawful lineage, original G6, profile/support and the operation lease.
// In particular F4's map coupling supplies NO admission-succession rule and
// never rewrites an immutable intent. No requester may provide trusted context.
func (c *registrationApprovalCodec) verifyAuthorityCertificate(raw, creation []byte, ctx *registrationApprovalContext, purpose string) error {
	if c == nil || c.codec == nil || ctx == nil || c.bounds.maxValidity == 0 ||
		check.IfNil(c.codec.marshaller) || check.IfNil(c.codec.hasher) ||
		(purpose != "REGISTER_TOKEN_ADMISSION" && purpose != "PROGRAM_ADMINISTRATION") {
		return errInvalidRegistrationRecord
	}
	envelope, err := c.fields(raw, 3, c.bounds.bytes)
	if err != nil {
		return err
	}
	m, err := c.fields(envelope[0], 12, c.bounds.bytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(m[0], []byte(registrationAuthorityCertificateTag)) || !bytes.Equal(m[2], []byte(purpose)) ||
		len(m[1]) == 0 || len(m[1]) > c.bounds.fieldBytes || len(m[4]) == 0 || len(m[4]) > c.bounds.fieldBytes ||
		len(m[3]) != len(core.SystemAccountAddress) || len(m[5]) != len(core.SystemAccountAddress) ||
		len(m[6]) != c.codec.hasher.Size() || len(m[7]) != c.codec.hasher.Size() || len(m[8]) != c.codec.hasher.Size() ||
		len(m[10]) != 8 || len(m[11]) != 8 {
		return errInvalidRegistrationRecord
	}
	dependency, err := c.fields(m[9], 6, c.bounds.bytes)
	if err != nil {
		return err
	}
	if len(dependency[0]) == 0 || len(dependency[0]) > c.bounds.roleBytes ||
		len(dependency[2]) == 0 || len(dependency[2]) > c.bounds.fieldBytes || len(dependency[3]) != 8 ||
		len(dependency[4]) != c.codec.hasher.Size() || len(dependency[5]) != c.codec.hasher.Size() {
		return errInvalidRegistrationRecord
	}
	nb, na := binary.BigEndian.Uint64(m[10]), binary.BigEndian.Uint64(m[11])
	expected, digest, err := c.authorityCertificatePreimage(creation, ctx, purpose, nb, na)
	if err != nil {
		return err
	}
	if !bytes.Equal(envelope[0], expected) {
		return errInvalidRegistrationRecord
	}
	positions, err := c.list(envelope[1], 8)
	if err != nil {
		return err
	}
	signatures, err := c.list(envelope[2], c.bounds.fieldBytes)
	if err != nil || len(positions) != len(signatures) {
		return errInvalidRegistrationRecord
	}
	indices := make([]uint64, len(positions))
	for i, position := range positions {
		if len(position) != 8 {
			return errInvalidRegistrationRecord
		}
		indices[i] = binary.BigEndian.Uint64(position)
	}
	set := ctx.pa
	if purpose == "REGISTER_TOKEN_ADMISSION" {
		set = ctx.admission
	}
	return verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", set.threshold, set.members, indices, signatures, digest,
		uint64(c.bounds.maxMembers), uint64(c.bounds.fieldBytes))
}

// Selected only for the bounded initial-materialization construction. This is
// not an installed endpoint, released ABI, appointment or native-origin proof.
const initialAuthorityInstallTag = "DRWA/INITIAL_PROGRAMME_AUTHORITY_INSTALL/candidate1"

// verifyInitialPossession verifies one E14 envelope using ONLY its G6-derived
// B9 roster. The caller still needs original-genesis authentication, ENROLL,
// actual native creator, lawful support and a stable original operation lease.
func (c *registrationApprovalCodec) verifyInitialPossession(raw, network []byte, appointment *initialAppointment,
	independent bool, at HeaderMilliseconds) error {
	if c == nil || appointment == nil || appointment.admission == nil || appointment.independent == nil ||
		len(network) == 0 || len(network) > c.bounds.fieldBytes {
		return errInvalidRegistrationRecord
	}
	envelope, err := c.fields(raw, 3, c.bounds.bytes)
	if err != nil {
		return err
	}
	m, err := c.fields(envelope[0], 14, c.bounds.fieldBytes)
	if err != nil {
		return err
	}
	body := appointment.admission
	purpose := "INSTALL_INITIAL_ADMISSION"
	if independent {
		body = appointment.independent
		purpose = "INSTALL_INITIAL_REGISTER_TOKEN"
	}
	expected := [][]byte{[]byte(initialAuthorityInstallTag), network, []byte(purpose), appointment.owner, appointment.programme,
		appointment.admission.hash, appointment.independent.hash, appointment.commitment, body.role, body.id, body.version, body.hash}
	for i, want := range expected {
		if !bytes.Equal(m[i], want) {
			return errInvalidRegistrationRecord
		}
	}
	if len(m[12]) != 8 || len(m[13]) != 8 {
		return errInvalidRegistrationRecord
	}
	nb, na := binary.BigEndian.Uint64(m[12]), binary.BigEndian.Uint64(m[13])
	if na < nb || na-nb > c.bounds.maxValidity || uint64(at) < nb || uint64(at) > na {
		return errInvalidRegistrationRecord
	}
	indices, err := c.list(envelope[1], 8)
	if err != nil {
		return err
	}
	signatures, err := c.list(envelope[2], c.bounds.fieldBytes)
	if err != nil {
		return err
	}
	positions := make([]uint64, len(indices))
	for i, index := range indices {
		if len(index) != 8 {
			return errInvalidRegistrationRecord
		}
		positions[i] = binary.BigEndian.Uint64(index)
	}
	digest, err := c.hash(envelope[0])
	if err != nil {
		return err
	}
	return verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", body.threshold, body.members, positions, signatures, digest,
		uint64(c.bounds.maxMembers), uint64(c.bounds.fieldBytes))
}
