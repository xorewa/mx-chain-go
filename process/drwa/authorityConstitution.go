package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
)

// These private Go coordinates select the owner-adopted SP2-27 synthetic
// P01-P17 policy. They are NOT native operation IDs, wire enums or codecs.
// No endpoint/factory installs this construction. Actual canonical readers,
// signing formats, claims, cold members, funding and effect owners retain their
// separate admission gates (A1191-1213, A1617-1645; adopted policy P01-P17).
type scopedAuthorityUse int
type scopedAuthorityPhase int

const (
	scopedIntent scopedAuthorityUse = iota + 1
	scopedRegistration
	scopedActivation
	scopedUnusedIntentCancellation
	scopedAdmissionWithdrawal
	scopedRegisteredCancellation
	scopedCEBChange
	scopedCapIncrease
	scopedRoleRotation
	scopedCEBCancellation
	scopedAdministrativeTransfer
	scopedATCancellation
	scopedRetirement
	scopedRetirementSeal
	scopedRetirementCommit
	scopedTerminalBurn
	scopedEmergencyAdd
	scopedEmergencyRelease
	scopedProviderBinding
	// Unselected cells never inherit an adjacent adopted purpose.
	scopedInitialSuccession
	scopedDecisionWriter
	scopedTechnicalRepair
	scopedScopeAppointment
)

const (
	scopedDirect scopedAuthorityPhase = iota + 1
	scopedPropose
	scopedAuthorize
	scopedStart
	scopedArm
	scopedDrive
	scopedCancel
)

const (
	scopedPA   = "Program Administration Authority"
	scopedPR   = "Program Recovery Authority"
	scopedSA   = "Supply Authority"
	scopedATA  = "Administrative-Transfer Authority"
	scopedEA   = "Emergency Authority"
	scopedIPAA = "programme-scoped Issuer/Program Admission Authority"
	scopedCDA  = "Compliance Decision Authority"
	scopedFCA  = "Financial-Crime Authority"
	scopedIRA  = "Independent Reconciliation Authority"
)

// Sources are private reference selectors, not global version/status flags.
const (
	scopedCurrent = iota
	scopedBound
	scopedProposed
	scopedFrozenProposed
)

type scopedAuthorityRequest struct {
	use                                           scopedAuthorityUse
	phase                                         scopedAuthorityPhase
	purpose                                       string
	locus                                         uint32
	targetShard                                   uint32
	domain, scope, subject, action, owner, digest []byte
}

func (r scopedAuthorityRequest) clone() scopedAuthorityRequest {
	r.domain, r.scope, r.subject = bytes.Clone(r.domain), bytes.Clone(r.scope), bytes.Clone(r.subject)
	r.action, r.owner, r.digest = bytes.Clone(r.action), bytes.Clone(r.owner), bytes.Clone(r.digest)
	return r
}

type scopedAuthoritySet struct {
	id, hash, predecessor                  []byte
	version, predecessorVersion, threshold uint64
	members                                [][]byte
}

type scopedAuthorityRequirement struct {
	role, kind string
	source     int
}

type scopedAuthorityProof struct {
	requirement      scopedAuthorityRequirement
	id, hash         []byte
	version          uint64
	notBefore, until HeaderMilliseconds
	indices          []uint64
	signatures       [][]byte
}

// The reader is a mandatory, read-only owner dependency. It must resolve an
// authenticated immutable view at the exact evaluated native context. Neither
// requester keys nor a default/root/off-chain lookup can supply that view.
// SigningDigest must bind the COMPLETE request, exact role/purpose/reference and
// certificate window using its separately admitted format. No codec is chosen
// here. The real native owner must guard callbacks with its existing T04/read
// boundary and serialize authority checks with the actual effect.
type scopedAuthorityReader interface {
	ReadScopedAuthority(scopedAuthorityRequest) (scopedAuthorityView, error)
	ScopedAuthoritySigningDigest(scopedAuthorityRequest, scopedAuthorityProof) ([]byte, error)
	IsInterfaceNil() bool
}

type scopedAuthorityView struct {
	request                                  scopedAuthorityRequest
	time                                     *HeaderTimeContext
	current, bound, proposed, frozenProposed map[string]scopedAuthoritySet
	plane, status, activation, intent, lrc   string
	highImpact, preToken                     bool
	targetRole, providerRole, claim          string
	lostRoles                                []string
	activeOwner, authorization, frozenPolicy []byte
	irreversibleAdmin, targetCurrent         []byte
	noTargetMutation                         []byte
	permissions                              [][]byte
	nativeAuthentication, nativeIssuerKey    []byte
	window                                   *governedActionWindow
	// R01/R03/R08/R10 are decoded, authenticated reader premises, not native
	// wire forms or defaults. Their real readers remain separately unadmitted.
	scopeAppointment            *scopedAppointmentContext
	nativeActor, issuerIdentity []byte
	memberRule                  scopedProgrammeMemberRule
	reconciliationEnabled       bool
	writer                      *scopedWriterContext
	arm                         *scopedArmContext
}

// Only the exact bound synthetic SP2-03 programme rosters may select this
// R10 choice. A real/stronger/cold profile must supply its own authenticated
// representation and rejection oracle; zero and every other choice deny.
type scopedProgrammeMemberRule int

const scopedSyntheticThresholdOnly scopedProgrammeMemberRule = 1

type scopedAppointmentContext struct {
	owner, scope, domain []byte
	unappointed          bool
}
type scopedWriterContext struct {
	subject, digest, ceb, currentCEB []byte
}
type scopedArmContext struct {
	use                   scopedAuthorityUse
	action, owner, digest []byte
	targetShard           uint32
}

func scopedAppointmentAllowed(r scopedAuthorityRequest, v scopedAuthorityView) bool {
	c := v.scopeAppointment
	if c == nil || len(c.owner) == 0 || !bytes.Equal(c.scope, r.scope) || !bytes.Equal(c.domain, r.domain) ||
		(len(v.issuerIdentity) != 0 && bytes.Equal(c.owner, v.issuerIdentity)) {
		return false
	}
	if r.use == scopedScopeAppointment {
		return v.preToken && c.unappointed && len(v.nativeAuthentication) != 0 && bytes.Equal(v.nativeActor, c.owner)
	}
	if c.unappointed || len(v.issuerIdentity) == 0 {
		return false
	}
	return r.use == scopedActivation || bytes.Equal(v.nativeActor, v.issuerIdentity)
}

func scopedBusinessArmAllowed(r scopedAuthorityRequest, v scopedAuthorityView) bool {
	if r.use != scopedCEBChange && r.use != scopedRoleRotation && r.use != scopedRetirement {
		return false
	}
	c := v.arm
	return c != nil && c.use == r.use && c.targetShard == r.targetShard && r.targetShard != core.MetachainShardId &&
		bytes.Equal(c.action, r.action) && bytes.Equal(c.owner, r.owner) && bytes.Equal(c.digest, r.digest)
}

type scopedAuthorityLimits struct {
	members, proofs, bytes uint64
	lifetime               HeaderMilliseconds
}

// scopedCancellationRoles represents only the adopted CONDITIONAL P09 quorum
// relation. It does not adjudicate a loss/compromise claim. The consuming check
// below rejects nonempty claims while claim-evidence policy remains OPEN.
func scopedCancellationRoles(v scopedAuthorityView) ([]string, error) {
	if v.claim == "" && len(v.lostRoles) == 0 {
		roles := []string{scopedPA, scopedPR}
		if v.highImpact {
			roles = append(roles, scopedATA)
		}
		return roles, nil
	}
	if v.claim != "UNAVAILABLE" && v.claim != "COMPROMISED" {
		return nil, errInvalidAuthoritySignatures
	}
	missing := make(map[string]bool)
	for _, role := range v.lostRoles {
		if missing[role] {
			return nil, errInvalidAuthoritySignatures
		}
		missing[role] = true
	}
	switch {
	case len(missing) == 1 && missing[scopedPA]:
		return []string{scopedPR, scopedSA, scopedATA}, nil
	case len(missing) == 1 && missing[scopedPR]:
		return []string{scopedPA, scopedSA, scopedATA}, nil
	case len(missing) == 2 && missing[scopedPA] && missing[scopedPR]:
		return []string{scopedSA, scopedATA, scopedEA}, nil
	case len(missing) == 1 && missing[scopedATA] && v.highImpact && v.targetRole == scopedATA:
		return []string{scopedPA, scopedPR, scopedSA}, nil
	default:
		return nil, errInvalidAuthoritySignatures
	}
}

func scopedAuthorityPlan(r scopedAuthorityRequest, v scopedAuthorityView) (proofs, bindings []scopedAuthorityRequirement, err error) {
	add := func(role, kind string, source int) {
		bindings = append(bindings, scopedAuthorityRequirement{role, kind, source})
	}
	business := false
	if len(r.action) == 0 || len(r.owner) == 0 {
		return nil, nil, errInvalidAuthoritySignatures
	}
	if r.use != scopedAdministrativeTransfer && r.use != scopedATCancellation && r.use != scopedDecisionWriter && r.purpose != "" {
		return nil, nil, errInvalidAuthoritySignatures
	}
	switch r.use {
	case scopedScopeAppointment:
		if r.phase != scopedDirect || !scopedAppointmentAllowed(r, v) {
			return nil, nil, errInvalidAuthoritySignatures
		}
		add(scopedIPAA, "possession", scopedProposed)
		add(scopedPR, "possession", scopedProposed)
	case scopedIntent, scopedRegistration:
		if r.phase != scopedDirect || v.intent != "OPEN" || len(v.nativeAuthentication) == 0 || len(v.nativeIssuerKey) == 0 || !scopedAppointmentAllowed(r, v) {
			return nil, nil, errInvalidAuthoritySignatures
		}
		add(scopedIPAA, "admission", scopedCurrent)
		add(scopedPR, "approval", scopedCurrent)
		add(scopedPA, "possession", scopedProposed)
	case scopedActivation:
		if r.phase != scopedDirect || v.activation != "BootstrapDeny" || v.intent != "CONSUMED" || !scopedAppointmentAllowed(r, v) {
			return nil, nil, errInvalidAuthoritySignatures
		}
		add(scopedIPAA, "admission", scopedCurrent)
		add(scopedPA, "approval", scopedProposed)
		add(scopedPR, "approval", scopedCurrent)
		if v.highImpact {
			add(scopedATA, "approval", scopedCurrent)
		}
	case scopedUnusedIntentCancellation, scopedAdmissionWithdrawal:
		if r.phase != scopedDirect || r.use == scopedUnusedIntentCancellation && v.intent != "OPEN" {
			return nil, nil, errInvalidAuthoritySignatures
		}
		kind := "withdrawal"
		if r.use == scopedUnusedIntentCancellation {
			kind = "cancellation"
		}
		add(scopedIPAA, kind, scopedCurrent)
	case scopedRegisteredCancellation:
		if r.phase != scopedDirect || v.activation != "BootstrapDeny" || v.intent != "CONSUMED" {
			return nil, nil, errInvalidAuthoritySignatures
		}
		add(scopedPA, "cancellation", scopedProposed)
		add(scopedPR, "cancellation", scopedCurrent)
	case scopedCEBChange, scopedCapIncrease, scopedRoleRotation, scopedRetirement:
		business = true
		add(scopedPA, "approval", scopedCurrent)
		add(scopedPR, "approval", scopedCurrent)
		if v.highImpact {
			add(scopedATA, "approval", scopedCurrent)
		}
		if r.use == scopedCapIncrease {
			add(scopedSA, "cap", scopedCurrent)
		}
		if r.use == scopedRoleRotation {
			if v.targetRole == "" || v.targetRole == scopedIPAA {
				return nil, nil, errInvalidAuthoritySignatures
			}
			add(v.targetRole, "predecessor", scopedCurrent)
			add(v.targetRole, "possession", scopedProposed)
		}
	case scopedCEBCancellation:
		if r.phase != scopedCancel || (v.status != "PROPOSED" && v.status != "EXECUTABLE" && v.status != "IN_PROGRESS") ||
			len(v.frozenPolicy) == 0 || len(v.noTargetMutation) == 0 || len(v.irreversibleAdmin) != 0 || len(v.targetCurrent) != 0 || len(v.permissions) != 0 ||
			(v.status == "IN_PROGRESS" && !bytes.Equal(v.activeOwner, r.owner)) {
			return nil, nil, errInvalidAuthoritySignatures
		}
		roles, e := scopedCancellationRoles(v)
		if e != nil {
			return nil, nil, e
		}
		for _, role := range roles {
			add(role, "cancellation", scopedBound)
		}
	case scopedAdministrativeTransfer, scopedATCancellation:
		if r.purpose != "HOLDER_RECOVERY" && r.purpose != "REDEMPTION" && r.purpose != "EXTERNAL_ORDER" && r.purpose != "PROGRAM_WIND_DOWN" {
			return nil, nil, errInvalidAuthoritySignatures
		}
		if v.lrc == "REQUALIFYING" {
			return nil, nil, errInvalidAuthoritySignatures
		}
		kind := "approval"
		if r.use == scopedATCancellation {
			if r.phase != scopedCancel || v.status != "PROPOSED" {
				return nil, nil, errInvalidAuthoritySignatures
			}
			kind = "cancellation"
		} else {
			business = true
		}
		add(scopedPA, kind, scopedCurrent)
		add(scopedATA, kind, scopedCurrent)
		if r.purpose == "EXTERNAL_ORDER" || r.purpose == "PROGRAM_WIND_DOWN" {
			add(scopedPR, kind, scopedCurrent)
		}
	case scopedRetirementSeal, scopedRetirementCommit, scopedTerminalBurn:
		if r.phase != scopedDirect || v.status != "IN_PROGRESS" || !bytes.Equal(v.activeOwner, r.owner) || len(v.authorization) == 0 {
			return nil, nil, errInvalidAuthoritySignatures
		}
		want := "WIND_DOWN"
		if r.use == scopedRetirementCommit {
			want = "WIND_DOWN_SEALED"
		}
		if v.lrc != want {
			return nil, nil, errInvalidAuthoritySignatures
		}
		add(scopedPA, "request", scopedCurrent)
		if r.use == scopedTerminalBurn {
			add(scopedSA, "burn", scopedCurrent)
		}
	case scopedEmergencyAdd, scopedEmergencyRelease:
		if r.phase != scopedDirect || v.lrc == "WIND_DOWN_SEALED" || v.lrc == "RETIRED" {
			return nil, nil, errInvalidAuthoritySignatures
		}
		if r.use == scopedEmergencyAdd {
			add(scopedEA, "add", scopedCurrent)
		} else {
			add(scopedPA, "release", scopedCurrent)
			add(scopedPR, "release", scopedCurrent)
			if v.highImpact {
				add(scopedATA, "release", scopedCurrent)
			}
		}
	case scopedProviderBinding:
		if v.providerRole == "" {
			return nil, nil, errInvalidAuthoritySignatures
		}
		if v.preToken {
			if r.phase != scopedDirect || len(v.nativeAuthentication) == 0 {
				return nil, nil, errInvalidAuthoritySignatures
			}
			add(scopedIPAA, "delegation", scopedCurrent)
			add(scopedPR, "delegation", scopedCurrent)
		} else {
			business = true
			add(scopedPA, "approval", scopedCurrent)
			add(scopedPR, "approval", scopedCurrent)
			if v.highImpact {
				add(scopedATA, "approval", scopedCurrent)
			}
		}
		add(v.providerRole, "predecessor", scopedCurrent)
		add(v.providerRole, "possession", scopedProposed)
	case scopedDecisionWriter:
		c := v.writer
		if r.phase != scopedDirect || c == nil || !bytes.Equal(c.subject, r.subject) || !bytes.Equal(c.digest, r.digest) ||
			len(c.ceb) == 0 || !bytes.Equal(c.ceb, c.currentCEB) ||
			(r.purpose != scopedCDA && r.purpose != scopedFCA && !(r.purpose == scopedIRA && v.reconciliationEnabled)) {
			return nil, nil, errInvalidAuthoritySignatures
		}
		add(scopedCDA, "writer", scopedCurrent)
		add(scopedFCA, "writer", scopedCurrent)
		if v.reconciliationEnabled {
			add(scopedIRA, "writer", scopedCurrent)
		}
		return []scopedAuthorityRequirement{{r.purpose, "writer", scopedCurrent}}, bindings, nil
	default:
		return nil, nil, errInvalidAuthoritySignatures
	}
	proofs = append(proofs, bindings...)
	if !business {
		return proofs, bindings, nil
	}
	switch r.phase {
	case scopedPropose:
		proofs = []scopedAuthorityRequirement{{scopedPA, "proposal", scopedCurrent}}
	case scopedAuthorize:
		// Existing GAS also revalidates an exact EXECUTABLE authorization as
		// an idempotent no-write call (governedActionRecords.go transition).
		if v.status != "PROPOSED" && v.status != "EXECUTABLE" {
			return nil, nil, errInvalidAuthoritySignatures
		}
	case scopedStart, scopedArm:
		if v.status != "EXECUTABLE" || len(v.authorization) == 0 ||
			(len(v.activeOwner) != 0 && !bytes.Equal(v.activeOwner, r.owner)) ||
			(r.phase == scopedStart && r.use == scopedAdministrativeTransfer) ||
			(r.phase == scopedArm && r.use != scopedAdministrativeTransfer && !scopedBusinessArmAllowed(r, v)) {
			return nil, nil, errInvalidAuthoritySignatures
		}
		kind := "start"
		if r.phase == scopedArm {
			kind = "arm"
		}
		proofs = []scopedAuthorityRequirement{{scopedPA, kind, scopedCurrent}}
	case scopedDrive:
		if v.status != "IN_PROGRESS" || len(v.authorization) == 0 || !bytes.Equal(v.activeOwner, r.owner) {
			return nil, nil, errInvalidAuthoritySignatures
		}
		proofs = nil
		for i := range bindings {
			if bindings[i].source == scopedProposed {
				bindings[i].source = scopedFrozenProposed
			} else {
				bindings[i].source = scopedBound
			}
		}
	default:
		return nil, nil, errInvalidAuthoritySignatures
	}
	return proofs, bindings, nil
}

func scopedAuthorityReference(v scopedAuthorityView, r scopedAuthorityRequirement) (scopedAuthoritySet, bool) {
	switch r.source {
	case scopedCurrent:
		s, ok := v.current[r.role]
		return s, ok
	case scopedBound:
		s, ok := v.bound[r.role]
		return s, ok
	case scopedProposed:
		s, ok := v.proposed[r.role]
		return s, ok
	case scopedFrozenProposed:
		s, ok := v.frozenProposed[r.role]
		return s, ok
	default:
		return scopedAuthoritySet{}, false
	}
}

// verifyScopedAuthority consumes the adopted purpose/phase policy and native
// threshold proofs. A nil result proves ONLY that scoped check in the supplied
// trusted view. It is not native effect admission, canonical evidence, claim
// eligibility, funding, accounting, cancellation serialization or a state write.
// No claim, real mandatory-member condition or technical cell gets a default.
func verifyScopedAuthority(reader scopedAuthorityReader, request scopedAuthorityRequest, proofs []scopedAuthorityProof, limits scopedAuthorityLimits) error {
	if check.IfNil(reader) || limits.members == 0 || limits.proofs == 0 || limits.bytes == 0 || limits.lifetime == 0 || uint64(len(proofs)) > limits.proofs {
		return errInvalidAuthoritySignatures
	}
	remaining := limits.bytes
	for _, field := range [][]byte{request.domain, request.scope, request.subject, request.action, request.owner, request.digest, []byte(request.purpose)} {
		if uint64(len(field)) > remaining {
			return errInvalidAuthoritySignatures
		}
		remaining -= uint64(len(field))
	}
	if len(request.domain) == 0 || len(request.scope) == 0 || len(request.subject) == 0 || len(request.digest) == 0 {
		return errInvalidAuthoritySignatures
	}
	r := request.clone()
	v, err := reader.ReadScopedAuthority(r.clone())
	if err != nil {
		return err
	}
	e := v.request
	if r.use != e.use || r.phase != e.phase || r.purpose != e.purpose || r.locus != e.locus || r.targetShard != e.targetShard ||
		!bytes.Equal(r.domain, e.domain) || !bytes.Equal(r.scope, e.scope) || !bytes.Equal(r.subject, e.subject) ||
		!bytes.Equal(r.action, e.action) || !bytes.Equal(r.owner, e.owner) || !bytes.Equal(r.digest, e.digest) || v.plane != "NORMAL" ||
		v.claim != "" || len(v.lostRoles) != 0 || v.time == nil || v.memberRule != scopedSyntheticThresholdOnly {
		return errInvalidAuthoritySignatures
	}
	_, locus := v.time.HeaderIdentity()
	if locus != r.locus {
		return errInvalidAuthoritySignatures
	}
	required, bindings, err := scopedAuthorityPlan(r, v)
	if err != nil {
		return err
	}
	if r.phase == scopedAuthorize || r.phase == scopedStart || r.phase == scopedArm {
		if err = v.window.mayStart(v.time); err != nil {
			return err
		}
	}
	// mayStart takes its own lease. Acquire our lasting lease afterwards:
	// recursively taking an RWMutex read lock can deadlock behind Reset.
	// The same still-active capability necessarily has the same time coordinate.
	at, _, release, err := v.time.Lease()
	if err != nil {
		return err
	}
	defer release()
	if len(proofs) != len(required) {
		return errInvalidAuthoritySignatures
	}
	// Resolve the complete class bundle even when the phase needs only PA's
	// proposal/start/arm proof. Merely EXECUTABLE work cannot grandfather keys.
	for i, binding := range bindings {
		s, ok := scopedAuthorityReference(v, binding)
		if !ok || len(s.id) == 0 || len(s.hash) == 0 || uint64(len(s.members)) > limits.members || validateProgrammeAuthorityThreshold(uint64(len(s.members)), s.threshold) != nil {
			return errInvalidAuthoritySignatures
		}
		if r.phase == scopedAuthorize || r.phase == scopedStart || r.phase == scopedArm || r.use == scopedCEBCancellation {
			old, exists := v.bound[binding.role]
			if binding.source == scopedBound {
				old, exists = v.current[binding.role]
			}
			if binding.source != scopedProposed && (!exists || old.version != s.version || !bytes.Equal(old.id, s.id) || !bytes.Equal(old.hash, s.hash)) {
				return errInvalidAuthoritySignatures
			}
		}
		if binding.source == scopedProposed && binding.kind == "possession" && (r.use == scopedRoleRotation || r.use == scopedProviderBinding) {
			old, exists := v.current[binding.role]
			if !exists || !bytes.Equal(old.id, s.id) || s.version <= old.version || !bytes.Equal(s.predecessor, old.hash) || s.predecessorVersion != old.version || bytes.Equal(s.hash, old.hash) {
				return errInvalidAuthoritySignatures
			}
		}
		for _, other := range bindings[:i] {
			if binding.role == other.role {
				continue
			} // same role/purposes count once
			peer, _ := scopedAuthorityReference(v, other)
			if validateProgrammeAuthorityIndependentPair(s.id, peer.id, s.members, peer.members) != nil {
				return errInvalidAuthoritySignatures
			}
		}
		if (r.use == scopedIntent || r.use == scopedRegistration) && binding.role == scopedIPAA {
			for _, key := range s.members {
				if bytes.Equal(key, v.nativeIssuerKey) {
					return errInvalidAuthoritySignatures
				}
			}
		}
	}
	seen := make(map[scopedAuthorityRequirement]bool)
	for _, proof := range proofs {
		found := false
		for _, want := range required {
			found = found || proof.requirement == want
		}
		if !found || seen[proof.requirement] {
			return errInvalidAuthoritySignatures
		}
		seen[proof.requirement] = true
		s, ok := scopedAuthorityReference(v, proof.requirement)
		if !ok || proof.version != s.version || !bytes.Equal(proof.id, s.id) || !bytes.Equal(proof.hash, s.hash) ||
			proof.until < proof.notBefore || proof.until-proof.notBefore > limits.lifetime || at < proof.notBefore || at > proof.until {
			return errInvalidAuthoritySignatures
		}
		metadata := proof
		metadata.id, metadata.hash = bytes.Clone(proof.id), bytes.Clone(proof.hash)
		metadata.indices, metadata.signatures = nil, nil
		digest, digestErr := reader.ScopedAuthoritySigningDigest(r.clone(), metadata)
		if digestErr != nil {
			return digestErr
		}
		if err = verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", s.threshold, s.members, proof.indices, proof.signatures, bytes.Clone(digest), limits.members, limits.bytes); err != nil {
			return err
		}
	}
	return nil
}
