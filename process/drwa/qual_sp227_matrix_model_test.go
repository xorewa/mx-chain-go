package drwa

import (
	"bytes"
	"fmt"
	"sort"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

// SP2-27 independent counting. This file holds a second model of the adopted
// synthetic constitution, written from the policy rows (P01-P17 and the P09
// alternatives of the 4 November ruling; R01, R03, R08 and R10 of the 5 November
// ruling; the owner's answers of 27 November to points A-1, D-03 and D-04 and of
// 28 November to point 9c) and
// from Part A section 3.3-3.4. It calls no production selector. A
// case is described symbolically; one function turns the symbols into the
// decoded view the production check reads, another computes the expected
// result. Every test below compares the two for every cell it enumerates.

type qualSP227Case struct {
	use     scopedAuthorityUse
	phase   scopedAuthorityPhase
	purpose string
	high    bool
	// token and action state as the reader reports it
	preToken, reconciliation        bool
	status, lrc, intent, activation string
	// request body
	noAction, noOwner bool
	// governed action
	noAuthorization bool
	activeOwner     string // "self", "other", ""
	// cancellation premises
	noFrozenPolicy, noTargetEvidence, adminCut, currentCut, openPermission bool
	claim                                                                  string
	lost                                                                   []string
	// synthetic claim premise (answer A-1): "" none, "ok" names exactly this
	// claim, these lost roles, this request and the frozen policy; any other
	// value names the one thing it gets wrong
	evidence string
	// native authentication and scope
	noNativeAuth, noIssuerKey bool
	scopeBinding              string // "ok", "none", "no_owner", "scope", "domain"
	notYetAppointed           bool
	issuer                    string // "I" a named issuer, "O" the scope owner itself, "" unnamed
	actor                     string // "O" scope owner, "I" the named issuer, "X" somebody else
	// writer, arm, rotation and provider context
	writer      string // "ok", "none", "subject", "digest", "no_ceb", "stale"
	arm         string // "", "ok", "class", "action", "owner", "digest", "shard"
	metaTarget  bool
	targetRole  string
	provider    string
	plane       string
	memberRule  scopedProgrammeMemberRule
	evaluatedAt uint64 // 0 means no time context
	noWindow    bool
}

type qualSP227Expected struct {
	admit            bool
	proofs, bindings []scopedAuthorityRequirement
}

const (
	qualSP227Owner  = "native programme scope owner"
	qualSP227Issuer = "native issuer account"
	qualSP227Other  = "unrelated native account"
)

var (
	qualSP227ATPurposes = []string{"HOLDER_RECOVERY", "REDEMPTION", "EXTERNAL_ORDER", "PROGRAM_WIND_DOWN"}
	qualSP227AllUses    = []scopedAuthorityUse{0, scopedIntent, scopedRegistration, scopedActivation, scopedUnusedIntentCancellation,
		scopedAdmissionWithdrawal, scopedRegisteredCancellation, scopedCEBChange, scopedCapIncrease, scopedRoleRotation, scopedCEBCancellation,
		scopedAdministrativeTransfer, scopedATCancellation, scopedRetirement, scopedRetirementSeal, scopedRetirementCommit, scopedTerminalBurn,
		scopedEmergencyAdd, scopedEmergencyRelease, scopedProviderBinding, scopedInitialSuccession, scopedDecisionWriter, scopedTechnicalRepair,
		scopedScopeAppointment, scopedScopeAppointment + 1}
	qualSP227AllPhases   = []scopedAuthorityPhase{0, scopedDirect, scopedPropose, scopedAuthorize, scopedStart, scopedArm, scopedDrive, scopedCancel, scopedCancel + 1}
	qualSP227AllPurposes = []string{"", "HOLDER_RECOVERY", "REDEMPTION", "EXTERNAL_ORDER", "PROGRAM_WIND_DOWN", scopedCDA, scopedFCA, scopedIRA, "OTHER"}
	qualSP227Statuses    = []string{"PROPOSED", "EXECUTABLE", "IN_PROGRESS", "EXECUTED", "CANCELLED", "EXPIRED"}
	qualSP227Lifecycles  = []string{"ACTIVE", "REQUALIFYING", "WIND_DOWN", "WIND_DOWN_SEALED", "RETIRED"}
	qualSP227Intents     = []string{"OPEN", "CONSUMED", "CANCELLED"}
	qualSP227Activations = []string{"BootstrapDeny", "ACTIVE"}
)

func qualSP227Need(role, kind string, source int) scopedAuthorityRequirement {
	return scopedAuthorityRequirement{role, kind, source}
}

// qualSP227Coalition is the P09 section 3 table: the roles that may approve a
// pre-cutoff cancellation for each admitted loss case. False means "no
// alternative configured" (truthful pending).
func qualSP227Coalition(claim string, lost []string, high bool, target string) ([]string, bool) {
	if claim == "" && len(lost) == 0 {
		if high {
			return []string{scopedPA, scopedPR, scopedATA}, true
		}
		return []string{scopedPA, scopedPR}, true
	}
	if claim != "UNAVAILABLE" && claim != "COMPROMISED" {
		return nil, false // dissent, silence or an unnamed reason is not a loss claim
	}
	named := map[string]int{}
	for _, role := range lost {
		named[role]++
		if named[role] > 1 {
			return nil, false
		}
	}
	gone := func(roles ...string) bool {
		if len(named) != len(roles) {
			return false
		}
		for _, role := range roles {
			if named[role] != 1 {
				return false
			}
		}
		return true
	}
	switch {
	case gone(scopedPA):
		return []string{scopedPR, scopedSA, scopedATA}, true
	case gone(scopedPR):
		return []string{scopedPA, scopedSA, scopedATA}, true
	case gone(scopedPA, scopedPR):
		return []string{scopedSA, scopedATA, scopedEA}, true
	case gone(scopedATA) && high && target == scopedATA:
		return []string{scopedPA, scopedPR, scopedSA}, true
	}
	return nil, false
}

// qualSP227Model returns what the adopted rows require for one case, before
// the checks that belong to the verifier (plane, claim admission, member rule,
// time and the authority sets themselves).
func qualSP227Model(c qualSP227Case) qualSP227Expected {
	deny := qualSP227Expected{}
	need := qualSP227Need
	cur := func(role, kind string) scopedAuthorityRequirement { return need(role, kind, scopedCurrent) }
	if c.noAction || c.noOwner {
		return deny
	}
	purposeBearing := c.use == scopedAdministrativeTransfer || c.use == scopedATCancellation || c.use == scopedDecisionWriter
	if !purposeBearing && c.purpose != "" {
		return deny
	}
	// R01: who the scope owner is, and who acts.
	scopeOwner := qualSP227Owner
	if c.scopeBinding == "no_owner" {
		scopeOwner = ""
	}
	scopeKnown := c.scopeBinding == "ok" && scopeOwner != ""
	issuer := map[string]string{"I": qualSP227Issuer, "O": qualSP227Owner, "": ""}[c.issuer]
	actor := map[string]string{"O": qualSP227Owner, "I": issuer, "X": qualSP227Other}[c.actor]
	ownerIsNotIssuer := issuer == "" || issuer != scopeOwner
	appointedScope := scopeKnown && ownerIsNotIssuer && !c.notYetAppointed && issuer != ""
	direct := func(proofs ...scopedAuthorityRequirement) qualSP227Expected {
		if c.phase != scopedDirect {
			return deny
		}
		return qualSP227Expected{true, proofs, proofs}
	}
	floor := func(kind string) []scopedAuthorityRequirement { // P06 two roles, P07 three
		out := []scopedAuthorityRequirement{cur(scopedPA, kind), cur(scopedPR, kind)}
		if c.high {
			out = append(out, cur(scopedATA, kind))
		}
		return out
	}
	var bundle []scopedAuthorityRequirement // class authorisation of a governed action
	switch c.use {
	case scopedScopeAppointment: // R01 first appointment
		if !(scopeKnown && ownerIsNotIssuer && c.preToken && c.notYetAppointed && !c.noNativeAuth && actor == scopeOwner) {
			return deny
		}
		return direct(need(scopedIPAA, "possession", scopedProposed), need(scopedPR, "possession", scopedProposed))
	case scopedIntent, scopedRegistration: // P01
		if c.intent != "OPEN" || c.noNativeAuth || c.noIssuerKey || !appointedScope || actor != issuer {
			return deny
		}
		return direct(cur(scopedIPAA, "admission"), cur(scopedPR, "approval"), need(scopedPA, "possession", scopedProposed))
	case scopedActivation: // P02
		if c.activation != "BootstrapDeny" || c.intent != "CONSUMED" || !appointedScope {
			return deny
		}
		proofs := []scopedAuthorityRequirement{cur(scopedIPAA, "admission"), need(scopedPA, "approval", scopedProposed), cur(scopedPR, "approval")}
		if c.high {
			proofs = append(proofs, cur(scopedATA, "approval"))
		}
		return direct(proofs...)
	case scopedUnusedIntentCancellation: // P03
		if c.intent != "OPEN" {
			return deny
		}
		return direct(cur(scopedIPAA, "cancellation"))
	case scopedAdmissionWithdrawal: // P04
		return direct(cur(scopedIPAA, "withdrawal"))
	case scopedRegisteredCancellation: // P05
		if c.activation != "BootstrapDeny" || c.intent != "CONSUMED" {
			return deny
		}
		return direct(need(scopedPA, "cancellation", scopedProposed), cur(scopedPR, "cancellation"))
	case scopedCEBChange, scopedRetirement: // P06, P07, P12
		bundle = floor("approval")
	case scopedCapIncrease: // P08
		bundle = append(floor("approval"), cur(scopedSA, "cap"))
	case scopedRoleRotation: // P06 normal rotation
		if c.targetRole == "" || c.targetRole == scopedIPAA {
			return deny
		}
		bundle = append(floor("approval"), cur(c.targetRole, "predecessor"), need(c.targetRole, "possession", scopedProposed))
	case scopedCEBCancellation: // P09
		started := c.status == "IN_PROGRESS"
		if c.phase != scopedCancel || (c.status != "PROPOSED" && c.status != "EXECUTABLE" && !started) ||
			c.noFrozenPolicy || c.noTargetEvidence || c.adminCut || c.currentCut || c.openPermission || (started && c.activeOwner != "self") {
			return deny
		}
		roles, configured := qualSP227Coalition(c.claim, c.lost, c.high, c.targetRole)
		if !configured {
			return deny
		}
		var proofs []scopedAuthorityRequirement
		for _, role := range roles {
			proofs = append(proofs, need(role, "cancellation", scopedBound))
		}
		return qualSP227Expected{true, proofs, proofs}
	case scopedAdministrativeTransfer, scopedATCancellation: // P10, P11
		three := c.purpose == "EXTERNAL_ORDER" || c.purpose == "PROGRAM_WIND_DOWN"
		if !three && c.purpose != "HOLDER_RECOVERY" && c.purpose != "REDEMPTION" {
			return deny
		}
		if c.lrc == "REQUALIFYING" {
			return deny
		}
		kind := "approval"
		if c.use == scopedATCancellation {
			kind = "cancellation"
		}
		roles := []scopedAuthorityRequirement{cur(scopedPA, kind), cur(scopedATA, kind)}
		if three {
			roles = append(roles, cur(scopedPR, kind))
		}
		if c.use == scopedATCancellation {
			if c.phase != scopedCancel || c.status != "PROPOSED" {
				return deny
			}
			return qualSP227Expected{true, roles, roles}
		}
		bundle = roles
	case scopedRetirementSeal, scopedRetirementCommit, scopedTerminalBurn: // P13
		stage := "WIND_DOWN"
		if c.use == scopedRetirementCommit {
			stage = "WIND_DOWN_SEALED"
		}
		if c.status != "IN_PROGRESS" || c.activeOwner != "self" || c.noAuthorization || c.lrc != stage {
			return deny
		}
		if c.use == scopedTerminalBurn {
			return direct(cur(scopedPA, "request"), cur(scopedSA, "burn"))
		}
		return direct(cur(scopedPA, "request"))
	case scopedEmergencyAdd, scopedEmergencyRelease: // P14, P15
		if c.lrc == "WIND_DOWN_SEALED" || c.lrc == "RETIRED" {
			return deny
		}
		if c.use == scopedEmergencyAdd {
			return direct(cur(scopedEA, "add"))
		}
		return direct(floor("release")...)
	case scopedProviderBinding: // P17
		if c.provider == "" {
			return deny
		}
		lineage := []scopedAuthorityRequirement{cur(c.provider, "predecessor"), need(c.provider, "possession", scopedProposed)}
		if c.preToken {
			if c.noNativeAuth || !scopeKnown || c.notYetAppointed || actor != scopeOwner {
				return deny
			}
			return direct(append([]scopedAuthorityRequirement{cur(scopedIPAA, "delegation"), cur(scopedPR, "delegation")}, lineage...)...)
		}
		bundle = append(floor("approval"), lineage...)
	case scopedDecisionWriter: // R03
		enabled := c.purpose == scopedCDA || c.purpose == scopedFCA || (c.purpose == scopedIRA && c.reconciliation)
		if c.phase != scopedDirect || c.writer != "ok" || !enabled {
			return deny
		}
		pairs := []scopedAuthorityRequirement{cur(scopedCDA, "writer"), cur(scopedFCA, "writer")}
		if c.reconciliation {
			pairs = append(pairs, cur(scopedIRA, "writer"))
		}
		return qualSP227Expected{true, []scopedAuthorityRequirement{cur(c.purpose, "writer")}, pairs}
	default: // C02 succession, technical cells and unknown selectors have no adopted row
		return deny
	}
	// P16 and R08: phases of a governed business action. P16 names P06, P07
	// and P12 (P17 sends operational provider changes to P06/P07). P08 and P10
	// state the approving roles and, for P10, the PA arm; nothing else. Answer
	// D-04 of 27 November refused the phases no adopted row states. The owner
	// then admitted the five cells (entry 9, point 9c, 28 November): PA
	// proposal, PA start and unsigned drive of a cap increase; PA proposal and
	// unsigned drive of an administrative transfer. They follow P16's wording.
	// Still refused: the start of a transfer (it is armed) and the arm of a
	// cap increase.
	shardExecuted := c.use == scopedAdministrativeTransfer
	startable := c.status == "EXECUTABLE" && !c.noAuthorization && (c.activeOwner == "" || c.activeOwner == "self")
	switch c.phase {
	case scopedPropose:
		return qualSP227Expected{true, []scopedAuthorityRequirement{cur(scopedPA, "proposal")}, bundle}
	case scopedAuthorize:
		if c.status != "PROPOSED" && c.status != "EXECUTABLE" {
			return deny
		}
		return qualSP227Expected{true, bundle, bundle}
	case scopedStart:
		if !startable || shardExecuted {
			return deny
		}
		return qualSP227Expected{true, []scopedAuthorityRequirement{cur(scopedPA, "start")}, bundle}
	case scopedArm:
		shardFirst := (c.use == scopedCEBChange || c.use == scopedRoleRotation || c.use == scopedRetirement) && c.arm == "ok" && !c.metaTarget
		if !startable || !(shardExecuted || shardFirst) {
			return deny
		}
		return qualSP227Expected{true, []scopedAuthorityRequirement{cur(scopedPA, "arm")}, bundle}
	case scopedDrive:
		if c.status != "IN_PROGRESS" || c.noAuthorization || c.activeOwner != "self" {
			return deny
		}
		frozen := make([]scopedAuthorityRequirement, len(bundle))
		for i, b := range bundle {
			frozen[i] = need(b.role, b.kind, scopedBound)
			if b.source == scopedProposed {
				frozen[i].source = scopedFrozenProposed
			}
		}
		return qualSP227Expected{true, nil, frozen}
	}
	return deny
}

// qualSP227ModelVerified adds what the verifier itself must refuse.
func qualSP227ModelVerified(c qualSP227Case) qualSP227Expected {
	e := qualSP227Model(c)
	timed := c.phase == scopedAuthorize || c.phase == scopedStart || c.phase == scopedArm
	// Answer A-1: a loss or compromise claim counts only for the P09
	// cancellation and only with the synthetic premise that names it exactly.
	claimed := c.claim != "" || len(c.lost) != 0 || c.evidence != ""
	premise := c.use == scopedCEBCancellation && c.evidence == "ok" && (c.claim == "UNAVAILABLE" || c.claim == "COMPROMISED") && len(c.lost) != 0 && !c.noFrozenPolicy
	switch {
	case c.plane != "NORMAL", claimed && !premise, c.memberRule != scopedSyntheticThresholdOnly, c.evaluatedAt == 0:
		return qualSP227Expected{}
	case e.admit && timed && (c.noWindow || c.evaluatedAt < 105 || c.evaluatedAt >= 120): // GAS start window, upper end exclusive
		return qualSP227Expected{}
	case e.admit && len(e.proofs) != 0 && (c.evaluatedAt < 100 || c.evaluatedAt > 120): // certificate window, inclusive
		return qualSP227Expected{}
	}
	return e
}

// qualSP227Healthy is the positive scenario of the row a case belongs to.
func qualSP227Healthy(use scopedAuthorityUse, phase scopedAuthorityPhase, purpose string, high, preToken, reconciliation bool) qualSP227Case {
	c := qualSP227Case{use: use, phase: phase, purpose: purpose, high: high, preToken: preToken, reconciliation: reconciliation,
		status: "PROPOSED", lrc: "ACTIVE", intent: "OPEN", activation: "BootstrapDeny", activeOwner: "self",
		scopeBinding: "ok", issuer: "I", actor: "I", writer: "ok", targetRole: scopedSA, provider: scopedSA,
		plane: "NORMAL", memberRule: scopedSyntheticThresholdOnly, evaluatedAt: 110}
	switch use {
	case scopedScopeAppointment:
		c.notYetAppointed, c.actor = true, "O"
	case scopedProviderBinding:
		if preToken {
			c.actor = "O"
		}
	case scopedActivation, scopedRegisteredCancellation:
		c.intent = "CONSUMED"
	case scopedRetirementSeal, scopedTerminalBurn:
		c.status, c.lrc = "IN_PROGRESS", "WIND_DOWN"
	case scopedRetirementCommit:
		c.status, c.lrc = "IN_PROGRESS", "WIND_DOWN_SEALED"
	}
	switch phase {
	case scopedStart:
		c.status = "EXECUTABLE"
	case scopedArm:
		c.status, c.arm = "EXECUTABLE", "ok"
	case scopedDrive:
		c.status = "IN_PROGRESS"
	}
	return c
}

// qualSP227Configurations lists every (use, phase, purpose, high-impact,
// pre-token, reconciliation) combination, each in its healthy scenario.
func qualSP227Configurations() []qualSP227Case {
	var out []qualSP227Case
	for _, use := range qualSP227AllUses {
		for _, phase := range qualSP227AllPhases {
			for _, purpose := range qualSP227AllPurposes {
				for _, flags := range [][3]bool{{}, {true}, {false, true}, {true, true}, {false, false, true}, {true, false, true}, {false, true, true}, {true, true, true}} {
					out = append(out, qualSP227Healthy(use, phase, purpose, flags[0], flags[1], flags[2]))
				}
			}
		}
	}
	return out
}

type qualSP227Fault struct {
	name  string
	apply func(*qualSP227Case)
}

func qualSP227PlanFaults() []qualSP227Fault {
	f := func(name string, apply func(*qualSP227Case)) qualSP227Fault { return qualSP227Fault{name, apply} }
	out := []qualSP227Fault{
		f("no_action", func(c *qualSP227Case) { c.noAction = true }),
		f("no_owner", func(c *qualSP227Case) { c.noOwner = true }),
		f("no_authorization", func(c *qualSP227Case) { c.noAuthorization = true }),
		f("other_active_owner", func(c *qualSP227Case) { c.activeOwner = "other" }),
		f("no_active_owner", func(c *qualSP227Case) { c.activeOwner = "" }),
		f("no_frozen_policy", func(c *qualSP227Case) { c.noFrozenPolicy = true }),
		f("no_target_evidence", func(c *qualSP227Case) { c.noTargetEvidence = true }),
		f("admin_cutoff_reached", func(c *qualSP227Case) { c.adminCut = true }),
		f("current_cutoff_reached", func(c *qualSP227Case) { c.currentCut = true }),
		f("open_permission", func(c *qualSP227Case) { c.openPermission = true }),
		f("no_native_authentication", func(c *qualSP227Case) { c.noNativeAuth = true }),
		f("no_issuer_key", func(c *qualSP227Case) { c.noIssuerKey = true }),
		f("no_scope_binding", func(c *qualSP227Case) { c.scopeBinding = "none" }),
		f("scope_binding_without_owner", func(c *qualSP227Case) { c.scopeBinding = "no_owner" }),
		f("foreign_scope", func(c *qualSP227Case) { c.scopeBinding = "scope" }),
		f("foreign_domain", func(c *qualSP227Case) { c.scopeBinding = "domain" }),
		f("appointment_state_flipped", func(c *qualSP227Case) { c.notYetAppointed = !c.notYetAppointed }),
		f("issuer_is_scope_owner", func(c *qualSP227Case) { c.issuer = "O" }),
		f("issuer_unnamed", func(c *qualSP227Case) { c.issuer = "" }),
		f("actor_scope_owner", func(c *qualSP227Case) { c.actor = "O" }),
		f("actor_issuer", func(c *qualSP227Case) { c.actor = "I" }),
		f("actor_unrelated", func(c *qualSP227Case) { c.actor = "X" }),
		f("no_writer_context", func(c *qualSP227Case) { c.writer = "none" }),
		f("writer_foreign_subject", func(c *qualSP227Case) { c.writer = "subject" }),
		f("writer_foreign_body", func(c *qualSP227Case) { c.writer = "digest" }),
		f("writer_no_ceb", func(c *qualSP227Case) { c.writer = "no_ceb" }),
		f("writer_stale_ceb", func(c *qualSP227Case) { c.writer = "stale" }),
		f("no_arm_context", func(c *qualSP227Case) { c.arm = "" }),
		f("arm_context_present", func(c *qualSP227Case) { c.arm = "ok" }),
		f("arm_other_class", func(c *qualSP227Case) { c.arm = "class" }),
		f("arm_other_action", func(c *qualSP227Case) { c.arm = "action" }),
		f("arm_other_owner", func(c *qualSP227Case) { c.arm = "owner" }),
		f("arm_other_body", func(c *qualSP227Case) { c.arm = "digest" }),
		f("arm_other_shard", func(c *qualSP227Case) { c.arm = "shard" }),
		f("arm_metachain_target", func(c *qualSP227Case) { c.metaTarget = true }),
		f("no_rotation_target", func(c *qualSP227Case) { c.targetRole = "" }),
		f("rotation_target_admission_authority", func(c *qualSP227Case) { c.targetRole = scopedIPAA }),
		f("no_provider_role", func(c *qualSP227Case) { c.provider = "" }),
		f("high_impact_flipped", func(c *qualSP227Case) { c.high = !c.high }),
		f("pre_token_flipped", func(c *qualSP227Case) { c.preToken = !c.preToken }),
		f("reconciliation_flipped", func(c *qualSP227Case) { c.reconciliation = !c.reconciliation }),
	}
	for _, v := range qualSP227Statuses {
		out = append(out, f("status_"+v, func(c *qualSP227Case) { c.status = v }))
	}
	for _, v := range qualSP227Lifecycles {
		out = append(out, f("lifecycle_"+v, func(c *qualSP227Case) { c.lrc = v }))
	}
	for _, v := range qualSP227Intents {
		out = append(out, f("intent_"+v, func(c *qualSP227Case) { c.intent = v }))
	}
	for _, v := range qualSP227Activations {
		out = append(out, f("activation_"+v, func(c *qualSP227Case) { c.activation = v }))
	}
	for _, v := range qualSP227AllPurposes {
		out = append(out, f("purpose_"+v, func(c *qualSP227Case) { c.purpose = v }))
	}
	for _, v := range qualSP227AllPhases {
		out = append(out, f(fmt.Sprintf("phase_%d", v), func(c *qualSP227Case) { c.phase = v }))
	}
	return out
}

func qualSP227VerifierFaults() []qualSP227Fault {
	f := func(name string, apply func(*qualSP227Case)) qualSP227Fault { return qualSP227Fault{name, apply} }
	return []qualSP227Fault{
		f("plane_FAIL_SAFE", func(c *qualSP227Case) { c.plane = "FAIL_SAFE" }),
		f("plane_unknown", func(c *qualSP227Case) { c.plane = "" }),
		f("claim_unavailable", func(c *qualSP227Case) { c.claim = "UNAVAILABLE" }),
		f("claim_compromised", func(c *qualSP227Case) { c.claim = "COMPROMISED" }),
		f("claim_dissent", func(c *qualSP227Case) { c.claim = "DISSENT" }),
		f("lost_PA_without_claim", func(c *qualSP227Case) { c.lost = []string{scopedPA} }),
		f("synthetic_premise_without_claim", func(c *qualSP227Case) { c.evidence = "ok" }),
		f("lost_PA_with_synthetic_premise", func(c *qualSP227Case) { c.claim, c.lost, c.evidence = "UNAVAILABLE", []string{scopedPA}, "ok" }),
		f("compromised_PR_with_synthetic_premise", func(c *qualSP227Case) { c.claim, c.lost, c.evidence = "COMPROMISED", []string{scopedPR}, "ok" }),
		f("dissent_with_synthetic_premise", func(c *qualSP227Case) { c.claim, c.lost, c.evidence = "DISSENT", []string{scopedPA}, "ok" }),
		f("lost_SA_with_synthetic_premise", func(c *qualSP227Case) { c.claim, c.lost, c.evidence = "UNAVAILABLE", []string{scopedSA}, "ok" }),
		f("lost_PA_premise_for_another_action", func(c *qualSP227Case) { c.claim, c.lost, c.evidence = "UNAVAILABLE", []string{scopedPA}, "action" }),
		f("member_rule_missing", func(c *qualSP227Case) { c.memberRule = 0 }),
		f("member_rule_stronger", func(c *qualSP227Case) { c.memberRule = 2 }),
		f("no_time_context", func(c *qualSP227Case) { c.evaluatedAt = 0 }),
		f("no_start_window", func(c *qualSP227Case) { c.noWindow = true }),
		f("time_99", func(c *qualSP227Case) { c.evaluatedAt = 99 }),
		f("time_100", func(c *qualSP227Case) { c.evaluatedAt = 100 }),
		f("time_104", func(c *qualSP227Case) { c.evaluatedAt = 104 }),
		f("time_105", func(c *qualSP227Case) { c.evaluatedAt = 105 }),
		f("time_119", func(c *qualSP227Case) { c.evaluatedAt = 119 }),
		f("time_120", func(c *qualSP227Case) { c.evaluatedAt = 120 }),
		f("time_121", func(c *qualSP227Case) { c.evaluatedAt = 121 }),
	}
}

// qualSP227Request and qualSP227View translate the symbols of a case into the
// decoded inputs of the production check. They hold no policy.
func qualSP227Request(c qualSP227Case, scope string) scopedAuthorityRequest {
	r := scopedAuthorityRequest{use: c.use, phase: c.phase, purpose: c.purpose, locus: core.MetachainShardId, targetShard: 1,
		domain: []byte("W03 constitution experiment"), scope: []byte(scope), subject: []byte("program-subject"),
		action: []byte("exact immutable action"), owner: []byte("exact action owner"), digest: []byte("complete class body commitment")}
	if c.metaTarget {
		r.targetShard = core.MetachainShardId
	}
	if c.noAction {
		r.action = nil
	}
	if c.noOwner {
		r.owner = nil
	}
	return r
}

func qualSP227View(c qualSP227Case, r scopedAuthorityRequest) scopedAuthorityView {
	present := func(absent bool, value string) []byte {
		if absent {
			return nil
		}
		return []byte(value)
	}
	v := scopedAuthorityView{request: r.clone(), plane: c.plane, status: c.status, activation: c.activation, intent: c.intent, lrc: c.lrc,
		highImpact: c.high, preToken: c.preToken, targetRole: c.targetRole, providerRole: c.provider, claim: c.claim, lostRoles: c.lost,
		memberRule: c.memberRule, reconciliationEnabled: c.reconciliation}
	v.authorization = present(c.noAuthorization, "canonical full authorization")
	switch c.activeOwner {
	case "self":
		v.activeOwner = []byte("exact action owner")
	case "other":
		v.activeOwner = []byte("another action")
	}
	v.frozenPolicy = present(c.noFrozenPolicy, "pre-incident exact cancellation policy")
	v.noTargetMutation = present(c.noTargetEvidence, "native no-target-mutation evidence")
	v.irreversibleAdmin = present(!c.adminCut, "irreversible prepared-admin commitment")
	v.targetCurrent = present(!c.currentCut, "canonical target-current commitment")
	if c.openPermission {
		v.permissions = [][]byte{[]byte("outstanding permission")}
	}
	v.nativeAuthentication = present(c.noNativeAuth, "separate native authentication")
	v.nativeIssuerKey = present(c.noIssuerKey, "native issuer outside IPAA roster")
	v.issuerIdentity = present(c.issuer == "", map[string]string{"I": qualSP227Issuer, "O": qualSP227Owner}[c.issuer])
	switch c.actor {
	case "O":
		v.nativeActor = []byte(qualSP227Owner)
	case "I":
		v.nativeActor = bytes.Clone(v.issuerIdentity)
	default:
		v.nativeActor = []byte(qualSP227Other)
	}
	if c.scopeBinding != "none" {
		a := &scopedAppointmentContext{owner: []byte(qualSP227Owner), scope: bytes.Clone(r.scope), domain: bytes.Clone(r.domain), unappointed: c.notYetAppointed}
		switch c.scopeBinding {
		case "no_owner":
			a.owner = nil
		case "scope":
			a.scope = []byte("another programme scope")
		case "domain":
			a.domain = []byte("another network domain")
		}
		v.scopeAppointment = a
	}
	if c.writer != "none" {
		w := &scopedWriterContext{subject: bytes.Clone(r.subject), digest: bytes.Clone(r.digest), ceb: []byte("exact current CEB"), currentCEB: []byte("exact current CEB")}
		switch c.writer {
		case "subject":
			w.subject = []byte("another holder or control epoch")
		case "digest":
			w.digest = []byte("another decision body")
		case "no_ceb":
			w.ceb = nil
		case "stale":
			w.currentCEB = []byte("a later CEB")
		}
		v.writer = w
	}
	if c.arm != "" {
		a := &scopedArmContext{use: c.use, action: bytes.Clone(r.action), owner: bytes.Clone(r.owner), digest: bytes.Clone(r.digest), targetShard: r.targetShard}
		switch c.arm {
		case "class":
			a.use = scopedCapIncrease
			if c.use == scopedCapIncrease {
				a.use = scopedCEBChange
			}
		case "action":
			a.action = []byte("another action")
		case "owner":
			a.owner = []byte("another owner")
		case "digest":
			a.digest = []byte("another body")
		case "shard":
			a.targetShard = r.targetShard + 1
		}
		v.arm = a
	}
	if !c.noWindow {
		v.window = &governedActionWindow{100, 105, 120}
	}
	if c.evidence != "" {
		e := &scopedSyntheticClaimEvidence{claim: c.claim, lostRoles: append([]string(nil), c.lost...), domain: bytes.Clone(r.domain), scope: bytes.Clone(r.scope),
			subject: bytes.Clone(r.subject), action: bytes.Clone(r.action), owner: bytes.Clone(r.owner), digest: bytes.Clone(r.digest), frozenPolicy: bytes.Clone(v.frozenPolicy)}
		switch c.evidence {
		case "claim":
			e.claim = map[string]string{"UNAVAILABLE": "COMPROMISED"}[c.claim]
			if e.claim == "" {
				e.claim = "UNAVAILABLE"
			}
		case "lost_other":
			e.lostRoles = []string{scopedEA}
		case "lost_more":
			e.lostRoles = append(e.lostRoles, scopedEA)
		case "lost_fewer":
			e.lostRoles = e.lostRoles[:len(e.lostRoles)-1]
		case "domain":
			e.domain = []byte("another network domain")
		case "scope":
			e.scope = []byte("another programme scope")
		case "subject":
			e.subject = []byte("another subject")
		case "action":
			e.action = []byte("another action")
		case "owner":
			e.owner = []byte("another owner")
		case "digest":
			e.digest = []byte("another body")
		case "policy":
			e.frozenPolicy = []byte("a policy written after the incident")
		}
		v.syntheticClaim = e
	}
	return v
}

func qualSP227Sorted(in []scopedAuthorityRequirement) []string {
	out := make([]string, len(in))
	for i, r := range in {
		out[i] = fmt.Sprintf("%s|%s|%d", r.role, r.kind, r.source)
	}
	sort.Strings(out)
	return out
}

// qualSP227ComparePlan compares the production selector with the model for one
// case and reports whether the case is admitted.
func qualSP227ComparePlan(t *testing.T, c qualSP227Case) bool {
	r := qualSP227Request(c, "synthetic scope")
	want := qualSP227Model(c)
	proofs, bindings, err := scopedAuthorityPlan(r, qualSP227View(c, r))
	if (err == nil) != want.admit {
		require.Failf(t, "admission differs", "model admit=%t, production error=%v, case %+v", want.admit, err, c)
	}
	if !want.admit {
		require.ErrorIs(t, err, errInvalidAuthoritySignatures)
		return false
	}
	if fmt.Sprint(qualSP227Sorted(want.proofs)) != fmt.Sprint(qualSP227Sorted(proofs)) || fmt.Sprint(qualSP227Sorted(want.bindings)) != fmt.Sprint(qualSP227Sorted(bindings)) {
		require.Failf(t, "required roles differ", "model %v / %v, production %v / %v, case %+v",
			qualSP227Sorted(want.proofs), qualSP227Sorted(want.bindings), qualSP227Sorted(proofs), qualSP227Sorted(bindings), c)
	}
	return true
}

// Every combination of operation, phase, purpose, high-impact flag, action
// status, lifecycle, intent, activation, pre-token flag and reconciliation
// flag: 25 x 9 x 9 x 2 x 6 x 5 x 3 x 2 x 2 x 2 cells. The other premises are
// healthy. The counts are computed here, not by the production code.
func TestQualSP227IndependentFullProduct(t *testing.T) {
	cells, admitted := 0, 0
	perUse := make(map[scopedAuthorityUse]int)
	for _, use := range qualSP227AllUses {
		for _, phase := range qualSP227AllPhases {
			for _, purpose := range qualSP227AllPurposes {
				for _, high := range []bool{false, true} {
					for _, preToken := range []bool{false, true} {
						for _, reconciliation := range []bool{false, true} {
							base := qualSP227Healthy(use, phase, purpose, high, preToken, reconciliation)
							for _, status := range qualSP227Statuses {
								for _, lrc := range qualSP227Lifecycles {
									for _, intent := range qualSP227Intents {
										for _, activation := range qualSP227Activations {
											c := base
											c.status, c.lrc, c.intent, c.activation = status, lrc, intent, activation
											cells++
											if qualSP227ComparePlan(t, c) {
												admitted++
												perUse[use]++
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	require.Equal(t, 25*9*9*2*2*2*6*5*3*2, cells)
	for _, use := range []scopedAuthorityUse{0, scopedInitialSuccession, scopedTechnicalRepair, scopedScopeAppointment + 1} {
		require.Zero(t, perUse[use], "no adopted row: operation %d has no admitted cell", use)
	}
	t.Logf("SP2-27_INDEPENDENT_COUNT product cells=%d admitted=%d refused=%d per_operation=%v", cells, admitted, cells-admitted, perUse)
}

// Starting from the healthy scenario of every admitted configuration, change
// one premise at a time. The model states which changes matter for which row.
func TestQualSP227IndependentSingleFaults(t *testing.T) {
	faults := qualSP227PlanFaults()
	configurations, cells, turned := 0, 0, 0
	for _, healthy := range qualSP227Configurations() {
		if !qualSP227Model(healthy).admit {
			require.False(t, qualSP227ComparePlan(t, healthy))
			continue
		}
		configurations++
		require.True(t, qualSP227ComparePlan(t, healthy))
		for _, fault := range faults {
			c := healthy
			fault.apply(&c)
			cells++
			if !qualSP227ComparePlan(t, c) {
				turned++
			}
		}
	}
	require.NotZero(t, configurations)
	require.Equal(t, configurations*len(faults), cells)
	t.Logf("SP2-27_INDEPENDENT_COUNT single_fault configurations=%d faults=%d cells=%d refused=%d still_admitted=%d", configurations, len(faults), cells, turned, cells-turned)
}
