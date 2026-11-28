package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
	"github.com/stretchr/testify/require"
)

// Experimental decoded host and signing layout: XV-SP2-27-CONSTITUTION-HOST.
// Expected proof lists below are literal adopted P01-P17 rows, NOT obtained
// from scopedAuthorityPlan. Public native keys are bound before any oracle.
// No test installs this host as a native reader, adjudicates an objective
// claim, executes cancellation or proves independent human controllers.
type qualSP227Source struct {
	v            scopedAuthorityView
	readErr      error
	afterRead    func()
	mutateRead   bool
	duringDigest func()
}

func (s *qualSP227Source) IsInterfaceNil() bool { return s == nil }
func (s *qualSP227Source) ReadScopedAuthority(r scopedAuthorityRequest) (scopedAuthorityView, error) {
	if s.mutateRead {
		r.domain[0] ^= 1
	}
	if s.afterRead != nil {
		s.afterRead()
	}
	return s.v, s.readErr
}

// ScopedAuthoritySigningDigest is the fixture's own encoder of the SP2-78
// certificate body of one requirement: written from the documented field
// order with the test framing, not with the product encoder. The signing set's
// predecessor is the one the view holds for the proof's exact set.
func (s *qualSP227Source) ScopedAuthoritySigningDigest(r scopedAuthorityRequest, p scopedAuthorityProof) ([]byte, error) {
	if s.duringDigest != nil {
		s.duringDigest()
	}
	u32 := func(n uint32) []byte { return binary.BigEndian.AppendUint32(nil, n) }
	var predecessor []byte
	var predecessorVersion uint64
	for _, sets := range []map[string]scopedAuthoritySet{s.v.current, s.v.bound, s.v.proposed, s.v.frozenProposed} {
		if set, ok := sets[p.requirement.role]; ok && bytes.Equal(set.id, p.id) && bytes.Equal(set.hash, p.hash) && set.version == p.version {
			predecessor, predecessorVersion = set.predecessor, set.predecessorVersion
		}
	}
	kind := qualRecordFrame(u32(uint32(r.use)), u32(uint32(r.phase)), []byte(p.requirement.kind), u32(uint32(p.requirement.source)),
		[]byte(r.purpose), u32(r.locus), u32(r.targetShard), r.action, r.owner)
	body := qualRecordFrame([]byte("DRWA/CERTIFICATE_BODY/experimental1"), r.domain, []byte("DRWA/SCOPED_AUTHORITY/experimental1"),
		qualSP227Number(1), []byte(p.requirement.role), r.scope, qualRecordFrame(r.subject), kind, r.digest, p.id, qualSP227Number(p.version), p.hash,
		qualSP227Number(predecessorVersion), predecessor, qualSP227Number(uint64(p.notBefore)), qualSP227Number(uint64(p.until)), nil)
	return blake2b.NewBlake2b().Compute(string(body)), nil
}
func qualSP227Number(n uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, n)
	return b
}

type qualSP227Constitution struct {
	s                  *qualSP227Source
	r                  scopedAuthorityRequest
	keys, proposedKeys map[string][]crypto.PrivateKey
	limits             scopedAuthorityLimits
	clock              *qualUnboundHeaderTime
	source             HeaderTimeSource
	codec              *registrationRecords
}

func qualSP227ConstitutionNew(t *testing.T, all []qualSP227Binding, programme string) *qualSP227Constitution {
	t.Helper()
	f := &qualSP227Constitution{s: &qualSP227Source{}, keys: make(map[string][]crypto.PrivateKey), proposedKeys: make(map[string][]crypto.PrivateKey),
		limits: scopedAuthorityLimits{members: 5, bytes: 4096, lifetime: 20}, clock: qualHeaderTimeOwner(t)}
	f.r = scopedAuthorityRequest{use: scopedCEBChange, phase: scopedAuthorize, locus: core.MetachainShardId,
		domain: []byte("W03 constitution experiment"), scope: []byte(programme), subject: []byte("program-subject"),
		action: []byte("exact immutable action"), owner: []byte("exact action owner"), digest: []byte("complete class body commitment")}
	v := &f.s.v
	v.current = make(map[string]scopedAuthoritySet)
	v.bound = make(map[string]scopedAuthoritySet)
	v.proposed = make(map[string]scopedAuthoritySet)
	v.frozenProposed = make(map[string]scopedAuthoritySet)
	for _, b := range all {
		if b.Programme != programme {
			continue
		}
		set := scopedAuthoritySet{id: []byte(b.ID), hash: blake2b.NewBlake2b().Compute(string(qualRecordFrame(b.Members...))), version: 1, threshold: b.Threshold, members: b.Members}
		v.current[b.Role], v.bound[b.Role] = set, set
		f.keys[b.Role] = b.Private
		next := set
		next.members = append([][]byte(nil), b.Members...)
		next.members[len(next.members)-1] = b.Standby[0]
		next.version = 2
		next.predecessor = bytes.Clone(set.hash)
		next.predecessorVersion = 1
		next.hash = blake2b.NewBlake2b().Compute(string(qualRecordFrame(next.members...)))
		v.proposed[b.Role], v.frozenProposed[b.Role] = next, next
		f.proposedKeys[b.Role] = append([]crypto.PrivateKey(nil), b.Private...)
		f.proposedKeys[b.Role][len(next.members)-1] = b.StandbyPrivate[0]
	}
	// The proof cap is the exact bound programme's role count, not a new
	// numerical default. Member/byte/time bounds reuse SP2-03 and T21/GAS.
	f.limits.proofs = uint64(len(f.keys))
	v.plane = "NORMAL"
	v.status = "PROPOSED"
	v.activation = "BootstrapDeny"
	v.intent = "OPEN"
	v.lrc = "ACTIVE"
	v.authorization = []byte("canonical full authorization")
	v.activeOwner = bytes.Clone(f.r.owner)
	v.frozenPolicy = []byte("pre-incident exact cancellation policy")
	v.noTargetMutation = []byte("native no-target-mutation evidence")
	v.nativeAuthentication = []byte("separate native issuer authentication")
	v.nativeIssuerKey = []byte("native issuer outside IPAA roster")
	v.memberRule = scopedSyntheticThresholdOnly
	v.issuerIdentity = []byte("native issuer account")
	v.nativeActor = bytes.Clone(v.issuerIdentity)
	v.scopeAppointment = &scopedAppointmentContext{owner: []byte("native programme scope owner"), scope: bytes.Clone(f.r.scope), domain: bytes.Clone(f.r.domain)}
	v.window = &governedActionWindow{100, 105, 120}
	v.time = qualGovernedContext(t, f.clock, core.MetachainShardId, 110)
	f.source = qualClockSource(f.clock, nil)
	var err error
	f.codec, err = newRegistrationRecords(qualRegistrationStore(t, 0), &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	f.bindRequest()
	return f
}
func (f *qualSP227Constitution) bindRequest() { f.s.v.request = f.r.clone() }
func (f *qualSP227Constitution) sign(t *testing.T, wants []scopedAuthorityRequirement) []scopedAuthorityProof {
	t.Helper()
	var out []scopedAuthorityProof
	for _, want := range wants {
		// The fixture resolves the literal expected source, independently of
		// the production selector/reference function.
		sets := f.s.v.current
		keys := f.keys[want.role]
		switch want.source {
		case scopedBound:
			sets = f.s.v.bound
		case scopedProposed:
			sets = f.s.v.proposed
			keys = f.proposedKeys[want.role]
		case scopedFrozenProposed:
			sets = f.s.v.frozenProposed
			keys = f.proposedKeys[want.role]
		}
		set, exists := sets[want.role]
		require.True(t, exists, "fixture role %q", want.role)
		p := scopedAuthorityProof{requirement: want, id: bytes.Clone(set.id), hash: bytes.Clone(set.hash), version: set.version, notBefore: 100, until: 120}
		digest, err := f.s.ScopedAuthoritySigningDigest(f.r, p)
		require.NoError(t, err)
		// Include the final member so successor possession requires an actual
		// bound standby-to-member key, not an inherited predecessor quorum.
		for _, i := range []uint64{0, 1, 4} {
			sig, e := (&singlesig.Ed25519Signer{}).Sign(keys[i], digest)
			require.NoError(t, e)
			p.indices = append(p.indices, i)
			p.signatures = append(p.signatures, sig)
		}
		out = append(out, p)
	}
	return out
}
func (f *qualSP227Constitution) verify(p []scopedAuthorityProof) error {
	return verifyScopedAuthority(f.source, f.codec, f.s, f.r, p, f.limits)
}
func qualSP227Want(role, kind string, source int) scopedAuthorityRequirement {
	return scopedAuthorityRequirement{role, kind, source}
}

func TestQualSP227ConstitutionMatrix(t *testing.T) {
	all := qualSP227Rosters(t)
	programmes := make(map[string]bool)
	for _, b := range all {
		programmes[b.Programme] = true
	}
	w := qualSP227Want
	pa := w(scopedPA, "approval", scopedCurrent)
	pr := w(scopedPR, "approval", scopedCurrent)
	ata := w(scopedATA, "approval", scopedCurrent)
	// Each list is the policy oracle recorded BEFORE implementation, expanded
	// here as literal expected signatures. No selector produces expectations.
	rows := []struct {
		name    string
		use     scopedAuthorityUse
		phase   scopedAuthorityPhase
		high    bool
		purpose string
		want    []scopedAuthorityRequirement
	}{
		{"P01_intent", scopedIntent, scopedDirect, false, "", []scopedAuthorityRequirement{w(scopedIPAA, "admission", scopedCurrent), pr, w(scopedPA, "possession", scopedProposed)}},
		{"P01_registration", scopedRegistration, scopedDirect, false, "", []scopedAuthorityRequirement{w(scopedIPAA, "admission", scopedCurrent), pr, w(scopedPA, "possession", scopedProposed)}},
		{"P02_activation", scopedActivation, scopedDirect, false, "", []scopedAuthorityRequirement{w(scopedIPAA, "admission", scopedCurrent), w(scopedPA, "approval", scopedProposed), pr}},
		{"P02_high_activation", scopedActivation, scopedDirect, true, "", []scopedAuthorityRequirement{w(scopedIPAA, "admission", scopedCurrent), w(scopedPA, "approval", scopedProposed), pr, ata}},
		{"P03_unused_cancel", scopedUnusedIntentCancellation, scopedDirect, false, "", []scopedAuthorityRequirement{w(scopedIPAA, "cancellation", scopedCurrent)}},
		{"P04_withdraw", scopedAdmissionWithdrawal, scopedDirect, false, "", []scopedAuthorityRequirement{w(scopedIPAA, "withdrawal", scopedCurrent)}},
		{"P05_registered_cancel", scopedRegisteredCancellation, scopedDirect, false, "", []scopedAuthorityRequirement{w(scopedPA, "cancellation", scopedProposed), w(scopedPR, "cancellation", scopedCurrent)}},
		{"P06_CEB", scopedCEBChange, scopedAuthorize, false, "", []scopedAuthorityRequirement{pa, pr}},
		{"P06_rotation", scopedRoleRotation, scopedAuthorize, false, "", []scopedAuthorityRequirement{pa, pr, w(scopedSA, "predecessor", scopedCurrent), w(scopedSA, "possession", scopedProposed)}},
		{"P07_high_CEB", scopedCEBChange, scopedAuthorize, true, "", []scopedAuthorityRequirement{pa, pr, ata}},
		{"P08_cap", scopedCapIncrease, scopedAuthorize, false, "", []scopedAuthorityRequirement{pa, pr, w(scopedSA, "cap", scopedCurrent)}},
		{"P08_high_cap", scopedCapIncrease, scopedAuthorize, true, "", []scopedAuthorityRequirement{pa, pr, ata, w(scopedSA, "cap", scopedCurrent)}},
		{"P09_cancel", scopedCEBCancellation, scopedCancel, false, "", []scopedAuthorityRequirement{w(scopedPA, "cancellation", scopedBound), w(scopedPR, "cancellation", scopedBound)}},
		{"P09_high_cancel", scopedCEBCancellation, scopedCancel, true, "", []scopedAuthorityRequirement{w(scopedPA, "cancellation", scopedBound), w(scopedPR, "cancellation", scopedBound), w(scopedATA, "cancellation", scopedBound)}},
		{"P10_HR", scopedAdministrativeTransfer, scopedAuthorize, false, "HOLDER_RECOVERY", []scopedAuthorityRequirement{pa, ata}},
		{"P10_redemption", scopedAdministrativeTransfer, scopedAuthorize, false, "REDEMPTION", []scopedAuthorityRequirement{pa, ata}},
		{"P10_order", scopedAdministrativeTransfer, scopedAuthorize, false, "EXTERNAL_ORDER", []scopedAuthorityRequirement{pa, ata, pr}},
		{"P10_wind_down", scopedAdministrativeTransfer, scopedAuthorize, false, "PROGRAM_WIND_DOWN", []scopedAuthorityRequirement{pa, ata, pr}},
		{"P11_HR_cancel", scopedATCancellation, scopedCancel, false, "HOLDER_RECOVERY", []scopedAuthorityRequirement{w(scopedPA, "cancellation", scopedCurrent), w(scopedATA, "cancellation", scopedCurrent)}},
		{"P11_order_cancel", scopedATCancellation, scopedCancel, false, "EXTERNAL_ORDER", []scopedAuthorityRequirement{w(scopedPA, "cancellation", scopedCurrent), w(scopedATA, "cancellation", scopedCurrent), w(scopedPR, "cancellation", scopedCurrent)}},
		{"P12_retirement", scopedRetirement, scopedAuthorize, false, "", []scopedAuthorityRequirement{pa, pr}},
		{"P12_high_retirement", scopedRetirement, scopedAuthorize, true, "", []scopedAuthorityRequirement{pa, pr, ata}},
		{"P13_seal", scopedRetirementSeal, scopedDirect, false, "", []scopedAuthorityRequirement{w(scopedPA, "request", scopedCurrent)}},
		{"P13_commit", scopedRetirementCommit, scopedDirect, false, "", []scopedAuthorityRequirement{w(scopedPA, "request", scopedCurrent)}},
		{"P13_burn", scopedTerminalBurn, scopedDirect, false, "", []scopedAuthorityRequirement{w(scopedPA, "request", scopedCurrent), w(scopedSA, "burn", scopedCurrent)}},
		{"P14_add", scopedEmergencyAdd, scopedDirect, false, "", []scopedAuthorityRequirement{w(scopedEA, "add", scopedCurrent)}},
		{"P15_release", scopedEmergencyRelease, scopedDirect, false, "", []scopedAuthorityRequirement{w(scopedPA, "release", scopedCurrent), w(scopedPR, "release", scopedCurrent)}},
		{"P15_high_release", scopedEmergencyRelease, scopedDirect, true, "", []scopedAuthorityRequirement{w(scopedPA, "release", scopedCurrent), w(scopedPR, "release", scopedCurrent), w(scopedATA, "release", scopedCurrent)}},
		{"P16_proposal", scopedCEBChange, scopedPropose, false, "", []scopedAuthorityRequirement{w(scopedPA, "proposal", scopedCurrent)}},
		{"P16_start", scopedCEBChange, scopedStart, false, "", []scopedAuthorityRequirement{w(scopedPA, "start", scopedCurrent)}},
		{"P16_AT_arm", scopedAdministrativeTransfer, scopedArm, false, "HOLDER_RECOVERY", []scopedAuthorityRequirement{w(scopedPA, "arm", scopedCurrent)}},
		{"P16_drive", scopedCEBChange, scopedDrive, false, "", nil},
		{"P16_rotation_drive", scopedRoleRotation, scopedDrive, false, "", nil},
		{"P17_pretoken", scopedProviderBinding, scopedDirect, false, "", []scopedAuthorityRequirement{w(scopedIPAA, "delegation", scopedCurrent), w(scopedPR, "delegation", scopedCurrent), w(scopedSA, "predecessor", scopedCurrent), w(scopedSA, "possession", scopedProposed)}},
		{"P17_operational", scopedProviderBinding, scopedAuthorize, false, "", []scopedAuthorityRequirement{pa, pr, w(scopedSA, "predecessor", scopedCurrent), w(scopedSA, "possession", scopedProposed)}},
		{"P17_high", scopedProviderBinding, scopedAuthorize, true, "", []scopedAuthorityRequirement{pa, pr, ata, w(scopedSA, "predecessor", scopedCurrent), w(scopedSA, "possession", scopedProposed)}},
	}
	for programme := range programmes {
		for _, row := range rows {
			t.Run(programme+"/"+row.name, func(t *testing.T) {
				f := qualSP227ConstitutionNew(t, all, programme)
				f.r.use, f.r.phase, f.r.purpose = row.use, row.phase, row.purpose
				v := &f.s.v
				v.highImpact = row.high
				v.targetRole = scopedSA
				v.providerRole = scopedSA
				if row.use == scopedActivation || row.use == scopedRegisteredCancellation {
					v.intent = "CONSUMED"
				}
				if row.phase == scopedStart || row.phase == scopedArm {
					v.status = "EXECUTABLE"
				}
				if row.phase == scopedDrive || row.use == scopedRetirementSeal || row.use == scopedRetirementCommit || row.use == scopedTerminalBurn {
					v.status = "IN_PROGRESS"
				}
				if row.use == scopedRetirementSeal || row.use == scopedTerminalBurn {
					v.lrc = "WIND_DOWN"
				}
				if row.use == scopedRetirementCommit {
					v.lrc = "WIND_DOWN_SEALED"
				}
				v.preToken = row.name == "P17_pretoken"
				if v.preToken { // adopted P17: the lawful scope owner acts
					v.nativeActor = bytes.Clone(v.scopeAppointment.owner)
				}
				if row.phase == scopedDrive { // started material survives later current rotations and expiry
					v.time = qualGovernedContext(t, f.clock, core.MetachainShardId, 121)
					v.current = nil
					v.proposed = nil
				}
				f.bindRequest()
				p := f.sign(t, row.want)
				require.NoError(t, f.verify(p), "literal adopted policy")
				for i := range p {
					missing := append([]scopedAuthorityProof(nil), p[:i]...)
					missing = append(missing, p[i+1:]...)
					require.ErrorIs(t, f.verify(missing), errInvalidAuthoritySignatures, "every independent factor is mandatory")
				}
			})
		}
	}
}

func TestQualSP227ConstitutionNegatives(t *testing.T) {
	all := qualSP227Rosters(t)
	programme := all[0].Programme
	w := qualSP227Want
	wants := []scopedAuthorityRequirement{w(scopedPA, "approval", scopedCurrent), w(scopedPR, "approval", scopedCurrent)}
	cases := []struct {
		name string
		edit func(*qualSP227Constitution, *[]scopedAuthorityProof)
	}{
		{"missing_reader_context", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.s.v.time = nil }},
		{"wrong_locus", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.r.locus = 1; f.bindRequest() }},
		{"inactive_time", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.clock.End(f.s.v.time) }},
		{"missing_domain", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.r.domain = nil }},
		{"missing_owner", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.r.owner = nil; f.bindRequest() }},
		{"missing_action", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.r.action = nil; f.bindRequest() }},
		{"missing_bound_role", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { delete(f.s.v.bound, scopedPR) }},
		{"missing_current_role", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { delete(f.s.v.current, scopedPR) }},
		{"stale_version", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			s := f.s.v.bound[scopedPR]
			s.version++
			f.s.v.bound[scopedPR] = s
		}},
		{"stale_hash", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			s := f.s.v.bound[scopedPR]
			s.hash = []byte("stale")
			f.s.v.bound[scopedPR] = s
		}},
		{"shared_set", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			s := f.s.v.current[scopedPR]
			s.id = f.s.v.current[scopedPA].id
			f.s.v.current[scopedPR] = s
			f.s.v.bound[scopedPR] = s
			*p = f.sign(t, wants) // native-valid proofs; only independence is wrong
		}},
		{"shared_unsigned_key", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			s := f.s.v.current[scopedPR]
			s.members = append([][]byte(nil), s.members...)
			s.members[3] = f.s.v.current[scopedPA].members[3]
			f.s.v.current[scopedPR] = s
			f.s.v.bound[scopedPR] = s
		}},
		{"lowered_threshold", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			s := f.s.v.current[scopedPR]
			s.threshold = 2
			f.s.v.current[scopedPR] = s
		}},
		{"oversized_roster", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.limits.members = 4 }},
		{"empty_set_id", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			s := f.s.v.current[scopedPR]
			s.id = nil
			f.s.v.current[scopedPR] = s
		}},
		{"empty_set_hash", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			s := f.s.v.current[scopedPR]
			s.hash = nil
			f.s.v.current[scopedPR] = s
		}},
		{"zero_members_bound", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.limits.members = 0 }},
		{"zero_proofs_bound", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.limits.proofs = 0 }},
		{"zero_bytes_bound", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.limits.bytes = 0 }},
		{"zero_lifetime", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.limits.lifetime = 0 }},
		{"proof_bound", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.limits.proofs = 1 }},
		{"bytes_bound", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.limits.bytes = 1 }},
		{"duplicate_proof", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { (*p)[1] = (*p)[0] }},
		{"wrong_role", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { (*p)[0].requirement.role = scopedEA }},
		{"wrong_kind", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { (*p)[0].requirement.kind = "cancellation" }},
		{"wrong_source", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { (*p)[0].requirement.source = scopedProposed }},
		{"wrong_id", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { (*p)[0].id = []byte("foreign") }},
		{"wrong_hash", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { (*p)[0].hash = []byte("foreign") }},
		{"wrong_version", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { (*p)[0].version++ }},
		{"threshold_shortage", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			(*p)[0].indices = (*p)[0].indices[:2]
			(*p)[0].signatures = (*p)[0].signatures[:2]
		}},
		{"duplicate_signer", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { (*p)[0].indices[1] = 0 }},
		{"invalid_signature", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { (*p)[0].signatures[0][0] ^= 1 }},
		{"invalid_extra_signature", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			q := &(*p)[0]
			q.indices = []uint64{0, 1, 2, 4}
			q.signatures = append(q.signatures[:2], nil, q.signatures[2])
		}},
		{"window_inverted", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { (*p)[0].notBefore = 121 }},
		{"window_overlong", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { (*p)[0].notBefore = 99 }},
		{"certificate_future", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { (*p)[0].notBefore = 111 }},
		{"certificate_expired", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { (*p)[0].until = 109 }},
		{"window_tamper_signed", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { (*p)[0].until = 119 }},
		{"before_timelock", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			f.s.v.time = qualGovernedContext(t, f.clock, core.MetachainShardId, 104)
		}},
		{"at_GAS_expiry", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			f.s.v.time = qualGovernedContext(t, f.clock, core.MetachainShardId, 120)
		}},
		{"nil_GAS_window", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.s.v.window = nil }},
		{"wrong_status", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.s.v.status = "CANCELLED" }},
		{"FAIL_SAFE", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.s.v.plane = "FAIL_SAFE" }},
		{"unknown_plane", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.s.v.plane = "" }},
		{"unadmitted_claim", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.s.v.claim = "UNAVAILABLE" }},
		{"unadmitted_loss", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.s.v.lostRoles = []string{scopedPA} }},
		{"unknown_use", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.r.use = 0; f.bindRequest() }},
		{"C02_OPEN", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			f.r.use = scopedInitialSuccession
			f.bindRequest()
		}},
		{"C30_missing_context", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			f.r.use = scopedDecisionWriter
			f.bindRequest()
		}},
		{"C32_C34_OPEN", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			f.r.use = scopedTechnicalRepair
			f.bindRequest()
		}},
		{"unknown_phase", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) { f.r.phase = 0; f.bindRequest() }},
		{"unknown_purpose", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			f.r.purpose = "unappointed purpose"
			f.bindRequest()
			*p = f.sign(t, wants)
		}},
		{"unappointed_signed_purpose", func(f *qualSP227Constitution, p *[]scopedAuthorityProof) {
			*p = f.sign(t, []scopedAuthorityRequirement{w(scopedPA, "cancellation", scopedCurrent), w(scopedPR, "cancellation", scopedCurrent)})
		}},
	}
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			f := qualSP227ConstitutionNew(t, all, programme)
			p := f.sign(t, wants)
			row.edit(f, &p)
			require.Error(t, f.verify(p), "deny without any write adapter")
		})
	}
	for _, field := range []string{"domain", "scope", "subject", "action", "owner", "digest", "purpose", "phase", "use", "locus"} {
		for _, rebind := range []bool{false, true} {
			t.Run(fmt.Sprintf("request_binding/%s/rebind_%t", field, rebind), func(t *testing.T) {
				f := qualSP227ConstitutionNew(t, all, programme)
				p := f.sign(t, wants)
				switch field {
				case "domain":
					f.r.domain = []byte("foreign")
				case "scope":
					f.r.scope = []byte("foreign")
				case "subject":
					f.r.subject = []byte("foreign")
				case "action":
					f.r.action = []byte("foreign")
				case "owner":
					f.r.owner = []byte("foreign")
				case "digest":
					f.r.digest = []byte("foreign")
				case "purpose":
					f.r.purpose = "foreign"
				case "phase":
					f.r.phase = scopedPropose
				case "use":
					f.r.use = scopedCapIncrease
				case "locus":
					f.r.locus = 1
				}
				if rebind {
					f.bindRequest()
				}
				require.Error(t, f.verify(p), "neither trusted-request mismatch nor altered signed request admits")
			})
		}
	}
	f := qualSP227ConstitutionNew(t, all, programme)
	p := f.sign(t, wants)
	require.ErrorIs(t, verifyScopedAuthority(f.source, f.codec, nil, f.r, p, f.limits), errInvalidAuthoritySignatures)
	var nilReader *qualSP227Source
	require.ErrorIs(t, verifyScopedAuthority(f.source, f.codec, nilReader, f.r, p, f.limits), errInvalidAuthoritySignatures)
	f.s.readErr = errors.New("reader unavailable")
	require.ErrorIs(t, f.verify(p), f.s.readErr)
	f.s.readErr = nil
	// The signed bytes are the product's (SP2-78): there is no reader digest to
	// fail. Without a codec, or with one too small for the body, it refuses.
	require.ErrorIs(t, verifyScopedAuthority(f.source, nil, f.s, f.r, p, f.limits), errInvalidAuthoritySignatures)
	small, err := newRegistrationRecords(qualRegistrationStore(t, 0), &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 64)
	require.NoError(t, err)
	require.ErrorIs(t, verifyScopedAuthority(f.source, small, f.s, f.r, p, f.limits), errInvalidAuthoritySignatures)
	f.s.mutateRead = true
	require.NoError(t, f.verify(p), "reader request copy cannot alter verifier request")
	require.Equal(t, []byte("W03 constitution experiment"), f.r.domain)
}

func TestQualSP227ConstitutionPolicyGuards(t *testing.T) {
	all := qualSP227Rosters(t)
	programme := all[0].Programme
	w := qualSP227Want
	// Exercise every guard against otherwise valid purpose-specific proofs.
	rows := []struct {
		name           string
		use            scopedAuthorityUse
		phase          scopedAuthorityPhase
		want           []scopedAuthorityRequirement
		setup, breakIt func(*qualSP227Constitution)
	}{
		{"intent_native", scopedIntent, scopedDirect, []scopedAuthorityRequirement{w(scopedIPAA, "admission", scopedCurrent), w(scopedPR, "approval", scopedCurrent), w(scopedPA, "possession", scopedProposed)}, nil, func(f *qualSP227Constitution) { f.s.v.nativeAuthentication = nil }},
		{"intent_consumed", scopedIntent, scopedDirect, []scopedAuthorityRequirement{w(scopedIPAA, "admission", scopedCurrent), w(scopedPR, "approval", scopedCurrent), w(scopedPA, "possession", scopedProposed)}, nil, func(f *qualSP227Constitution) { f.s.v.intent = "CONSUMED" }},
		{"issuer_overlap", scopedRegistration, scopedDirect, []scopedAuthorityRequirement{w(scopedIPAA, "admission", scopedCurrent), w(scopedPR, "approval", scopedCurrent), w(scopedPA, "possession", scopedProposed)}, nil, func(f *qualSP227Constitution) { f.s.v.nativeIssuerKey = f.s.v.current[scopedIPAA].members[3] }},
		{"unused_consumed", scopedUnusedIntentCancellation, scopedDirect, []scopedAuthorityRequirement{w(scopedIPAA, "cancellation", scopedCurrent)}, nil, func(f *qualSP227Constitution) { f.s.v.intent = "CONSUMED" }},
		{"withdraw_wrong_phase", scopedAdmissionWithdrawal, scopedDirect, []scopedAuthorityRequirement{w(scopedIPAA, "withdrawal", scopedCurrent)}, nil, func(f *qualSP227Constitution) { f.r.phase = scopedStart }},
		{"activation_already_active", scopedActivation, scopedDirect, []scopedAuthorityRequirement{w(scopedIPAA, "admission", scopedCurrent), w(scopedPA, "approval", scopedProposed), w(scopedPR, "approval", scopedCurrent)}, func(f *qualSP227Constitution) { f.s.v.intent = "CONSUMED" }, func(f *qualSP227Constitution) { f.s.v.activation = "ACTIVE" }},
		{"registered_not_consumed", scopedRegisteredCancellation, scopedDirect, []scopedAuthorityRequirement{w(scopedPA, "cancellation", scopedProposed), w(scopedPR, "cancellation", scopedCurrent)}, func(f *qualSP227Constitution) { f.s.v.intent = "CONSUMED" }, func(f *qualSP227Constitution) { f.s.v.intent = "OPEN" }},
		{"release_sealed", scopedEmergencyRelease, scopedDirect, []scopedAuthorityRequirement{w(scopedPA, "release", scopedCurrent), w(scopedPR, "release", scopedCurrent)}, nil, func(f *qualSP227Constitution) { f.s.v.lrc = "WIND_DOWN_SEALED" }},
		{"add_retired", scopedEmergencyAdd, scopedDirect, []scopedAuthorityRequirement{w(scopedEA, "add", scopedCurrent)}, nil, func(f *qualSP227Constitution) { f.s.v.lrc = "RETIRED" }},
		{"AT_requalifying", scopedAdministrativeTransfer, scopedAuthorize, []scopedAuthorityRequirement{w(scopedPA, "approval", scopedCurrent), w(scopedATA, "approval", scopedCurrent)}, func(f *qualSP227Constitution) { f.r.purpose = "HOLDER_RECOVERY" }, func(f *qualSP227Constitution) { f.s.v.lrc = "REQUALIFYING" }},
		{"AT_unknown_purpose", scopedAdministrativeTransfer, scopedAuthorize, []scopedAuthorityRequirement{w(scopedPA, "approval", scopedCurrent), w(scopedATA, "approval", scopedCurrent)}, func(f *qualSP227Constitution) { f.r.purpose = "HOLDER_RECOVERY" }, func(f *qualSP227Constitution) { f.r.purpose = "OTHER" }},
		{"AT_cancel_executable", scopedATCancellation, scopedCancel, []scopedAuthorityRequirement{w(scopedPA, "cancellation", scopedCurrent), w(scopedATA, "cancellation", scopedCurrent)}, func(f *qualSP227Constitution) { f.r.purpose = "HOLDER_RECOVERY" }, func(f *qualSP227Constitution) { f.s.v.status = "EXECUTABLE" }},
		{"start_missing_authorization", scopedCEBChange, scopedStart, []scopedAuthorityRequirement{w(scopedPA, "start", scopedCurrent)}, func(f *qualSP227Constitution) { f.s.v.status = "EXECUTABLE" }, func(f *qualSP227Constitution) { f.s.v.authorization = nil }},
		{"start_competing_owner", scopedCEBChange, scopedStart, []scopedAuthorityRequirement{w(scopedPA, "start", scopedCurrent)}, func(f *qualSP227Constitution) { f.s.v.status = "EXECUTABLE" }, func(f *qualSP227Constitution) { f.s.v.activeOwner = []byte("other") }},
		{"non_AT_P4_missing_context", scopedCEBChange, scopedStart, []scopedAuthorityRequirement{w(scopedPA, "start", scopedCurrent)}, func(f *qualSP227Constitution) { f.s.v.status = "EXECUTABLE" }, func(f *qualSP227Constitution) { f.r.phase = scopedArm }},
		{"AT_needs_arm", scopedAdministrativeTransfer, scopedArm, []scopedAuthorityRequirement{w(scopedPA, "arm", scopedCurrent)}, func(f *qualSP227Constitution) { f.s.v.status = "EXECUTABLE"; f.r.purpose = "REDEMPTION" }, func(f *qualSP227Constitution) { f.r.phase = scopedStart }},
		{"drive_wrong_owner", scopedCEBChange, scopedDrive, nil, func(f *qualSP227Constitution) { f.s.v.status = "IN_PROGRESS" }, func(f *qualSP227Constitution) { f.s.v.activeOwner = []byte("other") }},
		{"terminal_missing_owner", scopedRetirementSeal, scopedDirect, []scopedAuthorityRequirement{w(scopedPA, "request", scopedCurrent)}, func(f *qualSP227Constitution) { f.s.v.status = "IN_PROGRESS"; f.s.v.lrc = "WIND_DOWN" }, func(f *qualSP227Constitution) { f.s.v.activeOwner = []byte("other") }},
		{"terminal_wrong_lifecycle", scopedRetirementCommit, scopedDirect, []scopedAuthorityRequirement{w(scopedPA, "request", scopedCurrent)}, func(f *qualSP227Constitution) { f.s.v.status = "IN_PROGRESS"; f.s.v.lrc = "WIND_DOWN_SEALED" }, func(f *qualSP227Constitution) { f.s.v.lrc = "ACTIVE" }},
		{"rotation_missing_target", scopedRoleRotation, scopedAuthorize, []scopedAuthorityRequirement{w(scopedPA, "approval", scopedCurrent), w(scopedPR, "approval", scopedCurrent), w(scopedSA, "predecessor", scopedCurrent), w(scopedSA, "possession", scopedProposed)}, func(f *qualSP227Constitution) { f.s.v.targetRole = scopedSA }, func(f *qualSP227Constitution) { f.s.v.targetRole = "" }},
		{"provider_missing", scopedProviderBinding, scopedDirect, []scopedAuthorityRequirement{w(scopedIPAA, "delegation", scopedCurrent), w(scopedPR, "delegation", scopedCurrent), w(scopedSA, "predecessor", scopedCurrent), w(scopedSA, "possession", scopedProposed)}, func(f *qualSP227Constitution) {
			f.s.v.preToken = true
			f.s.v.providerRole = scopedSA
			f.s.v.nativeActor = bytes.Clone(f.s.v.scopeAppointment.owner)
		}, func(f *qualSP227Constitution) { f.s.v.providerRole = "" }},
		{"provider_no_native", scopedProviderBinding, scopedDirect, []scopedAuthorityRequirement{w(scopedIPAA, "delegation", scopedCurrent), w(scopedPR, "delegation", scopedCurrent), w(scopedSA, "predecessor", scopedCurrent), w(scopedSA, "possession", scopedProposed)}, func(f *qualSP227Constitution) {
			f.s.v.preToken = true
			f.s.v.providerRole = scopedSA
			f.s.v.nativeActor = bytes.Clone(f.s.v.scopeAppointment.owner)
		}, func(f *qualSP227Constitution) { f.s.v.nativeAuthentication = nil }},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			f := qualSP227ConstitutionNew(t, all, programme)
			f.r.use, f.r.phase = row.use, row.phase
			if row.setup != nil {
				row.setup(f)
			}
			f.bindRequest()
			p := f.sign(t, row.want)
			require.NoError(t, f.verify(p))
			row.breakIt(f)
			f.bindRequest()
			require.Error(t, f.verify(p))
		})
	}
	for _, field := range []string{"id", "hash", "version", "predecessor", "predecessor_version", "missing"} {
		t.Run("successor/"+field, func(t *testing.T) {
			f := qualSP227ConstitutionNew(t, all, programme)
			f.r.use = scopedRoleRotation
			f.s.v.targetRole = scopedSA
			f.bindRequest()
			p := f.sign(t, []scopedAuthorityRequirement{w(scopedPA, "approval", scopedCurrent), w(scopedPR, "approval", scopedCurrent), w(scopedSA, "predecessor", scopedCurrent), w(scopedSA, "possession", scopedProposed)})
			s := f.s.v.proposed[scopedSA]
			switch field {
			case "id":
				s.id = []byte("different lineage")
			case "hash":
				s.hash = f.s.v.current[scopedSA].hash
			case "version":
				s.version = 1
			case "predecessor":
				s.predecessor = nil
			case "predecessor_version":
				s.predecessorVersion = 0
			}
			f.s.v.proposed[scopedSA] = s
			if field == "missing" {
				delete(f.s.v.proposed, scopedSA)
			} else {
				p = f.sign(t, []scopedAuthorityRequirement{w(scopedPA, "approval", scopedCurrent), w(scopedPR, "approval", scopedCurrent), w(scopedSA, "predecessor", scopedCurrent), w(scopedSA, "possession", scopedProposed)})
			}
			require.Error(t, f.verify(p))
		})
	}
	_, exists := scopedAuthorityReference(scopedAuthorityView{}, scopedAuthorityRequirement{source: -1})
	require.False(t, exists)
}

func TestQualSP227ConstitutionCancellation(t *testing.T) {
	all := qualSP227Rosters(t)
	programme := all[0].Programme
	w := qualSP227Want
	wants := []scopedAuthorityRequirement{w(scopedPA, "cancellation", scopedBound), w(scopedPR, "cancellation", scopedBound)}
	for _, status := range []string{"PROPOSED", "EXECUTABLE", "IN_PROGRESS"} {
		for _, cut := range []string{"before", "admin_at", "admin_after", "current_at", "current_after", "permission", "missing_negative_evidence", "missing_policy", "wrong_owner", "closed", "stale_current"} {
			t.Run(status+"/"+cut, func(t *testing.T) {
				f := qualSP227ConstitutionNew(t, all, programme)
				f.r.use, f.r.phase = scopedCEBCancellation, scopedCancel
				v := &f.s.v
				v.status = status
				f.bindRequest()
				p := f.sign(t, wants)
				switch cut {
				case "admin_at", "admin_after":
					v.irreversibleAdmin = []byte(cut)
				case "current_at", "current_after":
					v.targetCurrent = []byte(cut)
				case "permission":
					v.permissions = [][]byte{[]byte("outstanding")}
				case "missing_negative_evidence":
					v.noTargetMutation = nil
				case "missing_policy":
					v.frozenPolicy = nil
				case "wrong_owner":
					v.activeOwner = []byte("different")
				case "closed":
					v.status = "CANCELLED"
				case "stale_current":
					s := v.current[scopedPA]
					s.version++
					v.current[scopedPA] = s
				}
				err := f.verify(p)
				if cut == "before" || cut == "wrong_owner" && status != "IN_PROGRESS" {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, errInvalidAuthoritySignatures)
				}
				// There is no effect writer. No check can write CANCELLED, restore
				// target permissions or invalidate another owner's work.
				require.Equal(t, cut == "closed", v.status == "CANCELLED")
			})
		}
	}
	// Conditional membership alone is NOT claim admission. Independently
	// sign each adopted alternative, then show the full gate still denies it.
	for _, row := range []struct {
		name, claim string
		lost, want  []string
		high        bool
		target      string
	}{
		{"PA_unavailable", "UNAVAILABLE", []string{scopedPA}, []string{scopedPR, scopedSA, scopedATA}, false, ""},
		{"PR_compromised", "COMPROMISED", []string{scopedPR}, []string{scopedPA, scopedSA, scopedATA}, false, ""},
		{"both", "UNAVAILABLE", []string{scopedPA, scopedPR}, []string{scopedSA, scopedATA, scopedEA}, false, ""},
		{"ATA_subject", "UNAVAILABLE", []string{scopedATA}, []string{scopedPA, scopedPR, scopedSA}, true, scopedATA},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := qualSP227ConstitutionNew(t, all, programme)
			v := &f.s.v
			v.claim, v.lostRoles, v.highImpact, v.targetRole = row.claim, row.lost, row.high, row.target
			roles, err := scopedCancellationRoles(*v)
			require.NoError(t, err)
			require.Equal(t, row.want, roles)
			f.r.use, f.r.phase = scopedCEBCancellation, scopedCancel
			f.bindRequest()
			var req []scopedAuthorityRequirement
			for _, role := range row.want {
				req = append(req, w(role, "cancellation", scopedBound))
			}
			p := f.sign(t, req)
			for _, proof := range p {
				s := v.bound[proof.requirement.role]
				digest, e := f.s.ScopedAuthoritySigningDigest(f.r, proof)
				require.NoError(t, e)
				require.NoError(t, verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", s.threshold, s.members, proof.indices, proof.signatures, digest, 5, 4096))
			}
			require.ErrorIs(t, f.verify(p), errInvalidAuthoritySignatures, "objective evidence/cold-member rules remain OPEN")
		})
	}
	for _, v := range []scopedAuthorityView{{claim: "DISSENT", lostRoles: []string{scopedPA}}, {claim: "UNAVAILABLE", lostRoles: []string{scopedPA, scopedPA}}, {claim: "UNAVAILABLE", lostRoles: []string{scopedSA}}, {claim: "UNAVAILABLE", lostRoles: []string{scopedPA, scopedSA}}, {claim: "UNAVAILABLE"}, {claim: "UNAVAILABLE", lostRoles: []string{scopedATA}, highImpact: true}} {
		_, err := scopedCancellationRoles(v)
		require.ErrorIs(t, err, errInvalidAuthoritySignatures)
	}
}

func TestQualSP227ConstitutionTimeAndConcurrency(t *testing.T) {
	all := qualSP227Rosters(t)
	programme := all[0].Programme
	w := qualSP227Want
	// Direct certificate bounds are inclusive, independently of GAS start's
	// exclusive upper end. These are existing experimental T21 coordinates.
	for _, at := range []uint64{99, 100, 120, 121} {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			f := qualSP227ConstitutionNew(t, all, programme)
			f.r.use, f.r.phase = scopedEmergencyAdd, scopedDirect
			f.s.v.time = qualGovernedContext(t, f.clock, core.MetachainShardId, at)
			f.bindRequest()
			p := f.sign(t, []scopedAuthorityRequirement{w(scopedEA, "add", scopedCurrent)})
			err := f.verify(p)
			if at == 100 || at == 120 {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, errInvalidAuthoritySignatures)
			}
		})
	}
	f := qualSP227ConstitutionNew(t, all, programme)
	p := f.sign(t, []scopedAuthorityRequirement{w(scopedPA, "approval", scopedCurrent), w(scopedPR, "approval", scopedCurrent)})
	before := qualRecordFrame(f.r.domain, f.r.scope, f.r.subject, f.r.action, f.r.owner, f.r.digest, p[0].id, p[0].hash, p[0].signatures[0])
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- f.verify(p) }()
	}
	wg.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	require.Equal(t, before, qualRecordFrame(f.r.domain, f.r.scope, f.r.subject, f.r.action, f.r.owner, f.r.digest, p[0].id, p[0].hash, p[0].signatures[0]))
}

// L-1 isolation: every certificate remains natively valid after the hostile
// change. Each case has one reason for denial, independent of signature failure
// or GAS's separate time/owner guards. Existing negative assertions stay intact.
func TestQualSP227ConstitutionIsolatedGuards(t *testing.T) {
	all := qualSP227Rosters(t)
	for _, name := range []string{"lifetime", "time_locus", "request_bytes", "owner_echo"} {
		t.Run(name, func(t *testing.T) {
			f := qualSP227ConstitutionNew(t, all, all[0].Programme)
			f.r.use, f.r.phase = scopedEmergencyAdd, scopedDirect
			f.bindRequest()
			want := []scopedAuthorityRequirement{qualSP227Want(scopedEA, "add", scopedCurrent)}
			proofs := f.sign(t, want)
			require.NoError(t, f.verify(proofs), "otherwise-valid direct authority control")
			switch name {
			case "time_locus":
				f.r.locus = 1 // existing T05 shard-1 fixture; capability remains metachain
				f.bindRequest()
				proofs = f.sign(t, want)
			case "request_bytes":
				f.r.domain = bytes.Repeat([]byte("A"), int(f.limits.bytes))
				f.bindRequest()
				proofs = f.sign(t, want)
				require.NotEmpty(t, f.r.scope, "domain alone consumes the budget; required scope exceeds it")
			case "owner_echo":
				f.s.v.request.owner = []byte("foreign") // signed request is unchanged
			case "lifetime":
				proofs[0].until = proofs[0].notBefore + f.limits.lifetime + 1
			}
			// Re-sign even the extended validity interval. This independent
			// native verification must succeed before the scoped error assertion.
			proof := &proofs[0]
			digest, err := f.s.ScopedAuthoritySigningDigest(f.r, *proof)
			require.NoError(t, err)
			proof.signatures = nil
			for _, index := range proof.indices {
				signature, signErr := (&singlesig.Ed25519Signer{}).Sign(f.keys[scopedEA][index], digest)
				require.NoError(t, signErr)
				proof.signatures = append(proof.signatures, signature)
			}
			set := f.s.v.current[scopedEA]
			require.NoError(t, verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", set.threshold, set.members,
				proof.indices, proof.signatures, digest, f.limits.members, f.limits.bytes), "native signature and its byte bound are satisfied")
			require.ErrorIs(t, f.verify(proofs), errInvalidAuthoritySignatures, "isolated "+name+" guard")
		})
	}
}

// M-1: signatures bind the original request, while each reader echo differs in
// exactly one field. Keep the existing isolated owner case unchanged.
func TestQualSP227ConstitutionReaderEcho(t *testing.T) {
	all := qualSP227Rosters(t)
	for _, row := range []struct {
		name   string
		change func(*scopedAuthorityRequest)
	}{
		{"use", func(r *scopedAuthorityRequest) { r.use = scopedIntent }},
		{"phase", func(r *scopedAuthorityRequest) { r.phase = scopedPropose }},
		{"purpose", func(r *scopedAuthorityRequest) { r.purpose = "EXTERNAL_ORDER" }},
		{"locus", func(r *scopedAuthorityRequest) { r.locus = 1 }},
		{"domain", func(r *scopedAuthorityRequest) { r.domain = []byte("foreign") }},
		{"scope", func(r *scopedAuthorityRequest) { r.scope = []byte("foreign") }},
		{"subject", func(r *scopedAuthorityRequest) { r.subject = []byte("foreign") }},
		{"action", func(r *scopedAuthorityRequest) { r.action = []byte("foreign") }},
		{"digest", func(r *scopedAuthorityRequest) { r.digest = []byte("foreign") }},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := qualSP227ConstitutionNew(t, all, all[0].Programme)
			f.r.use, f.r.phase = scopedEmergencyAdd, scopedDirect
			f.bindRequest()
			proofs := f.sign(t, []scopedAuthorityRequirement{qualSP227Want(scopedEA, "add", scopedCurrent)})
			require.NoError(t, f.verify(proofs), "otherwise-valid exact reader echo")
			original := f.r.clone()
			row.change(&f.s.v.request)
			digest, err := f.s.ScopedAuthoritySigningDigest(f.r, proofs[0])
			require.NoError(t, err)
			set := f.s.v.current[scopedEA]
			require.NoError(t, verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", set.threshold, set.members,
				proofs[0].indices, proofs[0].signatures, digest, f.limits.members, f.limits.bytes), "original request remains natively signed")
			require.ErrorIs(t, f.verify(proofs), errInvalidAuthoritySignatures, "isolated reader echo "+row.name)
			require.Equal(t, original, f.r, "echo mismatch cannot alter the signed request")
		})
	}
}

// This qualification adapter composes the real GAS/T04 store with the scoped
// native-signature checker. Its already-decoded packet is test transport only;
// equality binds every incoming byte to that public packet, not to a magic
// success token. It is not a production certificate parser or native reader.
type qualSP227GASHost struct {
	*qualGovernedActionHost
	f      *qualSP227Constitution
	proofs []scopedAuthorityProof
}

func qualSP227Packet(proofs []scopedAuthorityProof) []byte {
	var fields [][]byte
	for _, p := range proofs {
		fields = append(fields, []byte(p.requirement.role), []byte(p.requirement.kind), qualSP227Number(uint64(p.requirement.source)), p.id, p.hash, qualSP227Number(p.version), qualSP227Number(uint64(p.notBefore)), qualSP227Number(uint64(p.until)))
		var ids []byte
		for _, i := range p.indices {
			ids = append(ids, qualSP227Number(i)...)
		}
		fields = append(fields, ids, qualRecordFrame(p.signatures...))
	}
	return qualRecordFrame(fields...)
}
func (h *qualSP227GASHost) checkProof(id, digest, envelope, packet []byte) error {
	if !bytes.Equal(id, h.f.r.action) || !bytes.Equal(digest, h.f.r.digest) || !bytes.Equal(envelope, h.envelope) || !bytes.Equal(packet, qualSP227Packet(h.proofs)) {
		return errInvalidAuthoritySignatures
	}
	return h.f.verify(h.proofs)
}
func (h *qualSP227GASHost) Authorize(id, digest, envelope, packet []byte) error {
	return h.checkProof(id, digest, envelope, packet)
}
func (h *qualSP227GASHost) Start(id, digest, envelope, packet []byte) (bool, HeaderMilliseconds, error) {
	return h.arm, h.lifetime, h.checkProof(id, digest, envelope, packet)
}

func TestQualSP227ConstitutionGASComposition(t *testing.T) {
	all := qualSP227Rosters(t)
	programme := all[0].Programme
	w := qualSP227Want
	for _, arm := range []bool{false, true} {
		t.Run(fmt.Sprintf("arm_%t", arm), func(t *testing.T) {
			g := qualGovernedActionNew(t)
			g.initialize(t)
			id := g.propose(t)
			_, digest, _ := g.expected(100)
			f := qualSP227ConstitutionNew(t, all, programme)
			f.r.action, f.r.owner, f.r.digest = bytes.Clone(id), bytes.Clone(id), bytes.Clone(digest)
			f.s.v.activeOwner = bytes.Clone(id)
			f.r.phase = scopedAuthorize
			want := []scopedAuthorityRequirement{w(scopedPA, "approval", scopedCurrent), w(scopedPR, "approval", scopedCurrent)}
			if arm {
				f.r.use = scopedAdministrativeTransfer
				f.r.purpose = "HOLDER_RECOVERY"
				want[1] = w(scopedATA, "approval", scopedCurrent)
			}
			g.x = qualGovernedContext(t, g.c, core.MetachainShardId, 105)
			// One source for the action store and the authority check (D-3).
			f.s.v.time, f.source = g.x, g.g.timeSource
			f.bindRequest()
			h := &qualSP227GASHost{qualGovernedActionHost: g.h, f: f, proofs: f.sign(t, want)}
			h.arm = arm
			g.g.host = h
			// Bad native signature denies with unchanged actual AccountsDB root and
			// journal; replacing it with a valid purpose quorum advances real GAS.
			original := bytes.Clone(h.proofs[0].signatures[0])
			h.proofs[0].signatures[0][0] ^= 1
			g.denied(t, func() error { return g.g.authorize(g.x, id, qualSP227Packet(h.proofs)) })
			r, _, _, err := g.g.load(id)
			require.NoError(t, err)
			require.Equal(t, "PROPOSED", r.status)
			h.proofs[0].signatures[0] = original
			require.NoError(t, g.g.authorize(g.x, id, qualSP227Packet(h.proofs)))
			r, _, _, err = g.g.load(id)
			require.NoError(t, err)
			require.Equal(t, "EXECUTABLE", r.status)
			f.s.v.status = "EXECUTABLE"
			journal := g.s.JournalLen()
			require.NoError(t, g.g.authorize(g.x, id, qualSP227Packet(h.proofs)))
			require.Equal(t, journal, g.s.JournalLen(), "exact authorization revalidates without another write")
			f.r.phase = scopedStart
			kind := "start"
			if arm {
				f.r.phase = scopedArm
				kind = "arm"
			}
			f.bindRequest()
			h.proofs = f.sign(t, []scopedAuthorityRequirement{w(scopedPA, kind, scopedCurrent)})
			// Every class dependency remains current even though START only needs
			// PA's fresh proof. Restore the frozen reference, not a weaker guard.
			role := scopedPR
			if arm {
				role = scopedATA
			}
			old := f.s.v.bound[role]
			stale := old
			stale.version++
			f.s.v.bound[role] = stale
			g.denied(t, func() error { return g.g.start(g.x, id, qualSP227Packet(h.proofs)) })
			require.Zero(t, h.effects)
			f.s.v.bound[role] = old
			// A failure after the host effect is rolled back by the existing T04
			// owner; no signature checker invents a parallel transaction boundary.
			h.badOutput = true
			g.denied(t, func() error { return g.g.start(g.x, id, qualSP227Packet(h.proofs)) })
			h.badOutput = false
			r, _, _, err = g.g.load(id)
			require.NoError(t, err)
			require.Equal(t, "EXECUTABLE", r.status)
			require.NoError(t, g.g.start(g.x, id, qualSP227Packet(h.proofs)))
			r, _, _, err = g.g.load(id)
			require.NoError(t, err)
			require.Equal(t, "IN_PROGRESS", r.status)
			require.Equal(t, HeaderMilliseconds(105), r.started)
			if arm {
				require.Equal(t, HeaderMilliseconds(112), r.expiry)
			} else {
				require.Zero(t, r.expiry)
			}
			qualAssertContainmentBalance(t, g.s, 97)
			g.denied(t, func() error { return g.g.start(g.x, id, qualSP227Packet(h.proofs)) })
		})
	}
}

// R7: literal adopted rows and hostile decoded premises. Each negative starts
// with a healthy native-signed control, then re-signs the changed request so a
// missing policy/context guard cannot be hidden by a cryptographic failure.
func TestQualSP227AdoptedAppointment(t *testing.T) {
	all := qualSP227Rosters(t)
	w := qualSP227Want
	for _, use := range []scopedAuthorityUse{scopedScopeAppointment, scopedIntent, scopedRegistration, scopedActivation} {
		for _, bad := range []string{"control", "missing", "owner", "scope", "domain", "issuer_is_owner", "issuer_missing", "not_appointed", "native_actor", "native_auth", "repeat", "post_token", "phase", "possession_only", "shared_id", "shared_unsigned_key", "missing_possession"} {
			if use != scopedScopeAppointment && (bad == "repeat" || bad == "post_token" || bad == "possession_only" || bad == "missing_possession") {
				continue
			}
			if use == scopedScopeAppointment && (bad == "issuer_missing" || bad == "not_appointed") || use == scopedActivation && (bad == "native_actor" || bad == "native_auth") {
				continue
			}
			t.Run(fmt.Sprintf("%d/%s", use, bad), func(t *testing.T) {
				f := qualSP227ConstitutionNew(t, all, all[0].Programme)
				f.r.use, f.r.phase = use, scopedDirect
				wants := []scopedAuthorityRequirement{w(scopedIPAA, "admission", scopedCurrent), w(scopedPR, "approval", scopedCurrent), w(scopedPA, "possession", scopedProposed)}
				if use == scopedScopeAppointment {
					f.s.v.preToken = true
					f.s.v.scopeAppointment.unappointed = true
					f.s.v.nativeActor = bytes.Clone(f.s.v.scopeAppointment.owner)
					wants = []scopedAuthorityRequirement{w(scopedIPAA, "possession", scopedProposed), w(scopedPR, "possession", scopedProposed)}
				}
				if use == scopedActivation {
					f.s.v.intent = "CONSUMED"
					wants = []scopedAuthorityRequirement{w(scopedIPAA, "admission", scopedCurrent), w(scopedPA, "approval", scopedProposed), w(scopedPR, "approval", scopedCurrent)}
				}
				f.bindRequest()
				require.NoError(t, f.verify(f.sign(t, wants)))
				switch bad {
				case "missing":
					f.s.v.scopeAppointment = nil
				case "owner":
					f.s.v.scopeAppointment.owner = nil
				case "scope":
					f.s.v.scopeAppointment.scope = []byte("foreign")
				case "domain":
					f.s.v.scopeAppointment.domain = []byte("foreign")
				case "issuer_is_owner":
					f.s.v.issuerIdentity = bytes.Clone(f.s.v.scopeAppointment.owner)
					if use != scopedScopeAppointment {
						f.s.v.nativeActor = bytes.Clone(f.s.v.issuerIdentity)
					}
				case "issuer_missing":
					f.s.v.issuerIdentity = nil
				case "not_appointed":
					f.s.v.scopeAppointment.unappointed = true
				case "native_actor":
					f.s.v.nativeActor = []byte("unlawful native actor")
				case "native_auth":
					f.s.v.nativeAuthentication = nil
				case "repeat":
					f.s.v.scopeAppointment.unappointed = false
				case "post_token":
					f.s.v.preToken = false
				case "phase":
					f.r.phase = scopedPropose
				case "possession_only":
					f.s.v.nativeAuthentication = nil
					f.s.v.nativeActor = nil
				case "missing_possession":
					wants = wants[:1]
				case "shared_id", "shared_unsigned_key":
					sets, peer := f.s.v.current, f.s.v.current[scopedIPAA]
					if use == scopedScopeAppointment {
						sets, peer = f.s.v.proposed, f.s.v.proposed[scopedIPAA]
					}
					s := sets[scopedPR]
					if bad == "shared_id" {
						s.id = bytes.Clone(peer.id)
					} else {
						s.members = append([][]byte(nil), s.members...)
						s.members[3] = peer.members[3]
					}
					sets[scopedPR] = s
				}
				f.bindRequest()
				p := f.sign(t, wants)
				if bad == "control" {
					require.NoError(t, f.verify(p))
				} else {
					require.Error(t, f.verify(p))
				}
			})
		}
	}
	// R01 permits an unnamed issuer only at first appointment; this is not a
	// continuing issuer override, and native owner authentication stays required.
	f := qualSP227ConstitutionNew(t, all, all[0].Programme)
	f.r.use, f.r.phase = scopedScopeAppointment, scopedDirect
	f.s.v.preToken = true
	f.s.v.scopeAppointment.unappointed = true
	f.s.v.issuerIdentity = nil
	f.s.v.nativeActor = bytes.Clone(f.s.v.scopeAppointment.owner)
	f.bindRequest()
	require.NoError(t, f.verify(f.sign(t, []scopedAuthorityRequirement{w(scopedIPAA, "possession", scopedProposed), w(scopedPR, "possession", scopedProposed)})))
}

func TestQualSP227AdoptedWriters(t *testing.T) {
	all := qualSP227Rosters(t)
	w := qualSP227Want
	for _, enabled := range []bool{false, true} {
		for _, role := range []string{scopedCDA, scopedFCA, scopedIRA} {
			for _, bad := range []string{"control", "missing", "subject", "digest", "ceb_missing", "ceb_stale", "phase", "purpose", "missing_peer", "shared_id", "shared_unsigned_key", "prepared_only", "wrong_writer", "native_holder_substitution"} {
				t.Run(fmt.Sprintf("%t/%s/%s", enabled, role, bad), func(t *testing.T) {
					f := qualSP227ConstitutionNew(t, all, all[0].Programme)
					f.r.use, f.r.phase, f.r.purpose = scopedDecisionWriter, scopedDirect, role
					f.s.v.reconciliationEnabled = enabled
					f.s.v.writer = &scopedWriterContext{subject: bytes.Clone(f.r.subject), digest: bytes.Clone(f.r.digest), ceb: []byte("exact current CEB"), currentCEB: []byte("exact current CEB")}
					f.bindRequest()
					wants := []scopedAuthorityRequirement{w(role, "writer", scopedCurrent)}
					if role == scopedIRA && !enabled {
						require.Error(t, f.verify(f.sign(t, wants)))
						return
					}
					require.NoError(t, f.verify(f.sign(t, wants)))
					// Change an UNSIGNED peer, so pair independence is not reducible to
					// checking the selected signature list alone.
					peer := scopedFCA
					if role == scopedFCA {
						peer = scopedCDA
					}
					switch bad {
					case "missing":
						f.s.v.writer = nil
					case "subject":
						f.s.v.writer.subject = []byte("foreign holder/control epoch")
					case "digest":
						f.s.v.writer.digest = []byte("foreign complete body")
					case "ceb_missing":
						f.s.v.writer.ceb = nil
					case "ceb_stale":
						f.s.v.writer.currentCEB = []byte("new CEB")
					case "phase":
						f.r.phase = scopedAuthorize
					case "purpose":
						f.r.purpose = scopedPA
					case "missing_peer":
						delete(f.s.v.current, peer)
					case "shared_id", "shared_unsigned_key":
						s := f.s.v.current[peer]
						selected := f.s.v.current[role]
						if bad == "shared_id" {
							s.id = bytes.Clone(selected.id)
						} else {
							s.members = append([][]byte(nil), s.members...)
							s.members[3] = selected.members[3]
						}
						f.s.v.current[peer] = s
					case "prepared_only":
						wants[0].source = scopedProposed
					case "wrong_writer":
						wants[0].role = peer
					case "native_holder_substitution":
						wants = nil
					}
					f.bindRequest()
					p := f.sign(t, wants)
					if bad == "control" {
						require.NoError(t, f.verify(p))
					} else {
						require.Error(t, f.verify(p))
					}
				})
			}
		}
	}
	// When IRA is enabled, even an unsigned IRA is an independent current
	// dependency. Optional disabled IRA is not silently required.
	for _, enabled := range []bool{false, true} {
		f := qualSP227ConstitutionNew(t, all, all[0].Programme)
		f.r.use, f.r.phase, f.r.purpose = scopedDecisionWriter, scopedDirect, scopedCDA
		f.s.v.writer = &scopedWriterContext{f.r.subject, f.r.digest, []byte("ceb"), []byte("ceb")}
		f.s.v.reconciliationEnabled = enabled
		delete(f.s.v.current, scopedIRA)
		f.bindRequest()
		err := f.verify(f.sign(t, []scopedAuthorityRequirement{w(scopedCDA, "writer", scopedCurrent)}))
		if enabled {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}

func TestQualSP227AdoptedBusinessArm(t *testing.T) {
	all := qualSP227Rosters(t)
	w := qualSP227Want
	for _, use := range []scopedAuthorityUse{scopedCEBChange, scopedRoleRotation, scopedRetirement} {
		for _, high := range []bool{false, true} {
			for _, bad := range []string{"control", "missing", "class", "action", "owner", "digest", "target", "meta_target", "status", "authorization", "current_peer", "time_before", "time_at_expiry", "target_echo", "target_signature", "cap", "provider", "technical", "unsupported"} {
				t.Run(fmt.Sprintf("%d/%t/%s", use, high, bad), func(t *testing.T) {
					f := qualSP227ConstitutionNew(t, all, all[0].Programme)
					f.r.use, f.r.phase, f.r.targetShard = use, scopedArm, 1
					f.s.v.status = "EXECUTABLE"
					f.s.v.highImpact = high
					f.s.v.targetRole = scopedSA
					f.s.v.arm = &scopedArmContext{use, f.r.action, f.r.owner, f.r.digest, 1}
					f.bindRequest()
					wants := []scopedAuthorityRequirement{w(scopedPA, "arm", scopedCurrent)}
					p := f.sign(t, wants)
					require.NoError(t, f.verify(p))
					switch bad {
					case "missing":
						f.s.v.arm = nil
					case "class":
						f.s.v.arm.use = scopedCapIncrease
					case "action":
						f.s.v.arm.action = []byte("foreign")
					case "owner":
						f.s.v.arm.owner = []byte("foreign")
					case "digest":
						f.s.v.arm.digest = []byte("foreign")
					case "target":
						f.s.v.arm.targetShard = 0
					case "meta_target":
						f.r.targetShard = core.MetachainShardId
						f.s.v.arm.targetShard = f.r.targetShard
					case "status":
						f.s.v.status = "IN_PROGRESS"
					case "authorization":
						f.s.v.authorization = nil
					case "current_peer":
						s := f.s.v.current[scopedPR]
						s.version++
						f.s.v.current[scopedPR] = s
					case "time_before":
						f.s.v.time = qualGovernedContext(t, f.clock, core.MetachainShardId, 104)
					case "time_at_expiry":
						f.s.v.time = qualGovernedContext(t, f.clock, core.MetachainShardId, 120)
					case "target_echo":
						f.s.v.request.targetShard = 0
					case "target_signature":
						f.r.targetShard = 0
						f.s.v.arm.targetShard = 0
					case "cap":
						f.r.use = scopedCapIncrease
						f.s.v.arm.use = f.r.use
					case "provider":
						f.r.use = scopedProviderBinding
						f.s.v.providerRole = scopedSA
						f.s.v.arm.use = f.r.use
					case "technical":
						f.r.use = scopedTechnicalRepair
						f.s.v.arm.use = f.r.use
					case "unsupported":
						f.r.use = 0
						f.s.v.arm.use = f.r.use
					}
					if bad != "target_echo" {
						f.bindRequest()
					}
					if bad != "target_signature" {
						p = f.sign(t, wants)
					}
					if bad == "control" {
						require.NoError(t, f.verify(p))
					} else {
						require.Error(t, f.verify(p))
					}
				})
			}
		}
	}
}

func TestQualSP227AdoptedMemberAndOpenCells(t *testing.T) {
	all := qualSP227Rosters(t)
	w := qualSP227Want
	for _, rule := range []scopedProgrammeMemberRule{0, scopedSyntheticThresholdOnly, 2} {
		f := qualSP227ConstitutionNew(t, all, all[0].Programme)
		f.r.use, f.r.phase = scopedEmergencyAdd, scopedDirect
		f.bindRequest()
		p := f.sign(t, []scopedAuthorityRequirement{w(scopedEA, "add", scopedCurrent)})
		require.NoError(t, f.verify(p))
		f.s.v.memberRule = rule
		if rule == scopedSyntheticThresholdOnly {
			require.NoError(t, f.verify(p))
		} else {
			require.Error(t, f.verify(p), "unknown or actually stronger member condition cannot inherit the synthetic choice")
		}
	}
	for _, name := range []string{"R02_pre_token_succession", "R04_root_profile_missing", "R05_NG_succession", "R06_technical_profile_missing", "R07_independent_safety_admission", "R09_objective_claim", "R09_healthy_dissent", "R09_read_absence", "R09_compromised_but_signing"} {
		t.Run(name, func(t *testing.T) {
			f := qualSP227ConstitutionNew(t, all, all[0].Programme)
			f.r.phase = scopedDirect
			f.r.use = scopedTechnicalRepair
			if name == "R02_pre_token_succession" {
				f.r.use = scopedInitialSuccession
				f.s.v.preToken = true
			}
			if name == "R09_objective_claim" || name == "R09_healthy_dissent" || name == "R09_read_absence" || name == "R09_compromised_but_signing" {
				f.r.use = scopedEmergencyAdd
				f.s.v.claim = name
			}
			f.bindRequest()
			p := f.sign(t, []scopedAuthorityRequirement{w(scopedEA, "add", scopedCurrent)})
			// Native proof is independently valid; missing competence cannot be
			// satisfied by a threshold signature or by a reader's invented claim.
			d, e := f.s.ScopedAuthoritySigningDigest(f.r, p[0])
			require.NoError(t, e)
			s := f.s.v.current[scopedEA]
			require.NoError(t, verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", s.threshold, s.members, p[0].indices, p[0].signatures, d, 5, 4096))
			require.Error(t, f.verify(p))
		})
	}
}

// Reuse the existing pending/final/T04 owner; only its existing admission hook
// is composed with the scoped writer. This does not prove native evidence truth.
type qualSP227WriterHost struct {
	*qualPendingFinalHost
	f      *qualSP227Constitution
	proofs []scopedAuthorityProof
}

func (h *qualSP227WriterHost) Admit(c []byte) error {
	if err := h.qualPendingFinalHost.Admit(c); err != nil {
		return err
	}
	if !bytes.Equal(blake2b.NewBlake2b().Compute(string(c)), h.f.r.digest) {
		return errInvalidAuthoritySignatures
	}
	return h.f.verify(h.proofs)
}
func TestQualSP227AdoptedWriterComposition(t *testing.T) {
	all := qualSP227Rosters(t)
	p := qualPendingFinalNew(t)
	f := qualSP227ConstitutionNew(t, all, all[0].Programme)
	f.r.use, f.r.phase, f.r.purpose = scopedDecisionWriter, scopedDirect, scopedCDA
	f.r.subject, f.r.digest = bytes.Clone(p.c.key), bytes.Clone(p.digest)
	f.s.v.writer = &scopedWriterContext{f.r.subject, f.r.digest, []byte("current CEB"), []byte("current CEB")}
	f.bindRequest()
	h := &qualSP227WriterHost{p.h, f, f.sign(t, []scopedAuthorityRequirement{qualSP227Want(scopedCDA, "writer", scopedCurrent)})}
	p.r.host = h
	before := p.s.JournalLen()
	h.proofs[0].signatures[0][0] ^= 1
	require.Error(t, p.r.stage(p.c))
	require.Equal(t, before, p.s.JournalLen())
	require.Empty(t, qualRegistryValue(t, p.s, string(p.pendingKey)))
	h.proofs = f.sign(t, []scopedAuthorityRequirement{qualSP227Want(scopedCDA, "writer", scopedCurrent)})
	require.NoError(t, p.r.stage(p.c))
	p.staged(t)
	n := p.s.JournalLen()
	require.NoError(t, p.r.stage(p.c))
	require.Equal(t, n, p.s.JournalLen())
	require.Error(t, p.r.promote(p.c, []byte("unadmitted canonical evidence")))
	p.staged(t)
	require.NoError(t, p.promote())
	final, digest, err := p.r.final(p.c.key)
	require.NoError(t, err)
	require.Equal(t, p.encoded, final)
	require.Equal(t, p.digest, digest)
}

func TestQualSP227AdoptedBusinessArmComposition(t *testing.T) {
	all := qualSP227Rosters(t)
	w := qualSP227Want
	for _, use := range []scopedAuthorityUse{scopedCEBChange, scopedRoleRotation, scopedRetirement} {
		t.Run(fmt.Sprint(use), func(t *testing.T) {
			g := qualGovernedActionNew(t)
			g.initialize(t)
			id := g.propose(t)
			_, digest, _ := g.expected(100)
			f := qualSP227ConstitutionNew(t, all, all[0].Programme)
			f.r.use, f.r.action, f.r.owner, f.r.digest, f.r.targetShard = use, bytes.Clone(id), bytes.Clone(id), bytes.Clone(digest), 1
			f.s.v.targetRole = scopedSA
			f.s.v.activeOwner = bytes.Clone(id)
			g.x = qualGovernedContext(t, g.c, core.MetachainShardId, 105)
			// One source for the action store and the authority check (D-3).
			f.s.v.time, f.source = g.x, g.g.timeSource
			f.bindRequest()
			wants := []scopedAuthorityRequirement{w(scopedPA, "approval", scopedCurrent), w(scopedPR, "approval", scopedCurrent)}
			if use == scopedRoleRotation {
				wants = append(wants, w(scopedSA, "predecessor", scopedCurrent), w(scopedSA, "possession", scopedProposed))
			}
			h := &qualSP227GASHost{g.h, f, f.sign(t, wants)}
			h.arm = true
			g.g.host = h
			require.NoError(t, g.g.authorize(g.x, id, qualSP227Packet(h.proofs)))
			f.s.v.status = "EXECUTABLE"
			f.r.phase = scopedArm
			f.s.v.arm = &scopedArmContext{use, f.r.action, f.r.owner, f.r.digest, 1}
			f.bindRequest()
			h.proofs = f.sign(t, []scopedAuthorityRequirement{w(scopedPA, "arm", scopedCurrent)})
			f.s.v.arm.targetShard = 0
			g.denied(t, func() error { return g.g.start(g.x, id, qualSP227Packet(h.proofs)) })
			require.Zero(t, h.effects)
			f.s.v.arm.targetShard = 1
			h.badOutput = true
			g.denied(t, func() error { return g.g.start(g.x, id, qualSP227Packet(h.proofs)) })
			h.badOutput = false
			r, _, _, err := g.g.load(id)
			require.NoError(t, err)
			require.Equal(t, "EXECUTABLE", r.status)
			require.NoError(t, g.g.start(g.x, id, qualSP227Packet(h.proofs)))
			r, _, _, err = g.g.load(id)
			require.NoError(t, err)
			require.Equal(t, "IN_PROGRESS", r.status)
			require.Equal(t, HeaderMilliseconds(112), r.expiry)
			g.denied(t, func() error { return g.g.start(g.x, id, qualSP227Packet(h.proofs)) })
		})
	}
}

// All six bound programme/platform rosters consume the same literal adopted
// row expectations; the isolated hostile guards above remain unchanged.
func TestQualSP227AdoptedAllProgrammes(t *testing.T) {
	all := qualSP227Rosters(t)
	programmes := make(map[string]bool)
	for _, b := range all {
		programmes[b.Programme] = true
	}
	w := qualSP227Want
	for programme := range programmes {
		t.Run(programme, func(t *testing.T) {
			f := qualSP227ConstitutionNew(t, all, programme)
			f.r.use, f.r.phase = scopedScopeAppointment, scopedDirect
			f.s.v.preToken = true
			f.s.v.scopeAppointment.unappointed = true
			f.s.v.nativeActor = bytes.Clone(f.s.v.scopeAppointment.owner)
			f.bindRequest()
			p := f.sign(t, []scopedAuthorityRequirement{w(scopedIPAA, "possession", scopedProposed), w(scopedPR, "possession", scopedProposed)})
			require.NoError(t, f.verify(p))
			f.s.v.scopeAppointment.unappointed = false
			require.Error(t, f.verify(p))
			for _, role := range []string{scopedCDA, scopedFCA, scopedIRA} {
				for _, enabled := range []bool{false, true} {
					f = qualSP227ConstitutionNew(t, all, programme)
					f.r.use, f.r.phase, f.r.purpose = scopedDecisionWriter, scopedDirect, role
					f.s.v.reconciliationEnabled = enabled
					f.s.v.writer = &scopedWriterContext{f.r.subject, f.r.digest, []byte("current CEB"), []byte("current CEB")}
					f.bindRequest()
					p = f.sign(t, []scopedAuthorityRequirement{w(role, "writer", scopedCurrent)})
					if role == scopedIRA && !enabled {
						require.Error(t, f.verify(p))
					} else {
						require.NoError(t, f.verify(p))
						f.s.v.writer.currentCEB = []byte("foreign")
						require.Error(t, f.verify(p))
					}
				}
			}
			for _, use := range []scopedAuthorityUse{scopedCEBChange, scopedRoleRotation, scopedRetirement} {
				for _, high := range []bool{false, true} {
					f = qualSP227ConstitutionNew(t, all, programme)
					f.r.use, f.r.phase, f.r.targetShard = use, scopedArm, 1
					f.s.v.status = "EXECUTABLE"
					f.s.v.highImpact = high
					f.s.v.targetRole = scopedSA
					f.s.v.arm = &scopedArmContext{use, f.r.action, f.r.owner, f.r.digest, 1}
					f.bindRequest()
					p = f.sign(t, []scopedAuthorityRequirement{w(scopedPA, "arm", scopedCurrent)})
					require.NoError(t, f.verify(p))
					f.s.v.memberRule = 0
					require.Error(t, f.verify(p))
				}
			}
		})
	}
}
