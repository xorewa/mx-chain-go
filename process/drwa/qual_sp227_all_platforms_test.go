package drwa

import (
	"bytes"
	"fmt"
	"sort"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
	"github.com/stretchr/testify/require"
)

// SP2-27 on every platform. Each of the six bound synthetic programmes runs
// the complete verifier (real Ed25519 keys, real threshold, pair and time
// checks) against the expectations of the independent model in
// qual_sp227_matrix_model_test.go. No test here installs a native reader or
// writes a cancellation effect. A claim is admitted only under the labelled
// synthetic premise of the owner's answer A-1; no real claim rule exists.

type qualSP227Bench struct {
	f        *qualSP227Constitution
	all      []qualSP227Binding
	scope    string
	sets     [4]map[string]scopedAuthoritySet // current, bound, proposed, frozenProposed
	at       uint64
	time     *HeaderTimeContext
	signed   map[string][]scopedAuthorityProof
	verified int
}

func qualSP227Programmes(all []qualSP227Binding) []string {
	seen := make(map[string]bool)
	var out []string
	for _, b := range all {
		if !seen[b.Programme] {
			seen[b.Programme] = true
			out = append(out, b.Programme)
		}
	}
	sort.Strings(out)
	return out
}

func qualSP227BenchNew(t *testing.T, all []qualSP227Binding, programme string) *qualSP227Bench {
	t.Helper()
	f := qualSP227ConstitutionNew(t, all, programme)
	v := f.s.v
	return &qualSP227Bench{f: f, all: all, scope: programme, sets: [4]map[string]scopedAuthoritySet{v.current, v.bound, v.proposed, v.frozenProposed},
		at: 110, time: v.time, signed: make(map[string][]scopedAuthorityProof)}
}

func qualSP227CloneSets(in map[string]scopedAuthoritySet) map[string]scopedAuthoritySet {
	out := make(map[string]scopedAuthoritySet, len(in))
	for role, set := range in {
		out[role] = set
	}
	return out
}

// load installs one symbolic case as the reader's view, with this programme's
// authority sets, and returns nothing else: the request is in b.f.r.
func (b *qualSP227Bench) load(t *testing.T, c qualSP227Case) {
	t.Helper()
	b.f.r = qualSP227Request(c, b.scope)
	v := qualSP227View(c, b.f.r)
	v.current, v.bound, v.proposed, v.frozenProposed = b.sets[0], b.sets[1], b.sets[2], b.sets[3]
	if c.evaluatedAt != 0 {
		// The time owner keeps one evaluated header active; a new one replaces it.
		if b.at != c.evaluatedAt {
			b.at, b.time = c.evaluatedAt, qualGovernedContext(t, b.f.clock, core.MetachainShardId, c.evaluatedAt)
		}
		v.time = b.time
	}
	b.f.s.v = v
}

// proofs signs the listed requirements over the loaded request with the keys
// of the sets the literal source names. Results are reused for equal inputs.
func (b *qualSP227Bench) proofs(t *testing.T, wants []scopedAuthorityRequirement) []scopedAuthorityProof {
	t.Helper()
	r := b.f.r
	key := fmt.Sprint(r.use, r.phase, r.purpose, r.targetShard, len(r.action), len(r.owner), qualSP227Sorted(wants))
	if p, ok := b.signed[key]; ok {
		return append([]scopedAuthorityProof(nil), p...)
	}
	p := b.f.sign(t, wants)
	b.signed[key] = p
	return append([]scopedAuthorityProof(nil), p...)
}

func (b *qualSP227Bench) verify(p []scopedAuthorityProof) error {
	b.verified++
	return b.f.verify(p)
}

// check runs the verifier on a case with natively valid proofs of the roles
// "fallback" names when the model refuses the case, and compares the outcome.
func (b *qualSP227Bench) check(t *testing.T, c qualSP227Case, fallback []scopedAuthorityRequirement) bool {
	t.Helper()
	want := qualSP227ModelVerified(c)
	b.load(t, c)
	wants := fallback
	if want.admit {
		wants = want.proofs
	}
	p := b.proofs(t, wants)
	err := b.verify(p)
	if (err == nil) != want.admit {
		require.Failf(t, "verifier differs from the model", "programme %s model admit=%t production error=%v case %+v", b.scope, want.admit, err, c)
	}
	return want.admit
}

func TestQualSP227AllPlatformsMatrix(t *testing.T) {
	all := qualSP227Rosters(t)
	programmes := qualSP227Programmes(all)
	require.Len(t, programmes, 6)
	planFaults, verifierFaults := qualSP227PlanFaults(), qualSP227VerifierFaults()
	for _, programme := range programmes {
		t.Run(programme, func(t *testing.T) {
			// Platforms share only read-only inputs; each has its own bench.
			t.Parallel()
			b := qualSP227BenchNew(t, all, programme)
			configurations, admittedCells, refusedCells, factors := 0, 0, 0, 0
			for _, healthy := range qualSP227Configurations() {
				row := qualSP227ModelVerified(healthy)
				if !row.admit {
					continue
				}
				configurations++
				require.True(t, b.check(t, healthy, nil))
				admittedCells++
				// Every required factor is mandatory; an extra, natively valid
				// approval of a role the row does not name is refused as well.
				p := b.proofs(t, row.proofs)
				for i := range p {
					missing := append(append([]scopedAuthorityProof(nil), p[:i]...), p[i+1:]...)
					require.ErrorIs(t, b.verify(missing), errInvalidAuthoritySignatures)
					factors++
				}
				extra := qualSP227Need(scopedEA, "approval", scopedCurrent)
				require.ErrorIs(t, b.verify(append(b.proofs(t, row.proofs), b.proofs(t, []scopedAuthorityRequirement{extra})...)), errInvalidAuthoritySignatures)
				// One changed premise at a time. Cases the model still admits were
				// compared at selector level in TestQualSP227IndependentSingleFaults;
				// here every refusal is exercised through the verifier with the
				// healthy row's natively valid approvals.
				for _, fault := range planFaults {
					c := healthy
					fault.apply(&c)
					if qualSP227ModelVerified(c).admit {
						continue
					}
					require.False(t, b.check(t, c, row.proofs), fault.name)
					refusedCells++
				}
				for _, fault := range verifierFaults {
					c := healthy
					fault.apply(&c)
					if b.check(t, c, row.proofs) {
						admittedCells++
					} else {
						refusedCells++
					}
				}
			}
			// 452 again: answer D-04 had refused 88 configurations (proposal,
			// start and drive of a cap increase, 3 x 8; proposal and drive of an
			// administrative transfer, 2 x 4 purposes x 8); the owner admitted
			// those five cells on 28 November (entry 9, point 9c).
			require.Equal(t, 452, configurations, "admitted configurations, counted by the model")
			t.Logf("SP2-27_INDEPENDENT_COUNT platform=%s configurations=%d admitted_cells=%d refused_cells=%d mandatory_factor_checks=%d verifier_calls=%d",
				programme, configurations, admittedCells, refusedCells, factors, b.verified)
		})
	}
}

// qualSP227Mutate changes one role's set wherever the named source reads it,
// keeping "bound equals current" true so that only the intended rule can refuse.
func (b *qualSP227Bench) mutate(role string, source int, change func(*scopedAuthoritySet)) {
	maps := []int{0, 1}
	if source == scopedProposed || source == scopedFrozenProposed {
		maps = []int{2, 3}
	}
	for _, i := range maps {
		b.sets[i] = qualSP227CloneSets(b.sets[i])
		set := b.sets[i][role]
		set.members = append([][]byte(nil), set.members...)
		change(&set)
		b.sets[i][role] = set
	}
}

func (b *qualSP227Bench) source(req scopedAuthorityRequirement) scopedAuthoritySet {
	return b.sets[map[int]int{scopedCurrent: 0, scopedBound: 1, scopedProposed: 2, scopedFrozenProposed: 3}[req.source]][req.role]
}

// Required pairs: for every admitted configuration on every platform, every two
// different roles the row resolves must have distinct set identifiers and no
// common key at any roster position, signed or not.
func TestQualSP227AllPlatformsRequiredPairs(t *testing.T) {
	all := qualSP227Rosters(t)
	for _, programme := range qualSP227Programmes(all) {
		t.Run(programme, func(t *testing.T) {
			// Platforms share only read-only inputs; each has its own bench.
			t.Parallel()
			pairs := 0
			b := qualSP227BenchNew(t, all, programme)
			original := b.sets
			for _, healthy := range qualSP227Configurations() {
				row := qualSP227ModelVerified(healthy)
				if !row.admit {
					continue
				}
				succeeds := make(map[string]bool) // roles that also appear as a proposed successor
				for _, binding := range row.bindings {
					succeeds[binding.role] = succeeds[binding.role] || binding.source == scopedProposed || binding.source == scopedFrozenProposed
				}
				for i, left := range row.bindings {
					for _, right := range row.bindings[i+1:] {
						if left.role == right.role {
							continue // one role in two purposes counts once
						}
						pairs++
						// Change the side that has no successor version in this row, so
						// the separate lineage rule of a rotation stays satisfied.
						changed, other := right, left
						if succeeds[right.role] && !succeeds[left.role] {
							changed, other = left, right
						}
						for _, kind := range []string{"shared_identifier", "shared_key"} {
							b.sets = original
							peer := b.source(other)
							b.mutate(changed.role, changed.source, func(s *scopedAuthoritySet) {
								if kind == "shared_identifier" {
									s.id = bytes.Clone(peer.id)
								} else {
									s.members[3] = bytes.Clone(peer.members[3])
								}
							})
							b.load(t, healthy)
							// Signed after the change: every certificate matches the set
							// the reader now reports, so only pair independence can refuse.
							p := b.f.sign(t, row.proofs)
							require.ErrorIs(t, b.verify(p), errInvalidAuthoritySignatures, "%s %s/%s in %+v", kind, left.role, right.role, healthy)
						}
					}
				}
			}
			require.NotZero(t, pairs)
			t.Logf("SP2-27_INDEPENDENT_COUNT platform=%s required_pairs=%d checks=%d", programme, pairs, 2*pairs)
		})
	}
}

// The class floors of Part A L1354-1366, as counts of distinct approving roles
// at authorisation. Possession and predecessor proofs are not approvals.
func TestQualSP227IndependentRoleFloors(t *testing.T) {
	approving := map[string]bool{"admission": true, "approval": true, "cancellation": true, "withdrawal": true, "release": true, "cap": true, "delegation": true, "request": true, "burn": true, "add": true}
	for _, row := range []struct {
		name          string
		use           scopedAuthorityUse
		phase         scopedAuthorityPhase
		purpose       string
		preToken      bool
		ordinary, top int
	}{
		{"intent", scopedIntent, scopedDirect, "", false, 2, 2},
		{"registration", scopedRegistration, scopedDirect, "", false, 2, 2},
		{"activation", scopedActivation, scopedDirect, "", false, 3, 4},
		{"registered_cancellation", scopedRegisteredCancellation, scopedDirect, "", false, 2, 2},
		{"ordinary_CEB_change", scopedCEBChange, scopedAuthorize, "", false, 2, 3},
		{"cap_increase", scopedCapIncrease, scopedAuthorize, "", false, 3, 4},
		{"normal_rotation", scopedRoleRotation, scopedAuthorize, "", false, 2, 3},
		{"holder_recovery_transfer", scopedAdministrativeTransfer, scopedAuthorize, "HOLDER_RECOVERY", false, 2, 2},
		{"redemption_transfer", scopedAdministrativeTransfer, scopedAuthorize, "REDEMPTION", false, 2, 2},
		{"external_order_transfer", scopedAdministrativeTransfer, scopedAuthorize, "EXTERNAL_ORDER", false, 3, 3},
		{"wind_down_transfer", scopedAdministrativeTransfer, scopedAuthorize, "PROGRAM_WIND_DOWN", false, 3, 3},
		{"emergency_release", scopedEmergencyRelease, scopedDirect, "", false, 2, 3},
		{"retirement", scopedRetirement, scopedAuthorize, "", false, 2, 3},
		{"discretionary_cancellation", scopedCEBCancellation, scopedCancel, "", false, 2, 3},
		{"pre_token_provider_binding", scopedProviderBinding, scopedDirect, "", true, 2, 2},
	} {
		for _, high := range []bool{false, true} {
			c := qualSP227Healthy(row.use, row.phase, row.purpose, high, row.preToken, false)
			require.True(t, qualSP227ComparePlan(t, c), row.name)
			r := qualSP227Request(c, "synthetic scope")
			proofs, _, err := scopedAuthorityPlan(r, qualSP227View(c, r))
			require.NoError(t, err)
			roles := make(map[string]bool)
			for _, p := range proofs {
				if approving[p.kind] {
					roles[p.role] = true
				}
			}
			want := row.ordinary
			if high {
				want = row.top
			}
			require.Len(t, roles, want, "%s high=%t", row.name, high)
		}
	}
}

func qualSP227SignWith(t *testing.T, f *qualSP227Constitution, want scopedAuthorityRequirement, set scopedAuthoritySet, keys []crypto.PrivateKey, indices []uint64) scopedAuthorityProof {
	t.Helper()
	p := scopedAuthorityProof{requirement: want, id: bytes.Clone(set.id), hash: bytes.Clone(set.hash), version: set.version, notBefore: 100, until: 120, indices: indices}
	digest, err := f.s.ScopedAuthoritySigningDigest(f.r, p)
	require.NoError(t, err)
	for _, i := range indices {
		signature, signErr := (&singlesig.Ed25519Signer{}).Sign(keys[i], digest)
		require.NoError(t, signErr)
		p.signatures = append(p.signatures, signature)
	}
	return p
}

// D01 floor through the constitution verifier, for every role of every
// platform that an adopted row uses: n>=5 and ceil(3n/5)<=t<=n, a missing
// member never lowers the denominator, and t=n needs every member.
func TestQualSP227AllPlatformsThresholdFloor(t *testing.T) {
	all := qualSP227Rosters(t)
	rows := []struct {
		role    string
		use     scopedAuthorityUse
		purpose string
		high    bool
		kind    string
	}{
		{scopedIPAA, scopedAdmissionWithdrawal, "", false, "withdrawal"},
		{scopedPA, scopedEmergencyRelease, "", false, "release"},
		{scopedPR, scopedEmergencyRelease, "", false, "release"},
		{scopedATA, scopedEmergencyRelease, "", true, "release"},
		{scopedSA, scopedTerminalBurn, "", false, "burn"},
		{scopedEA, scopedEmergencyAdd, "", false, "add"},
		{scopedCDA, scopedDecisionWriter, scopedCDA, false, "writer"},
		{scopedFCA, scopedDecisionWriter, scopedFCA, false, "writer"},
		{scopedIRA, scopedDecisionWriter, scopedIRA, false, "writer"},
	}
	cells := 0
	for _, programme := range qualSP227Programmes(all) {
		for _, row := range rows {
			t.Run(programme+"/"+row.role, func(t *testing.T) {
				var roster qualSP227Binding
				for _, candidate := range all {
					if candidate.Programme == programme && candidate.Role == row.role {
						roster = candidate
					}
				}
				require.Len(t, roster.Private, 5)
				healthy := qualSP227Healthy(row.use, scopedDirect, row.purpose, row.high, false, true)
				model := qualSP227ModelVerified(healthy)
				require.True(t, model.admit)
				target := qualSP227Need(row.role, row.kind, scopedCurrent)
				for _, v := range []struct {
					name            string
					n               int
					threshold       uint64
					signers         []uint64
					memberBound     uint64
					expectAdmission bool
				}{
					{"n5_t3_three_signers", 5, 3, []uint64{0, 1, 4}, 5, true},
					{"n5_t3_two_signers", 5, 3, []uint64{0, 4}, 5, false},
					{"n5_t2_below_floor", 5, 2, []uint64{0, 1, 4}, 5, false},
					{"n5_t4_three_signers", 5, 4, []uint64{0, 1, 4}, 5, false},
					{"n5_t4_four_signers", 5, 4, []uint64{0, 1, 2, 4}, 5, true},
					{"n5_t5_four_signers", 5, 5, []uint64{0, 1, 2, 3}, 5, false},
					{"n5_t5_all_signers", 5, 5, []uint64{0, 1, 2, 3, 4}, 5, true},
					{"n5_t6_above_n", 5, 6, []uint64{0, 1, 2, 3, 4}, 5, false},
					{"n4_roster", 4, 3, []uint64{0, 1, 2}, 5, false},
					{"n6_over_measured_bound", 6, 4, []uint64{0, 1, 2, 5}, 5, false},
					{"n6_t3_below_floor", 6, 3, []uint64{0, 1, 5}, 6, false},
					{"n6_t4_three_signers", 6, 4, []uint64{0, 1, 5}, 6, false},
					{"n6_t4_four_signers", 6, 4, []uint64{0, 1, 2, 5}, 6, true},
				} {
					b := qualSP227BenchNew(t, all, programme)
					keys := append(append([]crypto.PrivateKey(nil), roster.Private...), roster.StandbyPrivate[0])
					b.mutate(row.role, scopedCurrent, func(s *scopedAuthoritySet) {
						s.threshold = v.threshold
						if v.n == 6 {
							s.members = append(s.members, roster.Standby[0])
						}
						s.members = s.members[:v.n]
					})
					b.f.limits.members = v.memberBound
					b.load(t, healthy)
					var p []scopedAuthorityProof
					for _, want := range model.proofs {
						if want == target {
							p = append(p, qualSP227SignWith(t, b.f, want, b.source(want), keys, v.signers))
						} else {
							p = append(p, b.f.sign(t, []scopedAuthorityRequirement{want})...)
						}
					}
					err := b.verify(p)
					cells++
					if v.expectAdmission {
						require.NoError(t, err, v.name)
					} else {
						require.ErrorIs(t, err, errInvalidAuthoritySignatures, v.name)
					}
				}
			})
		}
	}
	require.Equal(t, 6*9*13, cells)
}

// The floor also holds for a role the row resolves but whose certificate the
// phase does not ask for: the coapprovers behind a proposal, start or arm, the
// frozen sets of a started action, and the peer writers of a decision.
func TestQualSP227AllPlatformsUnsignedRoleFloor(t *testing.T) {
	all := qualSP227Rosters(t)
	writer := qualSP227Healthy(scopedDecisionWriter, scopedDirect, scopedCDA, false, false, true)
	cells := 0
	for _, programme := range qualSP227Programmes(all) {
		for _, row := range []struct {
			name   string
			c      qualSP227Case
			role   string
			source int
		}{
			{"proposal_PR", qualSP227Healthy(scopedCEBChange, scopedPropose, "", false, false, false), scopedPR, scopedCurrent},
			{"start_PR", qualSP227Healthy(scopedRetirement, scopedStart, "", false, false, false), scopedPR, scopedCurrent},
			{"start_high_ATA", qualSP227Healthy(scopedCEBChange, scopedStart, "", true, false, false), scopedATA, scopedCurrent},
			{"arm_ATA", qualSP227Healthy(scopedAdministrativeTransfer, scopedArm, "REDEMPTION", false, false, false), scopedATA, scopedCurrent},
			{"arm_cap_SA_successor", qualSP227Healthy(scopedRoleRotation, scopedArm, "", false, false, false), scopedSA, scopedProposed},
			// The drive of a cap increase is admitted again (entry 9, point 9c).
			{"drive_cap_PA", qualSP227Healthy(scopedCapIncrease, scopedDrive, "", false, false, false), scopedPA, scopedBound},
			{"drive_cap_SA", qualSP227Healthy(scopedCapIncrease, scopedDrive, "", false, false, false), scopedSA, scopedBound},
			{"drive_transfer_ATA", qualSP227Healthy(scopedAdministrativeTransfer, scopedDrive, "REDEMPTION", false, false, false), scopedATA, scopedBound},
			{"drive_PA", qualSP227Healthy(scopedCEBChange, scopedDrive, "", false, false, false), scopedPA, scopedBound},
			{"drive_SA_predecessor", qualSP227Healthy(scopedRoleRotation, scopedDrive, "", false, false, false), scopedSA, scopedBound},
			{"arm_order_PR", qualSP227Healthy(scopedAdministrativeTransfer, scopedArm, "EXTERNAL_ORDER", false, false, false), scopedPR, scopedCurrent},
			{"drive_frozen_successor", qualSP227Healthy(scopedRoleRotation, scopedDrive, "", false, false, false), scopedSA, scopedFrozenProposed},
			{"writer_peer_FCA", writer, scopedFCA, scopedCurrent},
			{"writer_peer_IRA", writer, scopedIRA, scopedCurrent},
		} {
			model := qualSP227ModelVerified(row.c)
			require.True(t, model.admit, row.name)
			for _, proof := range model.proofs {
				require.False(t, proof.role == row.role && proof.source == row.source, "%s: the changed set signs nothing in this phase", row.name)
			}
			for _, change := range []string{"none", "t2_below_floor", "t6_above_n", "n4_roster", "no_identifier", "no_hash", "absent"} {
				b := qualSP227BenchNew(t, all, programme)
				b.mutate(row.role, row.source, func(s *scopedAuthoritySet) {
					switch change {
					case "t2_below_floor":
						s.threshold = 2
					case "t6_above_n":
						s.threshold = 6
					case "n4_roster":
						s.members = s.members[:4]
					case "no_identifier":
						s.id = nil
					case "no_hash":
						s.hash = nil
					}
				})
				if change == "absent" {
					for i := range b.sets {
						if (i < 2) == (row.source == scopedCurrent || row.source == scopedBound) {
							delete(b.sets[i], row.role)
						}
					}
				}
				b.load(t, row.c)
				err := b.verify(b.f.sign(t, model.proofs))
				cells++
				if change == "none" {
					require.NoError(t, err, row.name)
				} else {
					require.ErrorIs(t, err, errInvalidAuthoritySignatures, "%s %s", row.name, change)
				}
			}
		}
	}
	require.Equal(t, 6*14*7, cells)
}

func qualSP227Subsets(roles []string) [][]string {
	var out [][]string
	for mask := 0; mask < 1<<len(roles); mask++ {
		var subset []string
		for i, role := range roles {
			if mask&(1<<i) != 0 {
				subset = append(subset, role)
			}
		}
		out = append(out, subset)
	}
	return out
}

// D02 cancellation, claim and loss matrix at selector level: every claim
// label, every subset of the five roles the P09 table names (and malformed
// lists), both floors, every replacement target, every action status, both
// cutoffs and each evidence premise.
func TestQualSP227IndependentCancellationLossMatrix(t *testing.T) {
	five := []string{scopedPA, scopedPR, scopedSA, scopedATA, scopedEA}
	lostLists := append(qualSP227Subsets(five), []string{scopedPA, scopedPA}, []string{scopedIPAA}, []string{scopedPA, scopedCDA})
	cells, admitted, alternatives := 0, 0, 0
	for _, claim := range []string{"", "UNAVAILABLE", "COMPROMISED", "DISSENT", "READ_ABSENCE"} {
		for _, lost := range lostLists {
			for _, high := range []bool{false, true} {
				for _, target := range append([]string{""}, five...) {
					roles, configured := qualSP227Coalition(claim, lost, high, target)
					got, err := scopedCancellationRoles(scopedAuthorityView{claim: claim, lostRoles: lost, highImpact: high, targetRole: target})
					require.Equal(t, configured, err == nil, "claim %q lost %v high %t target %q", claim, lost, high, target)
					if configured {
						require.Equal(t, roles, got)
						// No unavailable or compromised subject is a required signer,
						// no role is counted twice, and the class floor is kept.
						seen := make(map[string]bool)
						for _, role := range got {
							require.NotContains(t, lost, role)
							require.False(t, seen[role])
							seen[role] = true
						}
						floor := 2
						if high || len(lost) != 0 {
							floor = 3
						}
						require.Len(t, got, floor)
						if len(lost) != 0 {
							alternatives++
						}
					}
					for _, status := range qualSP227Statuses {
						for _, cut := range []int{0, 1, 2, 3} {
							for _, premise := range []string{"", "no_policy", "no_evidence", "permission"} {
								for _, owner := range []string{"self", "other", ""} {
									c := qualSP227Healthy(scopedCEBCancellation, scopedCancel, "", high, false, false)
									c.claim, c.lost, c.targetRole, c.status, c.activeOwner = claim, lost, target, status, owner
									c.adminCut, c.currentCut = cut&1 != 0, cut&2 != 0
									c.noFrozenPolicy, c.noTargetEvidence, c.openPermission = premise == "no_policy", premise == "no_evidence", premise == "permission"
									cells++
									if qualSP227ComparePlan(t, c) {
										admitted++
									}
								}
							}
						}
					}
				}
			}
		}
	}
	require.Equal(t, 5*35*2*6*6*4*4*3, cells)
	// Two claim labels x {PA, PR, PA+PR} x two floors x six targets, plus the
	// high-impact ATA subject with ATA as the replacement target.
	require.Equal(t, 2*3*2*6+2, alternatives)
	t.Logf("SP2-27_INDEPENDENT_COUNT cancellation_loss cells=%d selector_admitted=%d configured_loss_alternatives=%d", cells, admitted, alternatives)
}

// The same matrix through the verifier on every platform. Without a claim the
// bound (equal to current) roles cancel before either cutoff only. With a claim
// the pre-established coalition's natively valid certificates are refused
// unless the reader supplies the SYNTHETIC premise of the owner's answer A-1
// (27 November 2026). That premise is for qualification on the synthetic
// rosters only; the real rule for a loss or compromise claim stays OPEN (R09).
func TestQualSP227AllPlatformsCancellation(t *testing.T) {
	all := qualSP227Rosters(t)
	for _, programme := range qualSP227Programmes(all) {
		t.Run(programme, func(t *testing.T) {
			// Platforms share only read-only inputs; each has its own bench.
			t.Parallel()
			b := qualSP227BenchNew(t, all, programme)
			admitted, refused, claims, claimAdmitted, unconfigured, premiseFaults := 0, 0, 0, 0, 0, 0
			for _, high := range []bool{false, true} {
				base := qualSP227Healthy(scopedCEBCancellation, scopedCancel, "", high, false, false)
				floor := qualSP227Model(base).proofs
				for _, status := range qualSP227Statuses {
					for _, cut := range []int{0, 1, 2, 3} {
						for _, premise := range []string{"", "no_policy", "no_evidence", "permission", "FAIL_SAFE"} {
							for _, owner := range []string{"self", "other", ""} {
								c := base
								c.status, c.activeOwner = status, owner
								c.adminCut, c.currentCut = cut&1 != 0, cut&2 != 0
								c.noFrozenPolicy, c.noTargetEvidence, c.openPermission = premise == "no_policy", premise == "no_evidence", premise == "permission"
								if premise == "FAIL_SAFE" {
									c.plane = "FAIL_SAFE"
								}
								if b.check(t, c, floor) {
									admitted++
								} else {
									refused++
								}
							}
						}
					}
				}
				for _, claim := range []string{"UNAVAILABLE", "COMPROMISED"} {
					for _, lost := range [][]string{{scopedPA}, {scopedPR}, {scopedPA, scopedPR}, {scopedATA}} {
						c := base
						c.claim, c.lost, c.targetRole = claim, lost, scopedATA
						roles, configured := qualSP227Coalition(claim, lost, high, c.targetRole)
						if !configured {
							// No alternative configured: pending, premise or not.
							c.evidence = "ok"
							require.False(t, b.check(t, c, floor))
							unconfigured++
							continue
						}
						var wants []scopedAuthorityRequirement
						for _, role := range roles {
							wants = append(wants, qualSP227Need(role, "cancellation", scopedBound))
						}
						b.load(t, c)
						p := b.proofs(t, wants)
						for _, proof := range p {
							set := b.source(proof.requirement)
							digest, err := b.f.s.ScopedAuthoritySigningDigest(b.f.r, proof)
							require.NoError(t, err)
							require.NoError(t, verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", set.threshold, set.members, proof.indices, proof.signatures, digest, 5, 4096))
						}
						require.ErrorIs(t, b.verify(p), errInvalidAuthoritySignatures, "without the synthetic premise a claim is refused: the real rule is OPEN")
						claims++
						// Owner answer A-1: with the labelled synthetic premise the
						// pre-established alternative cancels.
						c.evidence = "ok"
						require.True(t, b.check(t, c, nil), "claim %s lost %v high %t", claim, lost, high)
						claimAdmitted++
						// Every alternative role is needed. The lost subject neither
						// signs nor vetoes: its own valid certificate is refused as an
						// extra approval and in place of any alternative role.
						for i := range p {
							require.ErrorIs(t, b.verify(append(append([]scopedAuthorityProof(nil), p[:i]...), p[i+1:]...)), errInvalidAuthoritySignatures)
						}
						for _, role := range lost {
							own := b.proofs(t, []scopedAuthorityRequirement{qualSP227Need(role, "cancellation", scopedBound)})
							require.ErrorIs(t, b.verify(append(append([]scopedAuthorityProof(nil), p...), own...)), errInvalidAuthoritySignatures)
							for i := range p {
								replaced := append([]scopedAuthorityProof(nil), p...)
								replaced[i] = own[0]
								require.ErrorIs(t, b.verify(replaced), errInvalidAuthoritySignatures)
							}
						}
						require.NoError(t, b.verify(p))
						// The premise must name exactly this claim, these roles, this
						// request and the policy frozen before the incident.
						for _, wrong := range []string{"claim", "lost_other", "lost_more", "lost_fewer", "domain", "scope", "subject", "action", "owner", "digest", "policy"} {
							d := c
							d.evidence = wrong
							require.False(t, b.check(t, d, wants), wrong)
							premiseFaults++
						}
						// Status, both cutoffs and the native evidence decide as before.
						for _, status := range qualSP227Statuses {
							for _, cut := range []int{0, 1, 2, 3} {
								for _, premise := range []string{"", "no_policy", "no_evidence", "permission", "FAIL_SAFE"} {
									d := c
									d.status = status
									d.adminCut, d.currentCut = cut&1 != 0, cut&2 != 0
									d.noFrozenPolicy, d.noTargetEvidence, d.openPermission = premise == "no_policy", premise == "no_evidence", premise == "permission"
									if premise == "FAIL_SAFE" {
										d.plane = "FAIL_SAFE"
									}
									want := (status == "PROPOSED" || status == "EXECUTABLE" || status == "IN_PROGRESS") && cut == 0 && premise == ""
									require.Equal(t, want, b.check(t, d, wants), "%s cut %d %s", status, cut, premise)
								}
							}
						}
						// An alternative role must be bound and still current. One that
						// is missing or whose version changed leaves the action pending.
						saved := b.sets
						for _, role := range roles {
							for _, side := range []int{0, 1} {
								b.sets = saved
								b.sets[side] = qualSP227CloneSets(b.sets[side])
								set := b.sets[side][role]
								set.version++
								b.sets[side][role] = set
								b.load(t, c)
								require.ErrorIs(t, b.verify(b.f.sign(t, wants)), errInvalidAuthoritySignatures)
							}
							b.sets = saved
							b.sets[0] = qualSP227CloneSets(b.sets[0])
							delete(b.sets[0], role)
							b.load(t, c)
							require.ErrorIs(t, b.verify(b.f.sign(t, wants)), errInvalidAuthoritySignatures)
						}
						b.sets = saved
						b.load(t, c)
						require.NoError(t, b.verify(p))
					}
				}
			}
			// 2 floors x {PROPOSED, EXECUTABLE} x 3 owners + IN_PROGRESS with its own owner.
			require.Equal(t, 2*(2*3+1), admitted)
			require.Equal(t, 2*6*4*5*3-admitted, refused)
			require.Equal(t, 2*(3+3+1), claims)
			// The same fourteen alternatives are admitted with the synthetic
			// premise; ATA lost on the ordinary floor has no alternative.
			require.Equal(t, claims, claimAdmitted)
			require.Equal(t, 2, unconfigured)
			require.Equal(t, 11*claims, premiseFaults)
			// A set version that changed between the frozen policy and now refuses
			// for each role of the floor, in either direction.
			for _, role := range []string{scopedPA, scopedPR, scopedATA} {
				for _, side := range []int{0, 1} {
					v := qualSP227BenchNew(t, all, programme)
					c := qualSP227Healthy(scopedCEBCancellation, scopedCancel, "", true, false, false)
					v.sets[side] = qualSP227CloneSets(v.sets[side])
					set := v.sets[side][role]
					set.version++
					v.sets[side][role] = set
					v.load(t, c)
					require.ErrorIs(t, v.verify(v.f.sign(t, qualSP227Model(c).proofs)), errInvalidAuthoritySignatures)
				}
			}
			// P11 administrative-transfer cancellation: PROPOSED only, each purpose.
			for _, purpose := range qualSP227ATPurposes {
				for _, status := range qualSP227Statuses {
					c := qualSP227Healthy(scopedATCancellation, scopedCancel, purpose, false, false, false)
					fallback := qualSP227Model(c).proofs
					c.status = status
					require.Equal(t, status == "PROPOSED", b.check(t, c, fallback), "%s %s", purpose, status)
				}
			}
			t.Logf("SP2-27_INDEPENDENT_COUNT platform=%s cancellation admitted=%d refused=%d claim_coalitions_refused_without_premise=%d admitted_with_synthetic_premise=%d premise_faults_refused=%d no_alternative=%d",
				programme, admitted, refused, claims, claimAdmitted, premiseFaults, unconfigured)
		})
	}
}

// qualSP227Foreign builds a successor version of one role whose keys are all
// different from the current version's: the same role of another programme.
func qualSP227Foreign(t *testing.T, all []qualSP227Binding, current scopedAuthoritySet, donor, role string) (scopedAuthoritySet, []crypto.PrivateKey) {
	t.Helper()
	for _, b := range all {
		if b.Programme == donor && b.Role == role {
			return scopedAuthoritySet{id: bytes.Clone(current.id), hash: blake2b.NewBlake2b().Compute(string(qualRecordFrame(b.Members...))),
				predecessor: bytes.Clone(current.hash), version: current.version + 1, predecessorVersion: current.version,
				threshold: b.Threshold, members: b.Members}, b.Private
		}
	}
	require.FailNow(t, "no donor roster")
	return scopedAuthoritySet{}, nil
}

// D02: a blocked successor cannot authorise itself or cancel its blocker.
// The successor is a complete, canonical version with its own keys. Its own
// signatures prove possession and nothing else.
func TestQualSP227AllPlatformsBlockedSuccessor(t *testing.T) {
	all := qualSP227Rosters(t)
	programmes := qualSP227Programmes(all)
	for index, programme := range programmes {
		donor := programmes[(index+1)%len(programmes)]
		for _, target := range []string{scopedPA, scopedPR, scopedSA, scopedATA, scopedEA, scopedCDA} {
			t.Run(programme+"/"+target, func(t *testing.T) {
				b := qualSP227BenchNew(t, all, programme)
				successor, successorKeys := qualSP227Foreign(t, all, b.sets[0][target], donor, target)
				b.sets[2], b.sets[3] = qualSP227CloneSets(b.sets[2]), qualSP227CloneSets(b.sets[3])
				b.sets[2][target], b.sets[3][target] = successor, successor
				b.f.proposedKeys[target] = successorKeys
				rotation := qualSP227Healthy(scopedRoleRotation, scopedAuthorize, "", false, false, false)
				rotation.targetRole = target
				row := qualSP227ModelVerified(rotation)
				require.True(t, row.admit)
				b.load(t, rotation)
				lawful := b.f.sign(t, row.proofs)
				require.NoError(t, b.verify(lawful), "predecessor authorises, successor proves possession")
				// 1. The successor signs the slots of its own role's current version.
				for i, proof := range lawful {
					if proof.requirement.role != target || proof.requirement.source != scopedCurrent {
						continue
					}
					forged := append([]scopedAuthorityProof(nil), lawful...)
					forged[i] = qualSP227SignWith(t, b.f, proof.requirement, b.sets[0][target], successorKeys, []uint64{0, 1, 4})
					require.ErrorIs(t, b.verify(forged), errInvalidAuthoritySignatures, "successor keys under the current version")
					asSuccessor := proof.requirement
					asSuccessor.source = scopedProposed
					forged[i] = qualSP227SignWith(t, b.f, asSuccessor, successor, successorKeys, []uint64{0, 1, 4})
					require.ErrorIs(t, b.verify(forged), errInvalidAuthoritySignatures, "a successor certificate is not the predecessor's authorisation")
				}
				// A successor must continue its predecessor: same stable identifier,
				// a later version, the predecessor's exact hash and version, new content.
				for _, breakLineage := range []string{"other_identifier", "same_version", "earlier_version", "no_predecessor_hash", "other_predecessor_hash", "other_predecessor_version", "same_content"} {
					broken := successor
					switch breakLineage {
					case "other_identifier":
						broken.id = []byte("another lineage")
					case "same_version":
						broken.version = b.sets[0][target].version
					case "earlier_version":
						broken.version = 0
					case "no_predecessor_hash":
						broken.predecessor = nil
					case "other_predecessor_hash":
						broken.predecessor = []byte("another predecessor")
					case "other_predecessor_version":
						broken.predecessorVersion++
					case "same_content":
						broken.hash = bytes.Clone(b.sets[0][target].hash)
					}
					saved := b.sets
					b.sets[2], b.sets[3] = qualSP227CloneSets(b.sets[2]), qualSP227CloneSets(b.sets[3])
					b.sets[2][target], b.sets[3][target] = broken, broken
					b.load(t, rotation)
					// Signed over the broken successor's own identity, version and hash.
					require.ErrorIs(t, b.verify(b.f.sign(t, row.proofs)), errInvalidAuthoritySignatures, breakLineage)
					b.sets = saved
					b.load(t, rotation)
				}
				require.NoError(t, b.verify(lawful))
				// 2. Possession alone, without the predecessor and the class floor.
				for _, proof := range lawful {
					if proof.requirement.source == scopedProposed {
						require.ErrorIs(t, b.verify([]scopedAuthorityProof{proof}), errInvalidAuthoritySignatures)
					}
				}
				// 3. The successor cannot cancel the action that blocks it, whether
				// it signs as itself or under the bound version, and a reader that
				// reports the successor as bound while it is not current is refused.
				if target != scopedPA && target != scopedPR {
					return
				}
				cancel := qualSP227Healthy(scopedCEBCancellation, scopedCancel, "", false, false, false)
				cancel.status, cancel.targetRole = "EXECUTABLE", target
				floor := qualSP227ModelVerified(cancel)
				b.load(t, cancel)
				healthyCancel := b.f.sign(t, floor.proofs)
				require.NoError(t, b.verify(healthyCancel))
				for i, proof := range healthyCancel {
					if proof.requirement.role != target {
						continue
					}
					forged := append([]scopedAuthorityProof(nil), healthyCancel...)
					forged[i] = qualSP227SignWith(t, b.f, proof.requirement, b.sets[1][target], successorKeys, []uint64{0, 1, 4})
					require.ErrorIs(t, b.verify(forged), errInvalidAuthoritySignatures)
					asSuccessor := proof.requirement
					asSuccessor.source = scopedProposed
					forged[i] = qualSP227SignWith(t, b.f, asSuccessor, successor, successorKeys, []uint64{0, 1, 4})
					require.ErrorIs(t, b.verify(forged), errInvalidAuthoritySignatures)
					b.sets[1] = qualSP227CloneSets(b.sets[1])
					b.sets[1][target] = successor
					b.load(t, cancel)
					forged[i] = qualSP227SignWith(t, b.f, proof.requirement, successor, successorKeys, []uint64{0, 1, 4})
					require.ErrorIs(t, b.verify(forged), errInvalidAuthoritySignatures, "canonical but not current")
				}
			})
		}
	}
}

// D02: unlawful cross-scope signatures. For every ordered pair of platforms,
// B's sets cannot approve in A's scope, B's valid certificates do not carry
// over to A, and an A certificate does not follow the request to scope B.
func TestQualSP227AllPlatformsCrossScope(t *testing.T) {
	all := qualSP227Rosters(t)
	programmes := qualSP227Programmes(all)
	pairs := 0
	for _, own := range programmes {
		for _, foreign := range programmes {
			if own == foreign {
				continue
			}
			pairs++
			for _, c := range []qualSP227Case{
				qualSP227Healthy(scopedCEBChange, scopedAuthorize, "", true, false, false),
				qualSP227Healthy(scopedProviderBinding, scopedDirect, "", false, true, false),
				qualSP227Healthy(scopedCEBCancellation, scopedCancel, "", false, false, false),
			} {
				a, b := qualSP227BenchNew(t, all, own), qualSP227BenchNew(t, all, foreign)
				row := qualSP227ModelVerified(c)
				require.True(t, row.admit)
				a.load(t, c)
				b.load(t, c)
				lawful := a.f.sign(t, row.proofs)
				require.NoError(t, a.verify(lawful))
				theirs := b.f.sign(t, row.proofs)
				require.NoError(t, b.verify(theirs))
				require.ErrorIs(t, a.verify(theirs), errInvalidAuthoritySignatures, "certificates of another scope")
				// B's keys sign A's exact request under A's set identities.
				var forged []scopedAuthorityProof
				for _, want := range row.proofs {
					keys := b.f.keys[want.role]
					if want.source == scopedProposed {
						keys = b.f.proposedKeys[want.role]
					}
					forged = append(forged, qualSP227SignWith(t, a.f, want, a.source(want), keys, []uint64{0, 1, 4}))
				}
				require.ErrorIs(t, a.verify(forged), errInvalidAuthoritySignatures, "foreign keys")
				for i := range lawful { // one foreign approver among lawful ones
					mixed := append([]scopedAuthorityProof(nil), lawful...)
					mixed[i] = forged[i]
					require.ErrorIs(t, a.verify(mixed), errInvalidAuthoritySignatures)
				}
				// The request is moved to B's scope; A's certificates stay behind.
				a.f.r.scope = []byte(foreign)
				require.ErrorIs(t, a.verify(lawful), errInvalidAuthoritySignatures)
				a.f.bindRequest()
				a.f.s.v.scopeAppointment.scope = []byte(foreign)
				require.ErrorIs(t, a.verify(lawful), errInvalidAuthoritySignatures, "scope is part of every signed request")
			}
		}
	}
	require.Equal(t, 30, pairs)
}

// qualSP227ModelPairs derives the independent-role pairs from the adopted rows:
// two roles are a pair when one adopted row makes them sign together. The role
// a rotation or a provider binding replaces can be any role, so its lineage
// proofs are left out here; at use they are checked against that row's floor.
func qualSP227ModelPairs() map[[2]string]bool {
	pairs := make(map[[2]string]bool)
	add := func(roles []string) {
		for i, left := range roles {
			for _, right := range roles[i+1:] {
				if left < right {
					pairs[[2]string{left, right}] = true
				} else if right < left {
					pairs[[2]string{right, left}] = true
				}
			}
		}
	}
	for _, c := range qualSP227Configurations() {
		row := qualSP227Model(c)
		if !row.admit {
			continue
		}
		var roles []string
		for _, b := range row.bindings {
			lineage := (c.use == scopedRoleRotation || c.use == scopedProviderBinding) && (b.kind == "predecessor" || b.kind == "possession")
			if !lineage {
				roles = append(roles, b.role)
			}
		}
		add(roles)
	}
	for _, claim := range []string{"UNAVAILABLE", "COMPROMISED"} {
		for _, lost := range qualSP227Subsets([]string{scopedPA, scopedPR, scopedSA, scopedATA, scopedEA}) {
			for _, high := range []bool{false, true} {
				if roles, configured := qualSP227Coalition(claim, lost, high, scopedATA); configured {
					add(roles)
				}
			}
		}
	}
	return pairs
}

func qualSP227Paired(pairs map[[2]string]bool, left, right string) bool {
	return pairs[[2]string{left, right}] || pairs[[2]string{right, left}]
}

// Owner answer D-03: the list the production check uses is the list the
// adopted rows give, fourteen pairs, each once.
func TestQualSP227IndependentPairList(t *testing.T) {
	model := qualSP227ModelPairs()
	require.Len(t, model, 14)
	seen := make(map[[2]string]bool)
	for _, pair := range scopedIndependentPairs {
		require.NotEqual(t, pair[0], pair[1])
		require.True(t, qualSP227Paired(model, pair[0], pair[1]), "%v is not given by an adopted row", pair)
		key := pair
		if key[1] < key[0] {
			key = [2]string{pair[1], pair[0]}
		}
		require.False(t, seen[key], "%v listed twice", pair)
		seen[key] = true
	}
	require.Len(t, seen, len(model))
	var names []string
	for pair := range model {
		names = append(names, pair[0]+" / "+pair[1])
	}
	sort.Strings(names)
	t.Logf("SP2-27_INDEPENDENT_COUNT derived_pairs=%d %q", len(names), names)
}

// Owner answer D-03 on every platform: a set that an operation installs must
// be independent of the installed set of every role it is paired with, also
// when the operation's own class does not name that role. For each role as
// successor and each other role as peer, a shared key or a shared identifier
// is refused exactly when the two are a pair or the peer is in the row.
func TestQualSP227AllPlatformsSuccessorPairs(t *testing.T) {
	all := qualSP227Rosters(t)
	nine := []string{scopedIPAA, scopedPA, scopedPR, scopedSA, scopedATA, scopedEA, scopedCDA, scopedFCA, scopedIRA}
	pairs := qualSP227ModelPairs()
	type operation struct {
		name string
		c    qualSP227Case
	}
	for _, programme := range qualSP227Programmes(all) {
		t.Run(programme, func(t *testing.T) {
			// Platforms share only read-only inputs; each has its own bench.
			t.Parallel()
			b := qualSP227BenchNew(t, all, programme)
			original := b.sets
			cells, refused, byListOnly := 0, 0, 0
			for _, successor := range nine {
				var operations []operation
				if successor == scopedIPAA || successor == scopedPR {
					operations = append(operations, operation{"first_appointment", qualSP227Healthy(scopedScopeAppointment, scopedDirect, "", false, true, false)})
				}
				if successor == scopedPA {
					operations = append(operations, operation{"registration", qualSP227Healthy(scopedRegistration, scopedDirect, "", false, false, false)},
						operation{"activation", qualSP227Healthy(scopedActivation, scopedDirect, "", false, false, false)})
				}
				if successor != scopedIPAA {
					for _, phase := range []scopedAuthorityPhase{scopedPropose, scopedAuthorize, scopedStart, scopedArm, scopedDrive} {
						c := qualSP227Healthy(scopedRoleRotation, phase, "", false, false, false)
						c.targetRole = successor
						operations = append(operations, operation{fmt.Sprintf("rotation_phase_%d", phase), c})
						c = qualSP227Healthy(scopedProviderBinding, phase, "", false, false, false)
						c.provider = successor
						operations = append(operations, operation{fmt.Sprintf("provider_binding_phase_%d", phase), c})
					}
				}
				for _, op := range operations {
					row := qualSP227ModelVerified(op.c)
					if !row.admit {
						continue // e.g. the arm of a provider binding has no adopted row
					}
					source, inRow := -1, make(map[string]bool)
					for _, binding := range row.bindings {
						if binding.role == successor && (binding.source == scopedProposed || binding.source == scopedFrozenProposed) {
							source = binding.source
						} else {
							inRow[binding.role] = true
						}
					}
					require.NotEqual(t, -1, source, "%s installs a %s set", op.name, successor)
					b.sets = original
					b.load(t, op.c)
					require.NoError(t, b.verify(b.f.sign(t, row.proofs)), "%s %s", op.name, successor)
					for _, peer := range nine {
						if peer == successor {
							continue
						}
						for _, kind := range []string{"shared_key", "shared_identifier"} {
							b.sets = original
							installed, next := b.sets[0][peer], b.sets[2][successor]
							if kind == "shared_key" {
								b.mutate(successor, source, func(s *scopedAuthoritySet) { s.members[3] = bytes.Clone(installed.members[3]) })
							} else {
								b.mutate(peer, scopedCurrent, func(s *scopedAuthoritySet) { s.id = bytes.Clone(next.id) })
							}
							b.load(t, op.c)
							err := b.verify(b.f.sign(t, row.proofs))
							cells++
							if inRow[peer] || qualSP227Paired(pairs, successor, peer) {
								require.ErrorIs(t, err, errInvalidAuthoritySignatures, "%s: %s successor and installed %s, %s", op.name, successor, peer, kind)
								refused++
								if !inRow[peer] {
									byListOnly++
								}
							} else {
								require.NoError(t, err, "%s: %s and %s are not a pair (%s)", op.name, successor, peer, kind)
							}
						}
					}
				}
			}
			require.NotZero(t, byListOnly)
			require.NotEqual(t, cells, refused)
			// A paired role that has no installed set has nothing to share; one
			// whose installed roster exceeds the measured member bound is refused.
			rotation := qualSP227Healthy(scopedRoleRotation, scopedAuthorize, "", false, false, false)
			row := qualSP227ModelVerified(rotation)
			b.sets = original
			b.sets[0], b.sets[1] = qualSP227CloneSets(b.sets[0]), qualSP227CloneSets(b.sets[1])
			delete(b.sets[0], scopedEA)
			delete(b.sets[1], scopedEA)
			b.load(t, rotation)
			require.NoError(t, b.verify(b.f.sign(t, row.proofs)))
			b.sets = original
			var spare []byte
			for _, roster := range all {
				if roster.Programme == programme && roster.Role == scopedEA {
					spare = roster.Standby[0]
				}
			}
			b.mutate(scopedEA, scopedCurrent, func(s *scopedAuthoritySet) { s.members = append(s.members, spare) })
			b.load(t, rotation)
			require.ErrorIs(t, b.verify(b.f.sign(t, row.proofs)), errInvalidAuthoritySignatures)
			// A started rotation: the frozen successor is checked against the peer
			// set bound to the action and against the peer set current now.
			drive := qualSP227Healthy(scopedRoleRotation, scopedDrive, "", false, false, false)
			for _, side := range []int{0, 1} {
				b.sets = original
				frozen := b.sets[3][scopedSA]
				b.sets[side] = qualSP227CloneSets(b.sets[side])
				peer := b.sets[side][scopedEA]
				peer.members = append([][]byte(nil), peer.members...)
				peer.members[2] = bytes.Clone(frozen.members[2])
				b.sets[side][scopedEA] = peer
				b.load(t, drive)
				require.ErrorIs(t, b.verify(nil), errInvalidAuthoritySignatures, "side %d", side)
			}
			b.sets = original
			b.load(t, drive)
			require.NoError(t, b.verify(nil))
			b.sets = original
			t.Logf("SP2-27_INDEPENDENT_COUNT platform=%s successor_pair_cells=%d refused=%d refused_by_pair_list_only=%d admitted=%d", programme, cells, refused, byListOnly, cells-refused)
		})
	}
}

// The five cells no adopted row states, on every platform. Answer D-04 of
// 27 November refused them; the owner admitted all five on 28 November
// (decision entry 9, point 9c): PA proposal, PA start and unsigned drive of a
// cap increase; PA proposal and unsigned drive of an administrative transfer.
// Standing as for P01-P17: synthetic qualification only. Each cell has its
// positive case and the refusals that must still hold. The start of a transfer
// and the arm of a cap increase stay refused.
func TestQualSP227AllPlatformsUnstatedPhases(t *testing.T) {
	all := qualSP227Rosters(t)
	pa := func(kind string) []scopedAuthorityRequirement {
		return []scopedAuthorityRequirement{qualSP227Need(scopedPA, kind, scopedCurrent)}
	}
	type cell struct {
		name    string
		use     scopedAuthorityUse
		phase   scopedAuthorityPhase
		purpose []string
		proofs  []scopedAuthorityRequirement // literal expectation, not taken from the model
		admit   bool
		owner   bool // one of the five cells of point 9c
	}
	none := []string{""}
	cells := []cell{
		// the five cells of point 9c
		{"cap_increase_proposal", scopedCapIncrease, scopedPropose, none, pa("proposal"), true, true},
		{"cap_increase_start", scopedCapIncrease, scopedStart, none, pa("start"), true, true},
		{"cap_increase_drive", scopedCapIncrease, scopedDrive, none, nil, true, true},
		{"administrative_transfer_proposal", scopedAdministrativeTransfer, scopedPropose, qualSP227ATPurposes, pa("proposal"), true, true},
		{"administrative_transfer_drive", scopedAdministrativeTransfer, scopedDrive, qualSP227ATPurposes, nil, true, true},
		// refused before and after: no adopted row and no owner answer
		{"cap_increase_arm", scopedCapIncrease, scopedArm, none, pa("arm"), false, false},
		{"administrative_transfer_start", scopedAdministrativeTransfer, scopedStart, qualSP227ATPurposes, pa("start"), false, false},
		// stated by P08 and P10
		{"cap_increase_authorization", scopedCapIncrease, scopedAuthorize, none, nil, true, false},
		{"administrative_transfer_authorization", scopedAdministrativeTransfer, scopedAuthorize, qualSP227ATPurposes, nil, true, false},
		{"administrative_transfer_arm", scopedAdministrativeTransfer, scopedArm, qualSP227ATPurposes, pa("arm"), true, false},
		// stated by P16 for P06/P07/P12
		{"CEB_change_proposal", scopedCEBChange, scopedPropose, none, pa("proposal"), true, false},
		{"CEB_change_start", scopedCEBChange, scopedStart, none, pa("start"), true, false},
		{"CEB_change_drive", scopedCEBChange, scopedDrive, none, nil, true, false},
		{"retirement_proposal", scopedRetirement, scopedPropose, none, pa("proposal"), true, false},
		{"retirement_start", scopedRetirement, scopedStart, none, pa("start"), true, false},
		{"retirement_drive", scopedRetirement, scopedDrive, none, nil, true, false},
	}
	checked, positives, negatives := 0, 0, 0
	for _, programme := range qualSP227Programmes(all) {
		b := qualSP227BenchNew(t, all, programme)
		refused := func(c qualSP227Case, wants []scopedAuthorityRequirement, edit func(), why string) {
			t.Helper()
			b.load(t, c)
			p := b.proofs(t, wants)
			if edit != nil {
				edit()
			}
			require.ErrorIs(t, b.verify(p), errInvalidAuthoritySignatures, why)
			negatives++
		}
		for _, row := range cells {
			for _, purpose := range row.purpose {
				for _, high := range []bool{false, true} {
					c := qualSP227Healthy(row.use, row.phase, purpose, high, false, false)
					model := qualSP227ModelVerified(c)
					require.Equal(t, row.admit, model.admit, row.name)
					require.Equal(t, row.admit, qualSP227ComparePlan(t, c), row.name)
					require.Equal(t, row.admit, b.check(t, c, row.proofs), "%s %s high=%t", row.name, purpose, high)
					checked++
					full := qualSP227Model(qualSP227Healthy(row.use, scopedAuthorize, purpose, high, false, false)).proofs
					if !row.admit {
						// Nor with the whole approving coalition's certificates.
						require.False(t, b.check(t, c, full), row.name)
						continue
					}
					if row.phase == scopedAuthorize {
						continue
					}
					// Positive, with the literal certificates of this table.
					require.ElementsMatch(t, qualSP227Sorted(row.proofs), qualSP227Sorted(model.proofs), row.name)
					b.load(t, c)
					require.NoError(t, b.verify(b.proofs(t, row.proofs)), "%s %s high=%t", row.name, purpose, high)
					positives++
					if !row.owner {
						continue
					}
					why := fmt.Sprintf("%s %s high=%t: ", row.name, purpose, high)
					// Wrong purpose.
					wrong := c
					if row.use == scopedAdministrativeTransfer {
						wrong.purpose = "UNLISTED_PURPOSE"
						refused(wrong, row.proofs, nil, why+"a purpose outside the adopted four")
						wrong.purpose = ""
						refused(wrong, row.proofs, nil, why+"no purpose")
					} else {
						wrong.purpose = "REDEMPTION"
						refused(wrong, row.proofs, nil, why+"a cap increase bears no purpose")
					}
					if row.phase == scopedDrive {
						// The driver signs nothing and carries only the stored step.
						refused(c, pa("start"), nil, why+"a certificate with the drive")
						refused(c, full, nil, why+"the approving coalition with the drive")
						for name, edit := range map[string]func(){
							"another body":         func() { b.f.r.digest = []byte("another class body commitment") },
							"another action":       func() { b.f.r.action = []byte("another immutable action") },
							"another target shard": func() { b.f.r.targetShard = 2 },
							"another subject":      func() { b.f.r.subject = []byte("another subject") },
							"another owner":        func() { b.f.r.owner = []byte("another action owner") },
						} {
							refused(c, nil, edit, why+"driver with "+name)
						}
						// No approval behind the drive.
						for name, fault := range map[string]func(*qualSP227Case){
							"not started":      func(x *qualSP227Case) { x.status = "EXECUTABLE" },
							"only proposed":    func(x *qualSP227Case) { x.status = "PROPOSED" },
							"no authorization": func(x *qualSP227Case) { x.noAuthorization = true },
							"another's action": func(x *qualSP227Case) { x.activeOwner = "other" },
							"no active owner":  func(x *qualSP227Case) { x.activeOwner = "" },
						} {
							x := c
							fault(&x)
							refused(x, nil, nil, why+"drive with "+name)
						}
						continue
					}
					// Wrong role, wrong certificate kind, missing or surplus certificate.
					kind := row.proofs[0].kind
					for _, role := range []string{scopedPR, scopedSA, scopedATA, scopedEA} {
						refused(c, []scopedAuthorityRequirement{qualSP227Need(role, kind, scopedCurrent)}, nil, why+"signed by "+role)
					}
					other := map[string]string{"proposal": "start", "start": "proposal"}[kind]
					refused(c, pa(other), nil, why+"a PA certificate of the other kind")
					refused(c, pa("approval"), nil, why+"a PA approval certificate")
					refused(c, nil, nil, why+"no certificate")
					refused(c, full, nil, why+"the approving coalition instead of PA")
					// The signed request is not the stored one.
					refused(c, row.proofs, func() { b.f.r.digest = []byte("another class body commitment") }, why+"another body")
					refused(c, row.proofs, func() { b.f.r.targetShard = 2 }, why+"another target shard")
					if row.phase == scopedStart {
						// No approval behind the start.
						for name, fault := range map[string]func(*qualSP227Case){
							"only proposed":    func(x *qualSP227Case) { x.status = "PROPOSED" },
							"already started":  func(x *qualSP227Case) { x.status = "IN_PROGRESS" },
							"no authorization": func(x *qualSP227Case) { x.noAuthorization = true },
							"another's action": func(x *qualSP227Case) { x.activeOwner = "other" },
						} {
							x := c
							fault(&x)
							refused(x, row.proofs, nil, why+"start with "+name)
						}
					}
				}
			}
		}
	}
	require.Equal(t, 6*2*(3+2*4+1+4+1+4+4+6), checked)
	// Per platform and impact class: cap proposal 1, cap start 1, cap drive 1,
	// transfer proposal 4, transfer drive 4, transfer arm 4, six P16 cells.
	require.Equal(t, 6*2*(3+4+4+4+6), positives)
	t.Logf("SP2-27_OWNER_ADMITTED_CELLS cells=5 checked=%d positives=%d negatives=%d", checked, positives, negatives)
}
