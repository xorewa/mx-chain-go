package drwa

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-31 test world. One metachain account store holds a bootstrap intent
// whose embedded admission decision is a real scoped admission decision, the
// programme's admission head and version, and the decision row. Registration
// and activation run through the real owners of T13/T44 bound to the scoped
// admission records; the withdrawal is authorised by the programme's admission
// authority through the scoped authority check. Rosters and windows are
// synthetic (adopted rows P02-P05, synthetic qualification only).

const qualSP231Token = "TOKEN-abcdef"

func qualSP231Hash(kind string, fields ...[]byte) []byte {
	all := append([][]byte{[]byte("DRWA/SCOPED_ADMISSION/" + kind + "/candidate1"), []byte("n")}, fields...)
	return blake2b.NewBlake2b().Compute(string(qualRecordFrame(all...)))
}

type qualSP231NoMandate struct{}

func (qualSP231NoMandate) IsInterfaceNil() bool { return false }
func (qualSP231NoMandate) Verify(string, []byte, []byte, []byte, []byte) error {
	return errScopedAdmission
}

type qualSP231World struct {
	t         *testing.T
	f         *qualRegistrationAdmissionFixture
	records   *scopedAdmissionRecords
	approvals *registrationApprovalCodec
	owner     []byte
	role      []byte
	scope     []byte
	outer     []byte
	d         scopedAdmissionDecision
	body      []byte
	auth      *qualSP227Constitution
}

func (w *qualSP231World) decisionBody(d scopedAdmissionDecision) []byte {
	return qualRecordFrame(w.scope, d.issuer, d.version, d.commitment, d.authority, binary.BigEndian.AppendUint64(nil, uint64(d.validUntil)))
}

func (w *qualSP231World) decisionID(d scopedAdmissionDecision) []byte {
	return qualSP231Hash("DECISION", w.scope, d.issuer, d.version)
}

// qualSP231New builds the world. validUntil is the decision's validity bound
// (the intent of the registration fixtures expires at time 1, where every
// covered transition of these tests executes). bind says whether the
// registration owner is bound to the scoped admission records.
func qualSP231New(t *testing.T, validUntil uint64, bind bool) *qualSP231World {
	t.Helper()
	w := &qualSP231World{t: t, owner: bytes.Repeat([]byte{1}, 32)}
	template, ctx, _ := qualR3Fixture(t, 200)
	w.role = bytes.Clone(ctx.admission.role)
	f := &qualRegistrationAdmissionFixture{}
	f.body, _, _, _, f.v = qualCreationIntent(core.FungibleESDT)
	f.body.programID = []byte("program")
	w.scope = qualRecordFrame([]byte("n"), w.owner, f.body.programID)
	w.outer = qualSP231Hash("VERSION", w.scope, nil, ctx.admission.body)
	w.d = scopedAdmissionDecision{owner: bytes.Clone(w.owner), program: bytes.Clone(f.body.programID), issuer: bytes.Clone(f.body.issuer),
		version: []byte("decision-1"), commitment: []byte("off-chain-evidence-commitment"), authority: bytes.Clone(w.outer), validUntil: HeaderMilliseconds(validUntil)}
	w.body = w.decisionBody(w.d)
	f.body.issuerProgramAdmissionDecision = bytes.Clone(w.body)
	encoded, digest, id := qualCreationIntentBytes(f.body)
	f.store = qualRegistrationStore(t, 0)
	qualRecordPut(t, f.store, append([]byte(registrationIntentPrefix), id...), qualRecordFrame(encoded, []byte("OPEN"), nil))
	budgetKey := []byte(scopedAdmissionPrefix + "budget")
	budget := binary.BigEndian.AppendUint64(nil, 2)
	budget = binary.BigEndian.AppendUint64(budget, uint64(len(budgetKey)+32+len(registrationIntentPrefix)+len(id)+len(qualRecordFrame(encoded, []byte("OPEN"), nil))))
	budget = binary.BigEndian.AppendUint64(budget, 10)
	budget = binary.BigEndian.AppendUint64(budget, 0)
	qualRecordPut(t, f.store, budgetKey, budget)
	// The programme's admission lineage: one version, the scope head, the
	// REGISTER_TOKEN_ADMISSION purpose head, and the decision row.
	key := func(kind string, identity []byte) []byte {
		return append([]byte(scopedAdmissionPrefix+kind+"@"), identity...)
	}
	qualRecordPut(t, f.store, key("version", w.outer), qualRecordFrame(w.scope, nil, ctx.admission.body))
	qualRecordPut(t, f.store, key("current", qualSP231Hash("SCOPE", w.scope)), qualRecordFrame(w.scope, w.outer))
	qualRecordPut(t, f.store, key("current", qualSP231Hash("SCOPE", w.scope, []byte("REGISTER_TOKEN_ADMISSION"))), qualRecordFrame(w.scope, w.outer))
	qualRecordPut(t, f.store, key("decision", w.decisionID(w.d)), w.body)
	_, err := f.store.Commit()
	require.NoError(t, err)
	coordinator := testscommon.NewMultiShardsCoordinatorMock(3)
	coordinator.CurrentShard = core.MetachainShardId
	r, boundary, err := NewRegistryRegistration(f.store, coordinator, 2)
	require.NoError(t, err)
	f.boundary = boundary
	f.owner, err = r.BindIntent(id, digest, bytes.Repeat([]byte{0x22}, 32), &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	f.hook, _ = qualT42Hook(t, f.store, core.MetachainShardId, true)
	_, f.end = qualT42Install(t, f.hook, core.MetachainShardId, 1)
	f.verify = &qualRegistrationVerifier{t: t, id: bytes.Clone(id), intentHash: bytes.Clone(digest), body: encoded,
		creation: f.v.bodyHash, roles: make(map[string]w03SignatureFixture)}
	var evidence [][]byte
	for _, purpose := range qualRegistrationPurposes {
		role := w03SignatureProof(t, 5, 3, []uint64{0, 1, 2})
		role.digest = blake2b.NewBlake2b().Compute(string(qualRecordFrame([]byte(purpose), id, digest, encoded, f.v.bodyHash,
			[]byte{0, 0, 0, 0, 0, 0, 0, 1}, []byte{0, 0, 0, 10})))
		role.sign(t)
		f.verify.roles[purpose] = role
		evidence = append(evidence, qualRecordFrame(role.signatures...))
	}
	f.proofs = RegistrationProofs{evidence[0], evidence[1], evidence[2], evidence[3], evidence[4], evidence[5], evidence[6], evidence[7]}
	f.admit, err = f.owner.WithRegistrationAdmission(f.hook, []byte("n"), 10, RegistrationResourceLimits{1000, 1048576, 100}, f.verify, f.proofs)
	require.NoError(t, err)
	w.f = f
	w.records, err = newScopedAdmissionRecords(f.store, boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(),
		[]byte("n"), scopedAdmissionLimits{4096, 100, 1 << 20, 100}, qualSP231NoMandate{}, f.hook)
	require.NoError(t, err)
	w.approvals, err = newRegistrationApprovalCodec(w.records.codec, template.bounds)
	require.NoError(t, err)
	if bind {
		require.NoError(t, f.admit.WithAdmissionWithdrawal(w.records, w.approvals, w.owner, w.role))
	}
	all := qualSP227Rosters(t)
	w.auth = qualSP227ConstitutionNew(t, all, qualSP227Programmes(all)[0])
	return w
}

// request is the scoped authority request of a withdrawal of d, written here
// from row P04 and the records' digest rule, not taken from the product.
func (w *qualSP231World) request(d scopedAdmissionDecision) scopedAuthorityRequest {
	id := w.decisionID(d)
	return scopedAuthorityRequest{use: scopedAdmissionWithdrawal, phase: scopedDirect, locus: core.MetachainShardId, targetShard: core.MetachainShardId,
		domain: []byte("n"), scope: bytes.Clone(w.scope), subject: id, action: bytes.Clone(id), owner: bytes.Clone(d.issuer),
		digest: qualSP231Hash("WITHDRAW", w.scope, id, w.decisionBody(d), w.outer)}
}

// certificate signs one requirement over a request with the roster keys of
// the role's current set, members 0, 1 and 4.
func (w *qualSP231World) certificate(r scopedAuthorityRequest, role, kind string, notBefore, until uint64, signers ...uint64) scopedAuthorityProof {
	w.t.Helper()
	if len(signers) == 0 {
		signers = []uint64{0, 1, 4}
	}
	set := w.auth.s.v.current[role]
	p := scopedAuthorityProof{requirement: scopedAuthorityRequirement{role, kind, scopedCurrent}, id: bytes.Clone(set.id), hash: bytes.Clone(set.hash),
		version: set.version, notBefore: HeaderMilliseconds(notBefore), until: HeaderMilliseconds(until)}
	digest, err := w.auth.s.ScopedAuthoritySigningDigest(r, p)
	require.NoError(w.t, err)
	for _, i := range signers {
		signature, signErr := (&singlesig.Ed25519Signer{}).Sign(w.auth.keys[role][i], digest)
		require.NoError(w.t, signErr)
		p.indices, p.signatures = append(p.indices, i), append(p.signatures, signature)
	}
	return p
}

// withdraw runs the product withdrawal of d with the given certificates. The
// reader's view is the synthetic programme view for exactly this request at
// the block in execution.
func (w *qualSP231World) withdraw(d scopedAdmissionDecision, proofs ...scopedAuthorityProof) (admissionWithdrawalOutcome, error) {
	w.t.Helper()
	w.auth.r = w.request(d)
	w.auth.bindRequest()
	context, err := w.f.hook.EvaluatedHeaderTimeContext()
	if err != nil {
		return admissionWithdrawalRefused, err
	}
	w.auth.s.v.time = context
	return w.records.withdrawAuthorized(context, d, proofs,
		scopedWithdrawalAuthority{codec: w.auth.codec, reader: w.auth.s, limits: w.auth.limits})
}

// withdrawn makes the withdrawal of the world's decision effective.
func (w *qualSP231World) withdrawn() {
	w.t.Helper()
	outcome, err := w.withdraw(w.d, w.certificate(w.request(w.d), scopedIPAA, "withdrawal", 1, 20))
	require.NoError(w.t, err)
	require.Equal(w.t, admissionWithdrawalEffective, outcome)
}

func (w *qualSP231World) status(d scopedAdmissionDecision) admissionDecisionStatus {
	w.t.Helper()
	status, err := w.records.decisionStatus(d)
	require.NoError(w.t, err)
	return status
}

func (w *qualSP231World) state() ([]byte, int) { return qualSP224State(w.t, w.f.store) }

// register runs DRWARegisterToken's owner path; created counts executions of
// the native creation.
func (w *qualSP231World) register(created *int) error {
	w.t.Helper()
	return w.f.register(w.t, func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		*created++
		return qualRegistrationCreator(w.t, qualSP231Token)(accounts)
	})
}

func (w *qualSP231World) intentStatus() string {
	w.t.Helper()
	record, err := w.f.owner.records.intent(w.f.owner.id)
	require.NoError(w.t, err)
	return record.status
}

// activation rebuilds the owners over the committed registration, as the
// activation fixtures do, bound to the same scoped admission records.
func (w *qualSP231World) activation(bind bool) *qualActivationFixture {
	w.t.Helper()
	f := w.f
	_, _, err := f.boundary.Commit()
	require.NoError(w.t, err)
	coordinator := testscommon.NewMultiShardsCoordinatorMock(3)
	coordinator.CurrentShard = core.MetachainShardId
	r, boundary, err := NewRegistryRegistration(f.store, coordinator, 2)
	require.NoError(w.t, err)
	old := f.owner
	f.owner, err = r.BindIntent(old.id, old.digest, old.manager, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(w.t, err)
	f.boundary = boundary
	f.admit, err = f.owner.WithRegistrationAdmission(f.hook, []byte("n"), 10, RegistrationResourceLimits{1000, 1048576, 100}, f.verify, f.proofs)
	require.NoError(w.t, err)
	w.records, err = newScopedAdmissionRecords(f.store, boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(),
		[]byte("n"), scopedAdmissionLimits{4096, 100, 1 << 20, 100}, qualSP231NoMandate{}, f.hook)
	require.NoError(w.t, err)
	w.approvals, err = newRegistrationApprovalCodec(w.records.codec, w.approvals.bounds)
	require.NoError(w.t, err)
	if bind {
		require.NoError(w.t, f.admit.WithAdmissionWithdrawal(w.records, w.approvals, w.owner, w.role))
	}
	x := &qualActivationFixture{f: f, genesis: []byte("synthetic-complete-genesis-body")}
	x.gh = &qualGovernedActionHost{store: f.store, faults: make(map[string]error), hooks: make(map[string]func())}
	x.g, err = newGovernedActionRecords(f.store, boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096,
		[]byte("n"), 4, 2, 2, x.gh, f.hook)
	require.NoError(w.t, err)
	x.h = &qualActivationHost{f: f, genesis: bytes.Clone(x.genesis), view: activationGenesis{
		token: []byte(qualSP231Token), closurePlan: bytes.Clone(f.body.closurePlan), epoch: 1,
		classes: []activationActionClass{{[]byte(qualSP231Token), []byte("synthetic-token-class")}, {bytes.Clone(f.body.programID), []byte("synthetic-program-class")}},
	}}
	x.a, err = newActivationRecords(f.admit, x.g, x.h)
	require.NoError(w.t, err)
	return x
}

// activate runs the activation write of the real owner in the block in
// execution. It returns the error and how often the activation host was asked.
func (w *qualSP231World) activate(x *qualActivationFixture) (error, int) {
	w.t.Helper()
	context, err := w.f.hook.EvaluatedHeaderTimeContext()
	require.NoError(w.t, err)
	before := x.h.calls
	var written []scopedAdmissionWrite
	_, err = x.a.writeActivationInHeader(context, []byte(qualSP231Token), w.f.owner.id, bytes.Clone(x.genesis),
		[]byte("synthetic-complete-activation-proof"), blake2b.NewBlake2b().Compute("readiness commitment"), &written)
	return err, x.h.calls - before
}
