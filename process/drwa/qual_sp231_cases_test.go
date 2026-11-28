package drwa

import (
	"bytes"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	statestub "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func (w *qualSP231World) key(kind string, identity []byte) []byte {
	return append([]byte(scopedAdmissionPrefix+kind+"@"), identity...)
}

// refused runs a withdrawal that must be refused and leave the state alone.
func (w *qualSP231World) refused(label string, d scopedAdmissionDecision, proofs ...scopedAuthorityProof) {
	w.t.Helper()
	root, journal := w.state()
	outcome, err := w.withdraw(d, proofs...)
	require.Error(w.t, err, label)
	require.Equal(w.t, admissionWithdrawalRefused, outcome, label)
	after, afterJournal := w.state()
	require.Equal(w.t, root, after, label)
	require.Equal(w.t, journal, afterJournal, label)
	require.Equal(w.t, admissionDecisionAdmitted, w.status(w.d), label+": the admission is untouched")
}

// E.8.6 bullet 2: both execution orders inside one block. The expected
// outcomes are E.8.4's: execution order decides, nothing else.
func TestQualSP231BothOrdersInOneBlock(t *testing.T) {
	// One evaluated header for every operation of each case: one block.
	t.Run("withdrawal_then_registration", func(t *testing.T) {
		w := qualSP231New(t, 200, true)
		w.withdrawn()
		created := 0
		require.ErrorIs(t, w.register(&created), errScopedAdmission)
		require.Zero(t, created)
		require.Equal(t, "OPEN", w.intentStatus())
		require.Equal(t, admissionDecisionWithdrawn, w.status(w.d))
	})
	t.Run("registration_then_withdrawal_then_activation", func(t *testing.T) {
		w := qualSP231New(t, 200, true)
		created := 0
		require.NoError(t, w.register(&created))
		x := w.activation(true)
		w.withdrawn()
		require.Equal(t, "CONSUMED", w.intentStatus(), "the registration that executed first stands")
		err, asked := w.activate(x)
		require.ErrorIs(t, err, errScopedAdmission, "the later covered transition is refused")
		require.Zero(t, asked)
	})
	t.Run("registration_twice", func(t *testing.T) {
		w := qualSP231New(t, 200, true)
		created := 0
		require.NoError(t, w.register(&created))
		require.Error(t, w.register(&created), "duplicate consumption of the intent")
		require.Equal(t, 1, created)
	})
	t.Run("withdrawal_twice", func(t *testing.T) {
		w := qualSP231New(t, 200, true)
		certificate := w.certificate(w.request(w.d), scopedIPAA, "withdrawal", 1, 20)
		outcome, err := w.withdraw(w.d, certificate)
		require.NoError(t, err)
		require.Equal(t, admissionWithdrawalEffective, outcome)
		root, journal := w.state()
		outcome, err = w.withdraw(w.d, certificate)
		require.NoError(t, err)
		require.Equal(t, admissionWithdrawalAlreadyEffective, outcome, "a replay reports that nothing new happened")
		after, afterJournal := w.state()
		require.Equal(t, root, after, "and writes nothing")
		require.Equal(t, journal, afterJournal)
		// The replay still needs a valid certificate.
		outcome, err = w.withdraw(w.d)
		require.Error(t, err)
		require.Equal(t, admissionWithdrawalRefused, outcome)
	})
}

// E.8.6 bullet 5 and E.8.3 items 1 and 2: exact scope and authority.
func TestQualSP231WithdrawalScopeAndAuthority(t *testing.T) {
	w := qualSP231New(t, 200, true)
	good := w.certificate(w.request(w.d), scopedIPAA, "withdrawal", 1, 20)
	other := func(change func(*scopedAdmissionDecision)) scopedAdmissionDecision {
		d := w.d
		change(&d)
		return d
	}
	// Another subject: the certificate of this decision withdraws nothing else,
	// and a decision that is not stored cannot be withdrawn.
	for name, d := range map[string]scopedAdmissionDecision{
		"another issuer":      other(func(d *scopedAdmissionDecision) { d.issuer = bytes.Repeat([]byte{0x77}, 32) }),
		"another programme":   other(func(d *scopedAdmissionDecision) { d.program = []byte("another programme") }),
		"another version":     other(func(d *scopedAdmissionDecision) { d.version = []byte("decision-2") }),
		"another commitment":  other(func(d *scopedAdmissionDecision) { d.commitment = []byte("another commitment") }),
		"another validity":    other(func(d *scopedAdmissionDecision) { d.validUntil = 201 }),
		"another authority":   other(func(d *scopedAdmissionDecision) { d.authority = blake2b.NewBlake2b().Compute("x") }),
		"another scope owner": other(func(d *scopedAdmissionDecision) { d.owner = bytes.Repeat([]byte{9}, 32) }),
	} {
		w.refused(name, d, good)
		w.refused(name+", own certificate", d, w.certificate(w.request(d), scopedIPAA, "withdrawal", 1, 20))
	}
	// A second stored decision of the same issuer and programme: withdrawing the
	// first leaves it admitted, and the first's certificate does not withdraw it.
	second := other(func(d *scopedAdmissionDecision) { d.version = []byte("decision-2") })
	qualRecordPut(t, w.f.store, w.key("decision", w.decisionID(second)), w.decisionBody(second))
	outcome, err := w.withdraw(second, good)
	require.Error(t, err, "the certificate of decision-1 presented for decision-2")
	require.Equal(t, admissionWithdrawalRefused, outcome)

	// Wrong certificate content.
	request := w.request(w.d)
	edited := func(change func(*scopedAuthorityRequest)) scopedAuthorityRequest {
		r := request.clone()
		change(&r)
		return r
	}
	for name, proofs := range map[string][]scopedAuthorityProof{
		"no certificate":                        nil,
		"cancellation kind":                     {w.certificate(request, scopedIPAA, "cancellation", 1, 20)},
		"admission kind":                        {w.certificate(request, scopedIPAA, "admission", 1, 20)},
		"unused-intent cancellation use":        {w.certificate(edited(func(r *scopedAuthorityRequest) { r.use = scopedUnusedIntentCancellation }), scopedIPAA, "cancellation", 1, 20)},
		"registered cancellation use":           {w.certificate(edited(func(r *scopedAuthorityRequest) { r.use = scopedRegisteredCancellation }), scopedPA, "cancellation", 1, 20)},
		"another network domain":                {w.certificate(edited(func(r *scopedAuthorityRequest) { r.domain = []byte("another network") }), scopedIPAA, "withdrawal", 1, 20)},
		"another programme scope":               {w.certificate(edited(func(r *scopedAuthorityRequest) { r.scope = []byte("another scope") }), scopedIPAA, "withdrawal", 1, 20)},
		"another decision identity":             {w.certificate(edited(func(r *scopedAuthorityRequest) { r.subject = []byte("another decision") }), scopedIPAA, "withdrawal", 1, 20)},
		"another withdrawal digest":             {w.certificate(edited(func(r *scopedAuthorityRequest) { r.digest = []byte("another digest") }), scopedIPAA, "withdrawal", 1, 20)},
		"another issuer in the certificate":     {w.certificate(edited(func(r *scopedAuthorityRequest) { r.owner = bytes.Repeat([]byte{0x77}, 32) }), scopedIPAA, "withdrawal", 1, 20)},
		"Program Recovery instead of admission": {w.certificate(request, scopedPR, "withdrawal", 1, 20)},
		"Program Administration instead":        {w.certificate(request, scopedPA, "withdrawal", 1, 20)},
		"two of five signatures":                {w.certificate(request, scopedIPAA, "withdrawal", 1, 20, 0, 1)},
		"admission and a second certificate":    {good, w.certificate(request, scopedPR, "withdrawal", 1, 20)},
		"not yet valid":                         {w.certificate(request, scopedIPAA, "withdrawal", 2, 20)},
		"expired":                               {w.certificate(request, scopedIPAA, "withdrawal", 0, 0)},
		"longer than the class lifetime":        {w.certificate(request, scopedIPAA, "withdrawal", 1, 22)},
	} {
		w.refused(name, w.d, proofs...)
	}
	// FA-02: only possession of the bound roster keys counts. Signatures of
	// another role's keys under the admission set's name are refused.
	forged := w.certificate(request, scopedPR, "withdrawal", 1, 20)
	set := w.auth.s.v.current[scopedIPAA]
	forged.requirement.role, forged.id, forged.hash, forged.version = scopedIPAA, set.id, set.hash, set.version
	w.refused("keys outside the admission roster", w.d, forged)

	// Certificate validity at its exact bounds (evaluated header time 1).
	for name, window := range map[string][2]uint64{"from 1": {1, 1}, "until 1": {0, 1}, "around 1": {0, 20}} {
		x := qualSP231New(t, 200, true)
		outcome, err = x.withdraw(x.d, x.certificate(x.request(x.d), scopedIPAA, "withdrawal", window[0], window[1]))
		require.NoError(t, err, name)
		require.Equal(t, admissionWithdrawalEffective, outcome, name)
	}

	// Missing authority dependencies refuse before anything is read.
	context, err := w.f.hook.EvaluatedHeaderTimeContext()
	require.NoError(t, err)
	for name, authority := range map[string]scopedWithdrawalAuthority{
		"no codec":  {reader: w.auth.s, limits: w.auth.limits},
		"no reader": {codec: w.auth.codec, limits: w.auth.limits},
		"no limits": {codec: w.auth.codec, reader: w.auth.s},
	} {
		outcome, err = w.records.withdrawAuthorized(context, w.d, []scopedAuthorityProof{good}, authority)
		require.Error(t, err, name)
		require.Equal(t, admissionWithdrawalRefused, outcome, name)
	}
	var none *scopedAdmissionRecords
	outcome, err = none.withdrawAuthorized(context, w.d, nil, scopedWithdrawalAuthority{})
	require.ErrorIs(t, err, errScopedAdmission)
	require.Equal(t, admissionWithdrawalRefused, outcome)
	require.ErrorIs(t, (&scopedWithdrawalMandate{}).Verify("ADMISSION", nil, nil, nil, nil), errScopedAdmission, "the adapter authorises withdrawals only")
	require.False(t, (&scopedWithdrawalMandate{}).IsInterfaceNil())

	// After all refusals the real certificate still works, once.
	outcome, err = w.withdraw(w.d, good)
	require.NoError(t, err)
	require.Equal(t, admissionWithdrawalEffective, outcome)
	require.Equal(t, admissionDecisionAdmitted, w.status(second), "the unaffected decision stays admitted")
}

// E.8.6 bullet 5, rotation straddle: a certificate made under the scope head
// that was current when it was signed is refused after the head moved; the
// decision is then withdrawn under the new head's certificate.
func TestQualSP231AuthorityRotationStraddle(t *testing.T) {
	w := qualSP231New(t, 200, true)
	old := w.certificate(w.request(w.d), scopedIPAA, "withdrawal", 1, 20)
	successor := qualSP231Hash("VERSION", w.scope, w.outer, []byte("successor body"))
	qualRecordPut(t, w.f.store, w.key("version", successor), qualRecordFrame(w.scope, w.outer, []byte("successor body")))
	qualRecordPut(t, w.f.store, w.key("current", qualSP231Hash("SCOPE", w.scope)), qualRecordFrame(w.scope, successor))
	previous := w.outer
	w.outer = successor // the world's request now names the new head
	root, journal := w.state()
	outcome, err := w.withdraw(w.d, old)
	require.Error(t, err, "signed under the previous head")
	require.Equal(t, admissionWithdrawalRefused, outcome)
	after, afterJournal := w.state()
	require.Equal(t, root, after)
	require.Equal(t, journal, afterJournal)
	w.d.authority = previous
	fresh := w.certificate(w.request(w.d), scopedIPAA, "withdrawal", 1, 20)
	outcome, err = w.withdraw(w.d, fresh)
	require.NoError(t, err, "the decision of the previous version is withdrawn under the current head")
	require.Equal(t, admissionWithdrawalEffective, outcome)

	// Consumption across a rotation of the admission purpose head, without any
	// withdrawal: the intent bound to the previous version cannot register.
	x := qualSP231New(t, 200, true)
	qualRecordPut(t, x.f.store, x.key("current", qualSP231Hash("SCOPE", x.scope, []byte("REGISTER_TOKEN_ADMISSION"))),
		qualRecordFrame(x.scope, blake2b.NewBlake2b().Compute("a later admission version")))
	created := 0
	require.Error(t, x.register(&created))
	require.Zero(t, created)
}

// E.8.6 bullet 6: valid-but-withdrawn, expired and unaffected decisions at
// the exact validity bound. Neither expiry nor withdrawal replaces the other.
func TestQualSP231DecisionValidityBounds(t *testing.T) {
	for name, c := range map[string]struct {
		validUntil uint64
		withdraw   bool
		admitted   bool
	}{
		"valid at its last instant":     {1, false, true},
		"valid for long":                {200, false, true},
		"expired one instant earlier":   {0, false, false},
		"valid at its bound, withdrawn": {1, true, false},
		"valid for long, withdrawn":     {200, true, false},
	} {
		t.Run(name, func(t *testing.T) {
			w := qualSP231New(t, c.validUntil, true)
			if c.withdraw {
				w.withdrawn()
			}
			created := 0
			err := w.register(&created)
			if c.admitted {
				require.NoError(t, err)
				require.Equal(t, 1, created)
				return
			}
			require.ErrorIs(t, err, errScopedAdmission)
			require.Zero(t, created)
		})
	}
	// An expired decision can still be withdrawn (the record is about the
	// decision, not about a certificate lifetime), and stays refused.
	w := qualSP231New(t, 0, true)
	w.withdrawn()
	require.Equal(t, admissionDecisionWithdrawn, w.status(w.d))
}

// E.8.6 bullet 8 and E.8.3 item 7: rollback, interrupted persistence, restart.
func TestQualSP231RollbackInterruptedPersistenceAndRestart(t *testing.T) {
	t.Run("the block that carried the withdrawal is removed", func(t *testing.T) {
		w := qualSP231New(t, 200, true)
		root, _ := w.state()
		snapshot := w.f.store.JournalLen()
		w.withdrawn()
		require.Equal(t, admissionDecisionWithdrawn, w.status(w.d))
		require.NoError(t, w.f.store.RevertToSnapshot(snapshot))
		reverted, _ := w.state()
		require.Equal(t, root, reverted)
		require.Equal(t, admissionDecisionAdmitted, w.status(w.d), "no withdrawal record outlives its block")
		created := 0
		require.NoError(t, w.register(&created), "and the registration follows canonical state")
	})
	t.Run("the block that carried the registration is removed", func(t *testing.T) {
		w := qualSP231New(t, 200, true)
		snapshot := w.f.store.JournalLen()
		created := 0
		require.NoError(t, w.register(&created))
		require.NoError(t, w.f.store.RevertToSnapshot(snapshot))
		require.Equal(t, "OPEN", w.intentStatus())
		w.withdrawn()
		require.ErrorIs(t, w.register(&created), errScopedAdmission, "the replayed registration meets the withdrawal that is now first")
		require.Equal(t, 1, created)
	})
	t.Run("interrupted persistence", func(t *testing.T) {
		w := qualSP231New(t, 200, true)
		failure := errors.New("injected save failure")
		certificate := w.certificate(w.request(w.d), scopedIPAA, "withdrawal", 1, 20)
		w.f.store.saveErr = failure
		outcome, err := w.withdraw(w.d, certificate)
		w.f.store.saveErr = nil
		require.ErrorIs(t, err, failure)
		require.Equal(t, admissionWithdrawalRefused, outcome, "a failed attempt is not reported as a withdrawal")
		require.Equal(t, admissionDecisionAdmitted, w.status(w.d))
		outcome, err = w.withdraw(w.d, certificate)
		require.NoError(t, err)
		require.Equal(t, admissionWithdrawalEffective, outcome)
	})
	t.Run("restart", func(t *testing.T) {
		w := qualSP231New(t, 200, true)
		w.withdrawn()
		w.f.end()
		reopened := qualSP224Reopen(t, w.f.store)
		hook, _ := qualT42Hook(t, reopened, core.MetachainShardId, true)
		context, end := qualT42Install(t, hook, core.MetachainShardId, 1)
		defer end()
		boundary, err := NewRollbackContainment(reopened)
		require.NoError(t, err)
		records, err := newScopedAdmissionRecords(reopened, boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(),
			[]byte("n"), scopedAdmissionLimits{4096, 100, 1 << 20, 100}, qualSP231NoMandate{}, hook)
		require.NoError(t, err)
		status, err := records.decisionStatus(w.d)
		require.NoError(t, err)
		require.Equal(t, admissionDecisionWithdrawn, status, "the withdrawal record is durable state")
		approvals, err := newRegistrationApprovalCodec(records.codec, w.approvals.bounds)
		require.NoError(t, err)
		require.ErrorIs(t, approvals.intentAdmission(records, context, w.f.body, w.owner, w.role), errScopedAdmission)
	})
}

// E.8.3 item 6 and E.8.6 bullet 11: what an observer can tell apart.
func TestQualSP231TruthfulStatus(t *testing.T) {
	w := qualSP231New(t, 200, true)
	unknown := w.d
	unknown.version = []byte("never issued")
	require.Equal(t, admissionDecisionAbsent, w.status(unknown))
	require.Equal(t, admissionDecisionAdmitted, w.status(w.d), "nothing requested: admitted")
	// A refused attempt changes no status and reports Refused.
	outcome, err := w.withdraw(w.d)
	require.Error(t, err)
	require.Equal(t, admissionWithdrawalRefused, outcome)
	require.Equal(t, admissionDecisionAdmitted, w.status(w.d))
	// Executed in a block that is not committed yet: visible in that state
	// only; the committed state still says admitted.
	committed, err := w.f.store.RootHash()
	require.NoError(t, err)
	w.withdrawn()
	require.Equal(t, admissionDecisionWithdrawn, w.status(w.d))
	pending, err := w.f.store.RootHash()
	require.NoError(t, err)
	require.NotEqual(t, committed, pending)
	// A status for a decision whose stored bytes differ is an error, never a
	// guess.
	qualRecordPut(t, w.f.store, w.key("withdrawn", w.decisionID(w.d)), []byte("other bytes"))
	_, err = w.records.decisionStatus(w.d)
	require.ErrorIs(t, err, errScopedAdmission)
	malformed := w.d
	malformed.issuer = []byte("short")
	_, err = w.records.decisionStatus(malformed)
	require.Error(t, err)

	// A store that cannot be read gives an error, never a status.
	failure := errors.New("injected read failure")
	for name, c := range map[string]struct {
		account error
		failAt  int
	}{"no system account": {failure, 0}, "decision row unreadable": {nil, 1}, "withdrawal record unreadable": {nil, 2}} {
		reads := 0
		account := &statestub.UserAccountStub{Address: bytes.Clone(core.SystemAccountAddress), RetrieveValueCalled: func([]byte) ([]byte, uint32, error) {
			reads++
			if reads == c.failAt {
				return nil, 0, failure
			}
			return nil, 0, nil
		}}
		accounts := &statestub.AccountsStub{GetExistingAccountCalled: func([]byte) (vmcommon.AccountHandler, error) {
			if c.account != nil {
				return nil, c.account
			}
			return account, nil
		}}
		codec, codecErr := newRegistrationRecords(accounts, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
		require.NoError(t, codecErr)
		broken := &scopedAdmissionRecords{codec: codec, domain: []byte("n")}
		_, err = broken.decisionStatus(w.d)
		require.ErrorIs(t, err, failure, name)
	}
	oversized := w.d
	oversized.version = make([]byte, 5000)
	_, err = w.records.decisionStatus(oversized)
	require.Error(t, err)
}

// E.8.6 bullets 4 and 10: the unused-intent and registered cancellation
// purposes are not withdrawals, the other approvals stay required, and the
// check does bounded work that does not depend on other records.
func TestQualSP231CancellationPurposesIsolationAndBoundedWork(t *testing.T) {
	w := qualSP231New(t, 200, true)
	// An authorised unused-intent cancellation certificate verifies under its
	// own row (P03) and leaves the admission decision admitted.
	cancellation := w.request(w.d)
	cancellation.use = scopedUnusedIntentCancellation
	w.auth.r = cancellation
	w.auth.bindRequest()
	context, err := w.f.hook.EvaluatedHeaderTimeContext()
	require.NoError(t, err)
	w.auth.s.v.time, w.auth.s.v.intent = context, "OPEN"
	require.NoError(t, verifyScopedAuthority(w.f.hook, w.auth.codec, w.auth.s, cancellation,
		[]scopedAuthorityProof{w.certificate(cancellation, scopedIPAA, "cancellation", 1, 20)}, w.auth.limits))
	require.Equal(t, admissionDecisionAdmitted, w.status(w.d), "a cancellation authorisation is no withdrawal")

	// Many unrelated decisions and withdrawal records in the same store: the
	// outcomes for this decision are the same.
	for i := 0; i < 64; i++ {
		other := w.d
		other.version = []byte{'v', byte(i)}
		qualRecordPut(t, w.f.store, w.key("decision", w.decisionID(other)), w.decisionBody(other))
		if i%2 == 0 {
			qualRecordPut(t, w.f.store, w.key("withdrawn", w.decisionID(other)), w.decisionBody(other))
		}
	}
	created := 0
	require.NoError(t, w.register(&created), "other subjects' withdrawals do not touch this admission")
	require.Equal(t, qualRegistrationPurposes, w.f.verify.calls, "every other approval was still required")

	// The withdrawal writes exactly one record and the budget, nothing else.
	x := qualSP231New(t, 200, true)
	intentBefore := qualRegistryValue(t, x.f.store, registrationIntentPrefix+string(x.f.owner.id))
	x.withdrawn()
	require.Equal(t, x.body, qualRegistryValue(t, x.f.store, string(x.key("withdrawn", x.decisionID(x.d)))))
	require.Equal(t, x.body, qualRegistryValue(t, x.f.store, string(x.key("decision", x.decisionID(x.d)))), "the decision row is not rewritten")
	require.Equal(t, intentBefore, qualRegistryValue(t, x.f.store, registrationIntentPrefix+string(x.f.owner.id)), "the immutable intent is not touched")
}

// The binding itself, and the duty of the ingress row to make it.
func TestQualSP231AdmissionWithdrawalBinding(t *testing.T) {
	w := qualSP231New(t, 200, false)
	a := w.f.admit
	otherStore := qualSP231New(t, 200, false)
	foreignDomain := *w.records
	foreignDomain.domain = []byte("another domain")
	for name, bind := range map[string]func() error{
		"no records":         func() error { return a.WithAdmissionWithdrawal(nil, w.approvals, w.owner, w.role) },
		"no approvals codec": func() error { return a.WithAdmissionWithdrawal(w.records, nil, w.owner, w.role) },
		"short scope owner":  func() error { return a.WithAdmissionWithdrawal(w.records, w.approvals, []byte("short"), w.role) },
		"no admission role":  func() error { return a.WithAdmissionWithdrawal(w.records, w.approvals, w.owner, nil) },
		"records of another store": func() error {
			return a.WithAdmissionWithdrawal(otherStore.records, w.approvals, w.owner, w.role)
		},
		"approvals of another store": func() error {
			return a.WithAdmissionWithdrawal(w.records, otherStore.approvals, w.owner, w.role)
		},
		"records of another domain": func() error { return a.WithAdmissionWithdrawal(&foreignDomain, w.approvals, w.owner, w.role) },
		"no owner": func() error {
			return (*RegistrationAdmission)(nil).WithAdmissionWithdrawal(w.records, w.approvals, w.owner, w.role)
		},
	} {
		require.ErrorIs(t, bind(), errInvalidRegistrationRecord, name)
	}
	require.NoError(t, a.WithAdmissionWithdrawal(w.records, w.approvals, w.owner, w.role))
	require.ErrorIs(t, a.WithAdmissionWithdrawal(w.records, w.approvals, w.owner, w.role), errInvalidRegistrationRecord, "bound once")
	// A wrong native scope owner or admission role refuses the covered action.
	wrongOwner := qualSP231New(t, 200, false)
	require.NoError(t, wrongOwner.f.admit.WithAdmissionWithdrawal(wrongOwner.records, wrongOwner.approvals, bytes.Repeat([]byte{9}, 32), wrongOwner.role))
	created := 0
	require.Error(t, wrongOwner.register(&created))
	wrongRole := qualSP231New(t, 200, false)
	require.NoError(t, wrongRole.f.admit.WithAdmissionWithdrawal(wrongRole.records, wrongRole.approvals, wrongRole.owner, []byte("another role")))
	require.Error(t, wrongRole.register(&created))
	require.Zero(t, created)

	// Structural guard for the ingress row (SP2-38): product code that builds a
	// registration admission owner must bind the withdrawal check in the same
	// file. Today no product file builds one.
	root := filepath.Join("..", "..")
	builders := 0
	require.NoError(t, filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if name := entry.Name(); name == ".git" || name == "vendor" || name == "testdata" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if _, parseErr := parser.ParseFile(token.NewFileSet(), path, source, parser.PackageClauseOnly); parseErr != nil {
			return parseErr
		}
		text := string(source)
		if strings.Contains(text, ".WithRegistrationAdmission(") {
			builders++
			require.Contains(t, text, ".WithAdmissionWithdrawal(", "%s builds a registration admission owner without the F04 binding", path)
		}
		return nil
	}))
	t.Logf("SP2-31 product files that build a registration admission owner: %d", builders)
}
