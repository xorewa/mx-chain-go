package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Each boundary is denied once at each observed call position. The healthy
// control establishes the finite positions, never the expected failure result.
// Part B 17.2 requires unavailable state to remain distinct from absence.
type sp1RecordFault struct {
	kind  string
	at    int
	calls map[string]int
	hit   bool
}

var sp1RecordUnavailable = errors.New("SP1 fixture: native record dependency unavailable")

func (f *sp1RecordFault) deny(kind string) bool {
	f.calls[kind]++
	if f.kind == kind && f.calls[kind] == f.at {
		f.hit = true
		return true
	}
	return false
}

type sp1RecordStore struct {
	state.AccountsAdapter
	fault *sp1RecordFault
}

func (s *sp1RecordStore) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	if s.fault.deny("account") {
		return nil, sp1RecordUnavailable
	}
	a, err := s.AccountsAdapter.GetExistingAccount(address)
	if err != nil {
		return nil, err
	}
	user, ok := a.(state.UserAccountHandler)
	if !ok {
		return a, nil
	}
	return &sp1RecordAccount{UserAccountHandler: user, fault: s.fault}, nil
}
func (s *sp1RecordStore) SaveAccount(a vmcommon.AccountHandler) error {
	if s.fault.deny("save-account") {
		return sp1RecordUnavailable
	}
	if w, ok := a.(*sp1RecordAccount); ok {
		a = w.UserAccountHandler
	}
	return s.AccountsAdapter.SaveAccount(a)
}

type sp1RecordAccount struct {
	state.UserAccountHandler
	fault *sp1RecordFault
}

func (a *sp1RecordAccount) RetrieveValue(key []byte) ([]byte, uint32, error) {
	if a.fault.deny("read") {
		return nil, 0, sp1RecordUnavailable
	}
	return a.UserAccountHandler.RetrieveValue(key)
}
func (a *sp1RecordAccount) SaveKeyValue(key, value []byte) error {
	if a.fault.deny("write") {
		return sp1RecordUnavailable
	}
	return a.UserAccountHandler.SaveKeyValue(key, value)
}

type sp1RecordMarshal struct {
	marshal.Marshalizer
	fault *sp1RecordFault
}

func (m *sp1RecordMarshal) Marshal(v interface{}) ([]byte, error) {
	if m.fault.deny("marshal") {
		return nil, sp1RecordUnavailable
	}
	return m.Marshalizer.Marshal(v)
}
func (m *sp1RecordMarshal) Unmarshal(v interface{}, b []byte) error {
	if m.fault.deny("unmarshal") {
		return sp1RecordUnavailable
	}
	return m.Marshalizer.Unmarshal(v, b)
}
func sp1InjectRecordFault(codec *registrationRecords, fault *sp1RecordFault) {
	codec.state.accounts = &sp1RecordStore{AccountsAdapter: codec.state.accounts, fault: fault}
	codec.marshaller = &sp1RecordMarshal{Marshalizer: codec.marshaller, fault: fault}
}

type sp1RecordCase struct {
	name    string
	prepare func(*testing.T) (*registrationRecords, func() error)
}

func TestSP1CoverageRecordUnavailable(t *testing.T) {
	cases := []sp1RecordCase{
		{"current-read", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualCurrentLocalNew(t)
			return f.r.codec, func() error { _, e := f.r.read(f.pointerKey); return e }
		}},
		{"current-unchanged", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualCurrentLocalNew(t)
			v, e := f.resolve()
			require.NoError(t, e)
			return f.r.codec, func() error { return f.r.unchanged(v) }
		}},
		{"convergence-read", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualConvergenceNew(t, 2)
			f.create(t)
			return f.records.codec, func() error { _, e := f.records.read(f.key); return e }
		}},
		{"convergence-save", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualConvergenceNew(t, 2)
			return f.records.codec, func() error {
				return f.records.save(f.key, f.binding, &convergenceProgress{status: "PENDING", bitmap: []byte{0}, acks: make([][]byte, 2)})
			}
		}},
		{"pending-read", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualPendingFinalNew(t)
			return f.r.codec, func() error { _, e := f.r.read(f.finalKey); return e }
		}},
		{"pending-final", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualPendingFinalNew(t)
			require.NoError(t, f.r.stage(f.c))
			require.NoError(t, f.promote())
			return f.r.codec, func() error { _, _, e := f.r.final(f.c.key); return e }
		}},
		{"pending-check", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualPendingFinalNew(t)
			require.NoError(t, f.r.stage(f.c))
			return f.r.codec, func() error { return f.r.check(f.c, f.encoded, false) }
		}},
		{"pending-verify", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualPendingFinalNew(t)
			return f.r.codec, func() error { return f.r.verifyState(f.c, func() error { return nil }) }
		}},
		{"pending-save", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualPendingFinalNew(t)
			return f.r.codec, func() error { return f.r.save(f.c, f.encoded, true) }
		}},
		{"pending-stage", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualPendingFinalNew(t)
			return f.r.codec, func() error { return f.r.stage(f.c) }
		}},
		{"source-encode", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualSourceGrantNew(t)
			return f.records.codec, func() error { _, _, e := f.records.encode(f.p); return e }
		}},
		{"source-load", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualSourceGrantNew(t)
			f.install(t)
			return f.records.codec, func() error { _, _, _, e := f.records.load(f.key, f.body); return e }
		}},
		{"source-check", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualSourceGrantNew(t)
			f.install(t)
			return f.records.codec, func() error { return f.records.check(f.key, f.body, "OPEN", "", nil) }
		}},
		{"source-save", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualSourceGrantNew(t)
			return f.records.codec, func() error { return f.records.save(f.key, f.body, "OPEN", "", nil) }
		}},
		{"source-verify", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualSourceGrantNew(t)
			return f.records.codec, func() error { return f.records.verifyProjection(f.key, f.body, []byte("synthetic-canonical-proof")) }
		}},
		{"source-install", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualSourceGrantNew(t)
			return f.records.codec, func() error { return f.records.install(f.context, f.p, []byte("synthetic-canonical-proof")) }
		}},
		{"intent-identity", func(t *testing.T) (*registrationRecords, func() error) {
			_, r, _, _ := qualRecordStore(t)
			body, _, _, _ := qualRecordBody()
			return r, func() error { _, _, _, e := r.identity(body); return e }
		}},
		{"intent-decode", func(t *testing.T) (*registrationRecords, func() error) {
			_, r, _, _ := qualRecordStore(t)
			_, body, _, _ := qualRecordBody()
			return r, func() error { _, e := r.decodeBody(body); return e }
		}},
		{"intent-consume", func(t *testing.T) (*registrationRecords, func() error) {
			_, r, _, id := qualRecordStore(t)
			expected, e := r.intent(id)
			require.NoError(t, e)
			return r, func() error { return r.consume(id, expected, []byte("TOKEN-abcdef"), bytes.Repeat([]byte{0x22}, 32)) }
		}},
		{"intent-association", func(t *testing.T) (*registrationRecords, func() error) {
			s, r, digest, id := qualRecordStore(t)
			writer, _ := qualRegistrationOwner(t, s, 2)
			require.NoError(t, writer.registerTokenForIntent(r, id, digest, bytes.Repeat([]byte{0x22}, 32), qualRegistrationCreator(t, "TOKEN-abcdef")))
			return r, func() error { _, _, e := r.registeredToken([]byte("TOKEN-abcdef")); return e }
		}},
	}
	cases = append(cases, sp1GovernedAndScopedCases()...)
	cases = append(cases, sp1AdminAndRegistryCases()...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			codec, run := tc.prepare(t)
			control := &sp1RecordFault{calls: make(map[string]int)}
			sp1InjectRecordFault(codec, control)
			require.NoError(t, run(), "healthy fixture must be admitted before fault injection")
			for _, kind := range []string{"account", "read", "write", "save-account", "marshal", "unmarshal"} {
				for at := 1; at <= control.calls[kind]; at++ {
					t.Run(fmt.Sprintf("%s/%d", kind, at), func(t *testing.T) {
						codec, run := tc.prepare(t)
						fault := &sp1RecordFault{kind: kind, at: at, calls: make(map[string]int)}
						sp1InjectRecordFault(codec, fault)
						root, rootErr := codec.state.accounts.RootHash()
						require.NoError(t, rootErr)
						journal := codec.state.accounts.JournalLen()
						err := run()
						if sp1BoundaryOwned(tc.name) {
							after, snapshotErr := codec.state.accounts.RootHash()
							require.NoError(t, snapshotErr)
							require.Equal(t, root, after, "denied operation changed native state")
							require.Equal(t, journal, codec.state.accounts.JournalLen(), "denied operation left journal entries")
						}
						require.True(t, fault.hit, "fixture must reach selected native boundary")
						require.Error(t, err, "unavailable dependency must not yield success")
					})
				}
			}
		})
	}
}

func sp1GovernedAndScopedCases() []sp1RecordCase {
	return []sp1RecordCase{
		{"governed-read", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualGovernedActionNew(t)
			f.initialize(t)
			return f.g.codec, func() error { _, e := f.g.read(f.counter()); return e }
		}},
		{"governed-save", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualGovernedActionNew(t)
			return f.g.codec, func() error { return f.g.save(governedActionWrite{[]byte("fixture/new-key"), []byte("value")}) }
		}},
		{"governed-unchanged", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualGovernedActionNew(t)
			return f.g.codec, func() error { return f.g.unchanged(governedActionWrite{f.counter(), nil}) }
		}},
		{"governed-aggregate", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualGovernedActionNew(t)
			return f.g.codec, func() error {
				_, e := f.g.aggregate([]governedActionMember{{id: bytes.Repeat([]byte{1}, 32)}})
				return e
			}
		}},
		{"governed-initialize", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualGovernedActionNew(t)
			return f.g.codec, func() error { return f.g.initialize(f.x, f.p.subject, f.p.class, f.p.token) }
		}},
		{"governed-load", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualGovernedActionNew(t)
			f.initialize(t)
			id := f.propose(t)
			return f.g.codec, func() error { _, _, _, e := f.g.load(id); return e }
		}},
		{"governed-counter", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualGovernedActionNew(t)
			f.initialize(t)
			id := f.propose(t)
			r, _, _, e := f.g.load(id)
			require.NoError(t, e)
			return f.g.codec, func() error { _, e := f.g.counterSnapshot(r); return e }
		}},
		{"governed-active", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualGovernedActionNew(t)
			f.initialize(t)
			id := f.propose(t)
			r, _, _, e := f.g.load(id)
			require.NoError(t, e)
			return f.g.codec, func() error { _, _, _, e := f.g.active(r); return e }
		}},
		{"governed-propose", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualGovernedActionNew(t)
			f.initialize(t)
			f.h.envelope, _, _ = f.expected(100)
			return f.g.codec, func() error {
				id, e := f.g.propose(f.x, f.p)
				if e != nil {
					require.Empty(t, id)
				}
				return e
			}
		}},
		{"governed-cleanup", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualGovernedActionNew(t)
			f.initialize(t)
			id := f.propose(t)
			return f.g.codec, func() error { return f.g.cleanup(f.x, id, "STALE_BINDING", []byte("synthetic-no-irreversible-proof")) }
		}},
		{"scope-frame", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualScopedNew(t)
			return f.records.codec, func() error { _, e := f.records.scope(f.d.owner, f.d.program); return e }
		}},
		{"scope-digest", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualScopedNew(t)
			return f.records.codec, func() error { _, e := f.records.digest("SCOPE", f.scope); return e }
		}},
		{"scope-current", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualScopedNew(t)
			f.enroll(t)
			return f.records.codec, func() error {
				a, e := f.records.codec.state.systemAccount()
				if e != nil {
					return e
				}
				_, e = f.records.current(a, f.scope)
				return e
			}
		}},
		{"scope-verify", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualScopedNew(t)
			return f.records.codec, func() error {
				return f.records.verifyState([][]byte{[]byte("fixture/scope-key")}, func() error { return nil })
			}
		}},
		{"scope-install", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualScopedNew(t)
			proof := f.mandates.proof("ENROLL", nil, f.d.authority)
			return f.records.codec, func() error { return f.records.install(f.context, f.d.owner, f.d.program, nil, f.versionBody, proof) }
		}},
		{"scope-decision", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualScopedNew(t)
			return f.records.codec, func() error { _, _, e := f.records.decisionBody(f.d); return e }
		}},
		{"scope-admit", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualScopedNew(t)
			f.enroll(t)
			proof := f.mandates.proof("ADMISSION", f.d.authority, qualScopedHash("ADMISSION", f.body()))
			return f.records.codec, func() error { return f.records.admit(f.context, f.d, proof) }
		}},
		{"scope-withdraw", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualScopedNew(t)
			f.enroll(t)
			f.admit(t)
			proof := f.withdrawProof()
			return f.records.codec, func() error { return f.records.withdraw(f.context, f.d, proof) }
		}},
		{"scope-check", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualScopedNew(t)
			f.enroll(t)
			f.admit(t)
			return f.records.codec, func() error { return f.records.checkDecisionAt(f.context, f.d) }
		}},
	}
}

func sp1AdminAndRegistryCases() []sp1RecordCase {
	return []sp1RecordCase{
		{"admin-digest", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualAdminNew(t)
			return f.carrier.codec, func() error { _, e := f.carrier.digest("APPLIED_ID", f.e.effectID, f.e.legID); return e }
		}},
		{"admin-normalized", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualAdminNew(t)
			return f.carrier.codec, func() error { _, e := f.carrier.normalized(f.e.payload, f.e.discriminator); return e }
		}},
		{"admin-read", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualAdminNew(t)
			return f.carrier.codec, func() error { _, e := f.carrier.readApplied(f.appliedKey()); return e }
		}},
		{"admin-check", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualAdminNew(t)
			return f.carrier.codec, func() error { return f.carrier.checkApplied(f.appliedKey(), nil) }
		}},
		{"admin-apply", func(t *testing.T) (*registrationRecords, func() error) {
			f := qualAdminNew(t)
			return f.carrier.codec, func() error { return f.carrier.apply(f.encoded, f.proof) }
		}},
		{"registry-create", func(t *testing.T) (*registrationRecords, func() error) {
			s := qualRegistrationStore(t, 0)
			writer, _ := qualRegistrationOwner(t, s, 2)
			codec, e := newRegistrationRecords(s, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
			require.NoError(t, e)
			writer.state = codec.state
			return codec, func() error { return writer.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")) }
		}},
	}
}
func TestSP1CoverageRecordStructuralDenials(t *testing.T) {
	f := qualPendingFinalNew(t)
	qualRecordPut(t, f.s, f.finalKey, bytes.Repeat([]byte{1}, f.r.codec.maxBytes+1))
	_, err := f.r.read(f.finalKey)
	require.Error(t, err)
	scope := qualScopedNew(t)
	_, err = scope.records.scope(nil, scope.d.program)
	require.Error(t, err)
	var a *RegistrationAdmission
	require.True(t, a.IsInterfaceNil())
	require.False(t, (&RegistrationAdmission{}).IsInterfaceNil())
	var c *RegistrationCancellation
	require.True(t, c.IsInterfaceNil())
	require.False(t, (&RegistrationCancellation{}).IsInterfaceNil())
	err = a.RegisterTokenForAuthenticatedCreation(nil, nil, nil, nil, nil, nil, nil, nil, 0, nil)
	require.Error(t, err)
	err = a.RegisterTokenForCommittedCreation(nil, nil, nil, nil, nil, nil, 0, nil, nil)
	require.Error(t, err)
	var candidate *registrationCandidate
	_, err = candidate.BindIntent(nil, nil, nil, nil, nil, 0)
	require.Error(t, err)
	require.Error(t, candidate.DRWAExecutionError())
	require.Error(t, candidate.DRWAExecutionHealthError())
	_, err = candidate.WithTokenClassification(nil, nil, func(bool) (*vmcommon.VMOutput, error) { t.Fatal("missing owner authorized execution"); return nil, nil })
	require.Error(t, err)
}

func TestSP1CoverageAdditionalStructuralDenials(t *testing.T) {
	admin := qualAdminNew(t)
	for _, payload := range [][]byte{nil, bytes.Repeat([]byte{1}, admin.carrier.codec.maxBytes+1)} {
		_, err := admin.carrier.normalized(payload, []byte("pause"))
		require.Error(t, err)
	}
	qualRecordPut(t, admin.store, admin.appliedKey(), bytes.Repeat([]byte{1}, admin.carrier.codec.maxBytes+1))
	_, err := admin.carrier.readApplied(admin.appliedKey())
	require.Error(t, err)
	scope := qualScopedNew(t)
	_, err = newScopedAdmissionRecords(scope.store, scope.boundary, nil, scope.records.codec.hasher, scope.records.domain, scope.records.limits, scope.mandates, scope.records.timeSource)
	require.Error(t, err)
	_, err = newScopedAdmissionRecords(scope.store, scope.boundary, scope.records.codec.marshaller, scope.records.codec.hasher, bytes.Repeat([]byte{1}, scope.records.limits.recordBytes+1), scope.records.limits, scope.mandates, scope.records.timeSource)
	require.Error(t, err)
	candidate, store, _ := qualRegistrationCandidate(t, false, false)
	_, err = candidate.BindIntent(nil, nil, nil, nil, nil, 0)
	require.Error(t, err)
	calls := 0
	execute := func(bool) (*vmcommon.VMOutput, error) {
		calls++
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
	}
	candidate.view.parent.mut.Lock()
	out, err := candidate.WithTokenClassification(store, []byte("TOKEN-abcdef"), execute)
	candidate.view.parent.mut.Unlock()
	require.ErrorIs(t, err, ErrExecutionBusy)
	require.Nil(t, out)
	require.Zero(t, calls)
	require.NoError(t, candidate.abort())
	out, err = candidate.WithTokenClassification(store, []byte("TOKEN-abcdef"), execute)
	require.ErrorIs(t, err, ErrExecutionClosed)
	require.Nil(t, out)
	require.Zero(t, calls)
}

func sp1BoundaryOwned(name string) bool {
	switch name {
	case "pending-stage", "source-install", "governed-initialize", "governed-propose", "governed-cleanup", "scope-install", "scope-admit", "scope-withdraw", "admin-apply", "registry-create":
		return true
	default:
		return false
	}
}
