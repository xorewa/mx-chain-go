package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

// Each boundary is denied once at each observed call position. The healthy
// control establishes the finite positions, never the expected failure result.
// Part B 17.2 requires unavailable state to remain distinct from absence.
type recordFault struct {
	kind  string
	at    int
	calls map[string]int
	hit   bool
}

var recordUnavailable = errors.New("test fixture: native record dependency unavailable")

func (f *recordFault) deny(kind string) bool {
	f.calls[kind]++
	if f.kind == kind && f.calls[kind] == f.at {
		f.hit = true
		return true
	}
	return false
}

type recordStore struct {
	state.AccountsAdapter
	fault *recordFault
}

func (s *recordStore) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	if s.fault.deny("account") {
		return nil, recordUnavailable
	}
	a, err := s.AccountsAdapter.GetExistingAccount(address)
	if err != nil {
		return nil, err
	}
	user, ok := a.(state.UserAccountHandler)
	if !ok {
		return a, nil
	}
	return &recordAccount{UserAccountHandler: user, fault: s.fault}, nil
}

func (s *recordStore) SaveAccount(a vmcommon.AccountHandler) error {
	if s.fault.deny("save-account") {
		return recordUnavailable
	}
	if w, ok := a.(*recordAccount); ok {
		a = w.UserAccountHandler
	}
	return s.AccountsAdapter.SaveAccount(a)
}

type recordAccount struct {
	state.UserAccountHandler
	fault *recordFault
}

func (a *recordAccount) RetrieveValue(key []byte) ([]byte, uint32, error) {
	if a.fault.deny("read") {
		return nil, 0, recordUnavailable
	}
	return a.UserAccountHandler.RetrieveValue(key)
}

func (a *recordAccount) SaveKeyValue(key, value []byte) error {
	if a.fault.deny("write") {
		return recordUnavailable
	}
	return a.UserAccountHandler.SaveKeyValue(key, value)
}

type recordMarshal struct {
	marshal.Marshalizer
	fault *recordFault
}

func (m *recordMarshal) Marshal(v interface{}) ([]byte, error) {
	if m.fault.deny("marshal") {
		return nil, recordUnavailable
	}
	return m.Marshalizer.Marshal(v)
}

func (m *recordMarshal) Unmarshal(v interface{}, b []byte) error {
	if m.fault.deny("unmarshal") {
		return recordUnavailable
	}
	return m.Marshalizer.Unmarshal(v, b)
}

func injectRecordFault(codec *registrationRecords, fault *recordFault) {
	codec.state.accounts = &recordStore{AccountsAdapter: codec.state.accounts, fault: fault}
	codec.marshaller = &recordMarshal{Marshalizer: codec.marshaller, fault: fault}
}

type recordCase struct {
	name    string
	prepare func(*testing.T) (*registrationRecords, func() error)
}

func TestRegistrationRecords_EncodeBodyDependencyFailures(t *testing.T) {
	cases := []recordCase{
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
	cases = append(cases, governedAndScopedCases()...)
	cases = append(cases, adminAndRegistryCases()...)
	for _, tc := range cases {
		t.Run(strings.ReplaceAll(tc.name, "/", " ")+" should preserve the expected result", func(t *testing.T) {
			codec, run := tc.prepare(t)
			control := &recordFault{calls: make(map[string]int)}
			injectRecordFault(codec, control)
			require.NoError(t, run(), "healthy fixture must be admitted before fault injection")
			for _, kind := range []string{"account", "read", "write", "save-account", "marshal", "unmarshal"} {
				for at := 1; at <= control.calls[kind]; at++ {
					t.Run(strings.ReplaceAll(fmt.Sprintf("%s/%d", kind, at), "/", " ")+" should preserve the expected result", func(t *testing.T) {
						codec, run := tc.prepare(t)
						fault := &recordFault{kind: kind, at: at, calls: make(map[string]int)}
						injectRecordFault(codec, fault)
						root, rootErr := codec.state.accounts.RootHash()
						require.NoError(t, rootErr)
						journal := codec.state.accounts.JournalLen()
						err := run()
						if boundaryOwned(tc.name) {
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

func governedAndScopedCases() []recordCase {
	return []recordCase{
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

func adminAndRegistryCases() []recordCase {
	return []recordCase{
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

func boundaryOwned(name string) bool {
	switch name {
	case "pending-stage", "source-install", "governed-initialize", "governed-propose", "governed-cleanup", "scope-install", "scope-admit", "scope-withdraw", "admin-apply", "registry-create":
		return true
	default:
		return false
	}
}

func FuzzRegistrationRecords_DecodeBody(f *testing.F) {
	body, encoded, _, _ := qualRecordBody()
	f.Add(encoded)
	f.Add([]byte(nil))
	f.Add([]byte{0x0a, 0xff})
	f.Add([]byte{0x0a, 0x01, 0x00})
	seed := func(issuer, family []byte) []byte {
		return qualRecordFrame(body.networkDomain, issuer, body.programID, body.intentNonce, family, body.creationProfile, body.nameCommitment, body.tickerCommitment, body.propertyCommitment, body.publicSchemaProfile, body.issuerProgramAdmissionDecision, qualRecordFrame(body.proposedProgramAuthoritySetBodies...), qualRecordFrame(body.proposedProgramAuthoritySetHashes...), body.closurePlan, body.networkProfile, []byte{0, 0, 0, 0, 0, 0, 0, 1})
	}
	f.Add(seed([]byte{1}, body.requestedTokenFamily))
	f.Add(seed(body.issuer, []byte(core.NonFungibleESDT)))
	codec := &registrationRecords{marshaller: &marshal.GogoProtoMarshalizer{}, hasher: blake2b.NewBlake2b(), maxBytes: 4096}
	allowed := map[string]bool{core.FungibleESDT: true, core.NonFungibleESDTv2: true, core.SemiFungibleESDT: true, core.MetaESDT: true, core.DynamicNFTESDT: true, core.DynamicSFTESDT: true, core.DynamicMetaESDT: true}
	f.Fuzz(func(t *testing.T, input []byte) {
		got, err := codec.decodeBody(input)
		if len(input) == 0 || len(input) > codec.maxBytes {
			require.Error(t, err)
			return
		}
		if err != nil {
			return
		}
		require.Len(t, got.issuer, len(core.SystemAccountAddress))
		for _, field := range [][]byte{got.networkDomain, got.programID, got.intentNonce, got.requestedTokenFamily, got.creationProfile, got.nameCommitment, got.tickerCommitment, got.propertyCommitment, got.publicSchemaProfile, got.issuerProgramAdmissionDecision, got.networkProfile} {
			require.NotEmpty(t, field)
		}
		require.True(t, allowed[string(got.requestedTokenFamily)], "decoder accepted an unsupported new issuance family")
		require.Contains(t, []string{"burn-and-retire", "preserve-and-close"}, string(got.closurePlan))
		require.NotEmpty(t, got.proposedProgramAuthoritySetBodies)
		require.Equal(t, len(got.proposedProgramAuthoritySetBodies), len(got.proposedProgramAuthoritySetHashes))
		for _, authority := range got.proposedProgramAuthoritySetBodies {
			require.NotEmpty(t, authority)
		}
		for _, hash := range got.proposedProgramAuthoritySetHashes {
			require.Len(t, hash, codec.hasher.Size())
		}
	})
}
