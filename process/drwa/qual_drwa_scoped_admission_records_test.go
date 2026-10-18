package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/batch"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Clause-derived DEVELOPMENT tests under the owner's 2026-10-09 instruction:
// local tests may precede model review, ALL acceptance awaits the batch audit.
// These synthetic mandates/limits are not appointments, production capacity or
// an admitted representation. Native interceptor/finality/wiring is NOT proved.
// Storage, hashing, signatures, journal rollback and trie reconstruction are real.
type qualScopedMandates struct {
	t     *testing.T
	scope []byte
	roles map[string]w03SignatureFixture
	calls int
	hook  func()
}

func (m *qualScopedMandates) IsInterfaceNil() bool { return m == nil }
func (m *qualScopedMandates) Verify(purpose string, scope, predecessor, digest, evidence []byte) error {
	m.calls++
	if m.hook != nil {
		m.hook()
	}
	role, exists := m.roles[purpose]
	if !exists || !bytes.Equal(scope, m.scope) {
		return errScopedAdmission
	}
	value := &batch.Batch{}
	if (&marshal.GogoProtoMarshalizer{}).Unmarshal(value, evidence) != nil || len(value.Data) != 3 ||
		!bytes.Equal(qualRecordFrame(value.Data...), evidence) {
		return errScopedAdmission
	}
	// The fixture separately binds purpose, exact scope and predecessor, as a
	// real resolver must. Signatures cannot be borrowed from another purpose.
	bound := qualScopedHash("MANDATE", []byte(purpose), scope, predecessor, digest)
	return verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", 3, role.members,
		[]uint64{0, 1, 2}, value.Data, bound, 5, 32)
}

func TestQualDRWAScopedAdmissionProofAndContextBoundaries(t *testing.T) {
	for _, fault := range []string{"oversized-proof", "context-invalidated-by-verifier"} {
		t.Run(fault, func(t *testing.T) {
			f := qualScopedNew(t)
			root, err := f.store.RootHash()
			require.NoError(t, err)
			proof := f.mandates.proof("ENROLL", nil, f.d.authority)
			if fault == "oversized-proof" {
				proof = make([]byte, f.records.limits.recordBytes+1)
			} else {
				f.mandates.hook = f.clock.Reset
			}
			require.Error(t, f.records.install(f.context, f.d.owner, f.d.program, nil, f.versionBody, proof))
			if fault == "oversized-proof" {
				require.Zero(t, f.mandates.calls, "bound before cloning/verifier work")
			}
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
		})
	}
}

func (m *qualScopedMandates) proof(purpose string, predecessor, digest []byte) []byte {
	role := m.roles[purpose]
	role.digest = qualScopedHash("MANDATE", []byte(purpose), m.scope, predecessor, digest)
	role.sign(m.t)
	return qualRecordFrame(role.signatures...)
}

// Independently hand-framed protobuf field-1 bytes. No production identity,
// scope, admission or Batch marshaler creates these signing preimages.
func qualScopedHash(kind string, fields ...[]byte) []byte {
	all := append([][]byte{[]byte("DRWA/SCOPED_ADMISSION/" + kind + "/candidate1"), []byte("fixture-domain")}, fields...)
	return blake2b.NewBlake2b().Compute(string(qualRecordFrame(all...)))
}

type qualScopedFixture struct {
	store              *qualNativeStore
	boundary           *RollbackContainment
	records            *scopedAdmissionRecords
	clock              *qualUnboundHeaderTime
	context            *HeaderTimeContext
	mandates           *qualScopedMandates
	d                  scopedAdmissionDecision
	scope, versionBody []byte
}

func qualScopedNew(t *testing.T) *qualScopedFixture {
	t.Helper()
	f := &qualScopedFixture{store: qualRegistrationStore(t, 0), clock: qualHeaderTimeOwner(t), versionBody: []byte("explicit synthetic scoped constitution with separate withdrawal purpose")}
	budget := make([]byte, 32)
	binary.BigEndian.PutUint64(budget, 1)
	binary.BigEndian.PutUint64(budget[8:], uint64(len(scopedAdmissionPrefix+"budget")+32))
	qualRecordPut(t, f.store, []byte(scopedAdmissionPrefix+"budget"), budget)
	_, err := f.store.Commit()
	require.NoError(t, err)
	f.boundary, err = NewRollbackContainment(f.store)
	require.NoError(t, err)
	f.context, err = f.clock.Begin(&block.MetaBlockV3{Epoch: 10, TimestampMs: 100})
	require.NoError(t, err)
	f.d = scopedAdmissionDecision{owner: bytes.Repeat([]byte{1}, 32), program: []byte("program"), issuer: bytes.Repeat([]byte{2}, 32),
		version: []byte("decision-1"), commitment: []byte("off-chain-evidence-commitment"), validUntil: 200}
	f.scope = qualRecordFrame([]byte("fixture-domain"), f.d.owner, f.d.program)
	f.d.authority = qualScopedHash("VERSION", f.scope, nil, f.versionBody)
	f.mandates = &qualScopedMandates{t: t, scope: f.scope, roles: make(map[string]w03SignatureFixture)}
	for _, purpose := range []string{"ENROLL", "SUCCESSOR", "ADMISSION"} {
		f.mandates.roles[purpose] = w03SignatureProof(t, 5, 3, []uint64{0, 1, 2})
	}
	// Owner Option 1: the SAME scoped Admission Authority, with a separately
	// explicit withdrawal mandate. Distinct purpose does not mean another signer.
	f.mandates.roles["WITHDRAW"] = f.mandates.roles["ADMISSION"]
	f.records, err = newScopedAdmissionRecords(f.store, f.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(),
		[]byte("fixture-domain"), scopedAdmissionLimits{4096, 100, 1 << 20, 100}, f.mandates, qualClockSource(f.clock, f.store))
	require.NoError(t, err)
	return f
}

func TestQualDRWAScopedAdmissionSeparateWithdrawalMandate(t *testing.T) {
	f := qualScopedNew(t)
	require.Equal(t, f.mandates.roles["ADMISSION"].members, f.mandates.roles["WITHDRAW"].members)
	f.enroll(t)
	f.admit(t)
	// Even the same roster's genuine admission signatures cannot be repurposed.
	admissionProof := f.mandates.proof("ADMISSION", f.d.authority, qualScopedHash("ADMISSION", f.body()))
	require.Error(t, f.records.withdraw(f.context, f.d, admissionProof))
	withdrawalProof := f.withdrawProof()
	mandate := f.mandates.roles["WITHDRAW"]
	delete(f.mandates.roles, "WITHDRAW")
	require.Error(t, f.records.withdraw(f.context, f.d, withdrawalProof), "admission role alone is insufficient")
	require.NoError(t, f.records.checkDecision(f.context, f.d))
	f.mandates.roles["WITHDRAW"] = mandate
	require.NoError(t, f.records.withdraw(f.context, f.d, withdrawalProof))
	require.Error(t, f.records.checkDecision(f.context, f.d))
}

func (f *qualScopedFixture) body() []byte {
	return qualRecordFrame(f.scope, f.d.issuer, f.d.version, f.d.commitment, f.d.authority,
		binary.BigEndian.AppendUint64(nil, uint64(f.d.validUntil)))
}
func (f *qualScopedFixture) id() []byte {
	return qualScopedHash("DECISION", f.scope, f.d.issuer, f.d.version)
}
func (f *qualScopedFixture) enroll(t *testing.T) {
	t.Helper()
	require.NoError(t, f.records.install(f.context, f.d.owner, f.d.program, nil, f.versionBody,
		f.mandates.proof("ENROLL", nil, f.d.authority)))
}
func (f *qualScopedFixture) admit(t *testing.T) {
	t.Helper()
	require.NoError(t, f.records.admit(f.context, f.d, f.mandates.proof("ADMISSION", f.d.authority, qualScopedHash("ADMISSION", f.body()))))
}
func (f *qualScopedFixture) withdrawProof() []byte {
	return f.mandates.proof("WITHDRAW", f.d.authority, qualScopedHash("WITHDRAW", f.scope, f.id(), f.body(), f.d.authority))
}

func TestQualDRWAScopedAdmissionOrders(t *testing.T) {
	for _, consumer := range []string{"registration", "activation"} {
		for _, withdrawalFirst := range []bool{false, true} {
			name := consumer + "/consumption-first"
			if withdrawalFirst {
				name = consumer + "/withdrawal-first"
			}
			t.Run(name, func(t *testing.T) {
				f := qualScopedNew(t)
				f.enroll(t)
				f.admit(t)
				consume := func() error {
					return f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
						return nil, f.records.checkDecision(f.context, f.d)
					})
				}
				// Observe eligibility at the actual serialized consumption instant.
				// This deliberately does NOT pretend to create/activate a token.
				if withdrawalFirst {
					require.NoError(t, f.records.withdraw(f.context, f.d, f.withdrawProof()))
					require.Error(t, consume())
				} else {
					require.NoError(t, consume())
					require.NoError(t, f.records.withdraw(f.context, f.d, f.withdrawProof()))
					require.Error(t, consume(), "later use must deny; earlier observation is not reversed")
				}
			})
		}
	}
}

func TestQualDRWAScopedAdmissionReplayAndLineage(t *testing.T) {
	f := qualScopedNew(t)
	f.enroll(t)
	f.admit(t)
	journal := f.store.JournalLen()
	f.enroll(t)
	f.admit(t)
	require.Equal(t, journal, f.store.JournalLen(), "exact duplicates add no retained fact")
	changed := f.d
	changed.commitment = []byte("conflicting immutable body")
	body := qualRecordFrame(f.scope, changed.issuer, changed.version, changed.commitment, changed.authority, binary.BigEndian.AppendUint64(nil, 200))
	require.Error(t, f.records.admit(f.context, changed, f.mandates.proof("ADMISSION", changed.authority, qualScopedHash("ADMISSION", body))))
	require.NoError(t, f.records.checkDecision(f.context, f.d))
	require.NoError(t, f.records.withdraw(f.context, f.d, f.withdrawProof()))
	journal = f.store.JournalLen()
	require.NoError(t, f.records.withdraw(f.context, f.d, f.withdrawProof()))
	f.admit(t)
	require.Equal(t, journal, f.store.JournalLen())
	require.Error(t, f.records.checkDecision(f.context, f.d), "admission resubmission cannot clear withdrawal")
	nextBody := []byte("lawful synthetic successor with own possession")
	next := qualScopedHash("VERSION", f.scope, f.d.authority, nextBody)
	require.NoError(t, f.records.install(f.context, f.d.owner, f.d.program, f.d.authority, nextBody, f.mandates.proof("SUCCESSOR", f.d.authority, next)))
	f.enroll(t) // no rollback to the retained initial version
	account, err := f.records.codec.state.systemAccount()
	require.NoError(t, err)
	current, err := f.records.current(account, f.scope)
	require.NoError(t, err)
	require.Equal(t, next, current)
	require.Error(t, f.records.checkDecision(f.context, f.d), "old admission remains stale after succession")
}

func TestQualDRWAScopedAdmissionDenials(t *testing.T) {
	for _, fault := range []string{"no-scope", "unknown-purpose", "invalid-signature", "wrong-purpose", "wrong-issuer", "wrong-program", "wrong-version", "wrong-commitment", "wrong-authority", "expired", "inactive-context", "shard-context", "missing-decision", "corrupt-current", "corrupt-decision", "corrupt-withdrawal"} {
		t.Run(fault, func(t *testing.T) {
			f := qualScopedNew(t)
			if fault != "no-scope" {
				f.enroll(t)
				f.admit(t)
			}
			before, err := f.store.RootHash()
			require.NoError(t, err)
			d := f.d
			switch fault {
			case "unknown-purpose":
				delete(f.mandates.roles, "WITHDRAW")
				require.Error(t, f.records.withdraw(f.context, d, []byte("not a mandate")))
			case "invalid-signature":
				proof := f.withdrawProof()
				proof[len(proof)-1] ^= 1
				require.Error(t, f.records.withdraw(f.context, d, proof))
			case "wrong-purpose":
				proof := f.mandates.proof("ADMISSION", d.authority, qualScopedHash("ADMISSION", f.body()))
				require.Error(t, f.records.withdraw(f.context, d, proof))
			case "wrong-issuer":
				d.issuer = bytes.Repeat([]byte{7}, 32)
			case "wrong-program":
				d.program = []byte("another")
			case "wrong-version":
				d.version = []byte("another")
			case "wrong-commitment":
				d.commitment = []byte("another")
			case "wrong-authority":
				d.authority = bytes.Repeat([]byte{7}, 32)
			case "expired":
				f.context, err = f.clock.Begin(&block.MetaBlockV3{Epoch: 10, TimestampMs: 201})
				require.NoError(t, err)
			case "inactive-context":
				f.clock.Reset()
			case "shard-context":
				f.context, err = f.clock.Begin(&block.HeaderV3{Epoch: 10, ShardID: 1, TimestampMs: 100})
				require.NoError(t, err)
			case "missing-decision":
				d.version = []byte("never-created")
			case "corrupt-current":
				qualRecordPut(t, f.store, f.records.key("current", qualScopedHash("SCOPE", f.scope)), []byte("bad"))
			case "corrupt-decision":
				qualRecordPut(t, f.store, f.records.key("decision", f.id()), []byte("bad"))
			case "corrupt-withdrawal":
				qualRecordPut(t, f.store, f.records.key("withdrawn", f.id()), []byte("bad"))
			}
			if fault != "unknown-purpose" && fault != "invalid-signature" && fault != "wrong-purpose" {
				require.Error(t, f.records.checkDecision(f.context, d))
			} else {
				after, err := f.store.RootHash()
				require.NoError(t, err)
				require.Equal(t, before, after)
				require.NoError(t, f.records.checkDecision(f.context, d))
			}
		})
	}
}

func TestQualDRWAScopedAdmissionExpiryAndIsolation(t *testing.T) {
	f := qualScopedNew(t)
	f.enroll(t)
	f.admit(t)
	for _, timestamp := range []uint64{100, 199, 200} {
		context, err := f.clock.Begin(&block.MetaBlockV3{Epoch: 10, TimestampMs: timestamp})
		require.NoError(t, err)
		require.NoError(t, f.records.checkDecision(context, f.d))
	}
	f.context, _ = f.clock.Begin(&block.MetaBlockV3{Epoch: 10, TimestampMs: 100})
	other := f.d
	other.version = []byte("independent-decision")
	otherBody := qualRecordFrame(f.scope, other.issuer, other.version, other.commitment, other.authority, binary.BigEndian.AppendUint64(nil, 200))
	require.NoError(t, f.records.admit(f.context, other, f.mandates.proof("ADMISSION", other.authority, qualScopedHash("ADMISSION", otherBody))))
	ordinaryBefore := qualRegistryValue(t, f.store, registryCountKey)
	require.NoError(t, f.records.withdraw(f.context, f.d, f.withdrawProof()))
	require.NoError(t, f.records.checkDecision(f.context, other))
	require.Equal(t, ordinaryBefore, qualRegistryValue(t, f.store, registryCountKey))
}

func TestQualDRWAScopedAdmissionPersistenceAndRollback(t *testing.T) {
	for _, fault := range []string{"none", "save", "rollback"} {
		t.Run(fault, func(t *testing.T) {
			f := qualScopedNew(t)
			f.enroll(t)
			f.admit(t)
			roots, _, err := f.boundary.Commit()
			require.NoError(t, err)
			f.boundary, err = NewRollbackContainment(f.store)
			require.NoError(t, err)
			f.records.boundary = f.boundary
			original, rollback := errors.New("native save fault"), errors.New("native rollback fault")
			if fault != "none" {
				f.store.saveErr = original
			}
			if fault == "rollback" {
				f.store.revertErr = rollback
			}
			err = f.records.withdraw(f.context, f.d, f.withdrawProof())
			if fault == "none" {
				require.NoError(t, err)
				withdrawnRoots, _, e := f.boundary.Commit()
				require.NoError(t, e)
				require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(withdrawnRoots[0])))
				require.Error(t, f.records.checkDecision(f.context, f.d))
				require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
				require.NoError(t, f.records.checkDecision(f.context, f.d), "orphaned withdrawal is not canonical")
			} else {
				require.ErrorIs(t, err, original)
				if fault == "rollback" {
					require.ErrorIs(t, err, rollback)
					_, output, e := f.boundary.Commit()
					require.Error(t, e)
					require.Empty(t, output)
					require.NoError(t, f.boundary.Recover())
				}
				require.NoError(t, f.records.checkDecision(f.context, f.d))
				current, e := f.store.RootHash()
				require.NoError(t, e)
				require.Equal(t, roots[0], current)
			}
		})
	}
}

func TestQualDRWAScopedAdmissionBudget(t *testing.T) {
	for _, fault := range []string{"count", "bytes", "rate", "malformed", "absent", "older-epoch", "overflow"} {
		t.Run(fault, func(t *testing.T) {
			f := qualScopedNew(t)
			budget := make([]byte, 32)
			binary.BigEndian.PutUint64(budget, 1)
			binary.BigEndian.PutUint64(budget[8:], uint64(len(scopedAdmissionPrefix+"budget")+32))
			switch fault {
			case "count":
				binary.BigEndian.PutUint64(budget, 99)
			case "bytes":
				binary.BigEndian.PutUint64(budget[8:], (1<<20)-1)
			case "rate":
				binary.BigEndian.PutUint64(budget[16:], 10)
				binary.BigEndian.PutUint64(budget[24:], 99)
			case "malformed":
				budget = []byte{1}
			case "absent":
				budget = nil
			case "older-epoch":
				binary.BigEndian.PutUint64(budget[16:], 11)
			case "overflow":
				binary.BigEndian.PutUint64(budget, ^uint64(0))
			}
			qualRecordPut(t, f.store, []byte(scopedAdmissionPrefix+"budget"), budget)
			_, err := f.store.Commit()
			require.NoError(t, err)
			f.boundary, err = NewRollbackContainment(f.store)
			require.NoError(t, err)
			f.records.boundary = f.boundary
			root, err := f.store.RootHash()
			require.NoError(t, err)
			require.Error(t, f.records.install(f.context, f.d.owner, f.d.program, nil, f.versionBody, f.mandates.proof("ENROLL", nil, f.d.authority)))
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
		})
	}
}

func TestQualDRWAScopedAdmissionSerializedWriters(t *testing.T) {
	f := qualScopedNew(t)
	f.enroll(t)
	f.admit(t)
	proof := f.withdrawProof()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- f.records.withdraw(f.context, f.d, proof) }()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			require.ErrorIs(t, err, ErrExecutionBusy)
		}
	}
	require.Error(t, f.records.checkDecision(f.context, f.d))
}

func TestQualDRWAScopedAdmissionFreshLineageDenial(t *testing.T) {
	f := qualScopedNew(t)
	f.enroll(t)
	f.admit(t)
	// NO withdrawal is present: isolate the current-lineage predicate.
	nextBody := []byte("independently appointed synthetic successor")
	next := qualScopedHash("VERSION", f.scope, f.d.authority, nextBody)
	require.NoError(t, f.records.install(f.context, f.d.owner, f.d.program, f.d.authority, nextBody,
		f.mandates.proof("SUCCESSOR", f.d.authority, next)))
	require.Error(t, f.records.checkDecision(f.context, f.d))
}

type qualScopedKeyFault struct {
	state.UserAccountHandler
	key   []byte
	fault error
}

func (a *qualScopedKeyFault) SaveKeyValue(key, value []byte) error {
	if bytes.Equal(key, a.key) {
		return a.fault
	}
	return a.UserAccountHandler.SaveKeyValue(key, value)
}

type qualScopedAccountFault struct {
	state.AccountsAdapter
	key   []byte
	fault error
}

func (s *qualScopedAccountFault) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	a, err := s.AccountsAdapter.GetExistingAccount(address)
	if err != nil {
		return nil, err
	}
	return &qualScopedKeyFault{a.(state.UserAccountHandler), s.key, s.fault}, nil
}

func TestQualDRWAScopedAdmissionSelectiveWriteFaults(t *testing.T) {
	for _, key := range []string{"version", "current", "budget", "decision", "withdrawn"} {
		t.Run(key, func(t *testing.T) {
			f := qualScopedNew(t)
			if key == "decision" || key == "withdrawn" {
				f.enroll(t)
			}
			if key == "withdrawn" {
				f.admit(t)
			}
			_, _, err := f.boundary.Commit()
			require.NoError(t, err)
			original := errors.New("selected key save fault")
			var exact []byte
			switch key {
			case "version":
				exact = f.records.key(key, f.d.authority)
			case "current":
				exact = f.records.key(key, qualScopedHash("SCOPE", f.scope))
			case "budget":
				exact = []byte(scopedAdmissionPrefix + "budget")
			default:
				exact = f.records.key(key, f.id())
			}
			faulted := &qualScopedAccountFault{f.store, exact, original}
			f.boundary, err = NewRollbackContainment(faulted)
			require.NoError(t, err)
			f.records, err = newScopedAdmissionRecords(faulted, f.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(),
				[]byte("fixture-domain"), scopedAdmissionLimits{4096, 100, 1 << 20, 100}, f.mandates, qualClockSource(f.clock, faulted))
			require.NoError(t, err)
			root, err := f.store.RootHash()
			require.NoError(t, err)
			switch key {
			case "decision":
				err = f.records.admit(f.context, f.d, f.mandates.proof("ADMISSION", f.d.authority, qualScopedHash("ADMISSION", f.body())))
			case "withdrawn":
				err = f.records.withdraw(f.context, f.d, f.withdrawProof())
			default:
				err = f.records.install(f.context, f.d.owner, f.d.program, nil, f.versionBody, f.mandates.proof("ENROLL", nil, f.d.authority))
			}
			require.ErrorIs(t, err, original)
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
		})
	}
}

func TestQualDRWAScopedAdmissionDependenciesAndRateReset(t *testing.T) {
	f := qualScopedNew(t)
	limits := scopedAdmissionLimits{4096, 100, 1 << 20, 100}
	_, err := newScopedAdmissionRecords(f.store, nil, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"), limits, f.mandates, qualClockSource(f.clock, f.store))
	require.Error(t, err)
	_, err = newScopedAdmissionRecords(f.store, f.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"), limits, nil, qualClockSource(f.clock, f.store))
	require.Error(t, err)
	_, err = newScopedAdmissionRecords(qualRegistrationStore(t, 0), f.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"), limits, f.mandates, qualClockSource(f.clock, f.store))
	require.Error(t, err, "containment must own the actual store")
	f.enroll(t)
	f.admit(t)
	f.records.limits.newRecordsPerEpoch = 3
	require.Error(t, f.records.withdraw(f.context, f.d, f.withdrawProof()), "two scope keys plus decision exhaust this epoch")
	f.context, err = f.clock.Begin(&block.MetaBlockV3{Epoch: 11, TimestampMs: 100})
	require.NoError(t, err)
	require.NoError(t, f.records.withdraw(f.context, f.d, f.withdrawProof()))
	require.Error(t, f.records.checkDecision(f.context, f.d))
}
