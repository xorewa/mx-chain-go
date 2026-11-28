package drwa

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-29 (Part A L2220-2228, L11145; ledger L31/L38). EXPERIMENTAL VALUES ONLY:
// every limit in these files is a test input. The owner has adopted no number.
//
// sp229Model is the independent expected model. It is written from the clause,
// not from the production functions: one chain-global budget of retained
// records, retained bytes and new records per epoch, plus the permanent token
// cap; a request is admitted whole or not at all; nothing is ever returned.
type sp229Limits struct {
	recordBytes                       int
	records, bytes, perEpoch, maxEver uint64
}

type sp229Write struct {
	key   string
	value []byte
}

type sp229Model struct {
	lim                                  sp229Limits
	count, size, rateEpoch, rate, tokens uint64
	held                                 map[string]int
}

func (m *sp229Model) admit(epoch uint64, token bool, writes []sp229Write) bool {
	if epoch < m.rateEpoch || token && m.tokens >= m.lim.maxEver {
		return false
	}
	rate := m.rate
	if epoch > m.rateEpoch {
		rate = 0
	}
	var fresh, grown uint64
	for _, w := range writes {
		old, exists := m.held[w.key]
		switch {
		case !exists:
			fresh++
			grown += uint64(len(w.key) + len(w.value))
		case len(w.value) < old:
			return false
		default:
			grown += uint64(len(w.value) - old)
		}
	}
	if m.count+fresh > m.lim.records || rate+fresh > m.lim.perEpoch || m.size+grown > m.lim.bytes {
		return false
	}
	for _, w := range writes {
		m.held[w.key] = len(w.value)
	}
	m.count, m.size, m.rateEpoch, m.rate = m.count+fresh, m.size+grown, epoch, rate+fresh
	if token {
		m.tokens++
	}
	return true
}

func (m *sp229Model) budget() []byte {
	b := binary.BigEndian.AppendUint64(nil, m.count)
	b = binary.BigEndian.AppendUint64(b, m.size)
	b = binary.BigEndian.AppendUint64(b, m.rateEpoch)
	return binary.BigEndian.AppendUint64(b, m.rate)
}

// Synthetic trusted adapters. They authenticate nothing and are labelled so:
// this row bounds resources, the authority rows own the real verifiers.
type sp229Verifier struct{ calls int }

func (v *sp229Verifier) IsInterfaceNil() bool { return v == nil }
func (v *sp229Verifier) VerifyRegistration(string, []byte, []byte, []byte, []byte, []byte, HeaderMilliseconds, uint32) error {
	v.calls++
	return nil
}
func (v *sp229Verifier) VerifyBootstrapCancellation(string, []byte, []byte, HeaderMilliseconds, uint32) error {
	v.calls++
	return nil
}
func (v *sp229Verifier) Verify(string, []byte, []byte, []byte, []byte) error {
	v.calls++
	return nil
}

const sp229BudgetKey = "ELRONDDRWA@scopedAdmission@budget"

type sp229World struct {
	t            *testing.T
	lim          sp229Limits
	store        *qualNativeStore
	clock        *qualUnboundHeaderTime
	context      *HeaderTimeContext
	epoch        uint32
	time         uint64
	registration *RegistryRegistration
	boundary     *RollbackContainment
	scoped       *scopedAdmissionRecords
	verifier     *sp229Verifier
	model        *sp229Model
}

func sp229New(t *testing.T, lim sp229Limits) *sp229World {
	t.Helper()
	w := &sp229World{t: t, lim: lim, store: qualRegistrationStore(t, 0), clock: qualHeaderTimeOwner(t), epoch: 10, time: 1, verifier: &sp229Verifier{}}
	t.Cleanup(func() { _ = w.store.Close() })
	w.model = &sp229Model{lim: lim, count: 1, size: uint64(len(sp229BudgetKey) + 32), rateEpoch: 10, held: map[string]int{}}
	qualRecordPut(t, w.store, []byte(sp229BudgetKey), w.model.budget())
	_, err := w.store.Commit()
	require.NoError(t, err)
	w.build()
	w.header()
	return w
}

func (w *sp229World) build() {
	coordinator := testscommon.NewMultiShardsCoordinatorMock(3)
	coordinator.CurrentShard = core.MetachainShardId
	var err error
	w.registration, w.boundary, err = NewRegistryRegistration(w.store, coordinator, w.lim.maxEver)
	require.NoError(w.t, err)
	w.scoped, err = newScopedAdmissionRecords(w.store, w.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(),
		[]byte("fixture-domain"), scopedAdmissionLimits{w.lim.recordBytes, w.lim.records, w.lim.bytes, w.lim.perEpoch},
		w.verifier, qualClockSource(w.clock, w.store))
	require.NoError(w.t, err)
}

func (w *sp229World) header() {
	var err error
	w.context, err = w.clock.Begin(&block.MetaBlockV3{Epoch: w.epoch, TimestampMs: w.time})
	require.NoError(w.t, err)
}

// restart commits, reopens the trie at the committed root and rebuilds every
// owner from the same configured inputs. Nothing is carried in memory.
func (w *sp229World) restart() {
	roots, _, err := w.boundary.Commit()
	require.NoError(w.t, err)
	require.NoError(w.t, w.store.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
	require.Zero(w.t, w.store.JournalLen())
	w.build()
}

func (w *sp229World) resources() RegistrationResourceLimits {
	return RegistrationResourceLimits{w.lim.records, w.lim.bytes, w.lim.perEpoch}
}

type sp229Intent struct {
	body                bootstrapIntentBody
	v                   qualCreationVector
	encoded, digest, id []byte
	token               string
}

func sp229IntentFor(n int) sp229Intent {
	body, _, _, _, v := qualCreationIntent(core.FungibleESDT)
	body.intentNonce = []byte(fmt.Sprintf("nonce-%d", n))
	encoded, digest, id := qualCreationIntentBytes(body)
	return sp229Intent{body, v, encoded, digest, id, fmt.Sprintf("TKN-%06x", n)}
}

func (w *sp229World) admission(i sp229Intent) *RegistrationAdmission {
	owner, err := w.registration.BindIntent(i.id, i.digest, bytes.Repeat([]byte{0x22}, 32), &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), w.lim.recordBytes)
	require.NoError(w.t, err)
	p := []byte("synthetic")
	admit, err := owner.WithRegistrationAdmission(qualClockSource(w.clock, w.store), []byte("n"), 10, w.resources(), w.verifier,
		RegistrationProofs{p, p, p, p, p, p, p, p})
	require.NoError(w.t, err)
	return admit
}

type sp229Scope struct {
	d                           scopedAdmissionDecision
	scope, body, version, value []byte
}

func sp229ScopeFor(n int) sp229Scope {
	s := sp229Scope{body: []byte(fmt.Sprintf("synthetic scoped constitution %d", n))}
	s.d = scopedAdmissionDecision{owner: bytes.Repeat([]byte{byte(n), byte(n >> 8)}, 16), program: []byte("program"), issuer: bytes.Repeat([]byte{2}, 32),
		version: []byte("decision-1"), commitment: []byte("off-chain-evidence-commitment"), validUntil: 200}
	s.scope = qualRecordFrame([]byte("fixture-domain"), s.d.owner, s.d.program)
	s.version = qualScopedHash("VERSION", s.scope, nil, s.body)
	s.d.authority = s.version
	s.value = qualRecordFrame(s.scope, s.d.issuer, s.d.version, s.d.commitment, s.d.authority, binary.BigEndian.AppendUint64(nil, 200))
	return s
}

func (s sp229Scope) decisionID() string {
	return string(qualScopedHash("DECISION", s.scope, s.d.issuer, s.d.version))
}

// A request carries its production call and, independently framed, the exact
// records the clause says it retains.
type sp229Request struct {
	name   string
	token  bool
	writes []sp229Write
	run    func(*sp229World) error
}

func sp229OpenIntent(i sp229Intent) sp229Request {
	return sp229Request{name: "intent", writes: []sp229Write{{"ELRONDDRWA@registration@intent@" + string(i.id), qualRecordFrame(i.encoded, []byte("OPEN"), nil)}},
		run: func(w *sp229World) error { return w.admission(i).RetainBootstrapIntent(i.encoded, []byte("synthetic")) }}
}

func sp229Register(i sp229Intent) sp229Request {
	token, manager := []byte(i.token), bytes.Repeat([]byte{0x22}, 32)
	return sp229Request{name: "register", token: true, writes: []sp229Write{
		{"ELRONDDRWA@registration@activation@" + i.token, qualRecordFrame(token, i.id, []byte("BootstrapDeny"))},
		{"ELRONDDRWA@registration@token@" + i.token, qualRecordFrame(token, i.id, i.digest, i.encoded, manager)},
		{"ELRONDDRWA@registration@intent@" + string(i.id), qualRecordFrame(i.encoded, []byte("CONSUMED"), token)}},
		run: func(w *sp229World) error {
			// Synthetic native creator: it returns the identifier and writes no
			// native token record. The System-SC tests use the real creator.
			return w.admission(i).RegisterTokenForAuthenticatedCreation(i.id, i.v.body, i.body.issuer, manager,
				i.body.requestedTokenFamily, i.v.profile, i.v.name, i.v.ticker, 6,
				func(state.AccountsAdapter, []byte, []byte, []byte, []byte, []byte, uint32, [][]byte) ([]byte, *vmcommon.VMOutput, error) {
					return bytes.Clone(token), &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, ReturnData: [][]byte{bytes.Clone(token)}}, nil
				})
		}}
}

func sp229Retire(i sp229Intent) sp229Request {
	token, native, proof := []byte(i.token), []byte("native-token-record"), []byte("synthetic")
	return sp229Request{name: "retire", writes: []sp229Write{
		{"ELRONDDRWA@registration@activation@" + i.token, qualRecordFrame(token, i.id, []byte("RetiredDeny"), native, proof, proof, proof)}},
		run: func(w *sp229World) error {
			cancel, err := w.admission(i).owner.WithBootstrapCancellation(qualClockSource(w.clock, w.store), []byte("n"), 10, w.resources(), w.verifier)
			require.NoError(w.t, err)
			return cancel.CancelBootstrapRegistration(token, i.id, proof, proof, proof,
				func(state.AccountsAdapter, []byte, []byte, []byte) ([]byte, error) { return bytes.Clone(native), nil })
		}}
}

func sp229Enroll(s sp229Scope) sp229Request {
	return sp229Request{name: "enroll", writes: []sp229Write{
		{"ELRONDDRWA@scopedAdmission@version@" + string(s.version), qualRecordFrame(s.scope, nil, s.body)},
		{"ELRONDDRWA@scopedAdmission@current@" + string(qualScopedHash("SCOPE", s.scope)), qualRecordFrame(s.scope, s.version)}},
		run: func(w *sp229World) error {
			return w.scoped.install(w.context, s.d.owner, s.d.program, nil, s.body, []byte("synthetic"))
		}}
}

func sp229Decide(s sp229Scope) sp229Request {
	return sp229Request{name: "decide", writes: []sp229Write{{"ELRONDDRWA@scopedAdmission@decision@" + s.decisionID(), s.value}},
		run: func(w *sp229World) error { return w.scoped.admit(w.context, s.d, []byte("synthetic")) }}
}

func sp229Withdraw(s sp229Scope) sp229Request {
	return sp229Request{name: "withdraw", writes: []sp229Write{{"ELRONDDRWA@scopedAdmission@withdrawn@" + s.decisionID(), s.value}},
		run: func(w *sp229World) error { return w.scoped.withdraw(w.context, s.d, []byte("synthetic")) }}
}

func (w *sp229World) root() []byte {
	root, err := w.store.RootHash()
	require.NoError(w.t, err)
	return root
}

// apply runs one request through production and through the model and compares
// them. It returns whether the request was admitted.
func (w *sp229World) apply(r sp229Request, label string) bool {
	w.t.Helper()
	before, journal, outputs := w.root(), w.store.JournalLen(), len(w.boundary.outputs)
	budget := bytes.Clone(qualRegistryValue(w.t, w.store, sp229BudgetKey))
	registry := bytes.Clone(qualRegistryValue(w.t, w.store, registryCountKey))
	expected := w.model.admit(uint64(w.epoch), r.token, r.writes)
	err := r.run(w)
	require.Equal(w.t, expected, err == nil, "%s: production %v, model admitted=%v", label, err, expected)
	after := qualRegistryValue(w.t, w.store, sp229BudgetKey)
	require.Equal(w.t, w.model.budget(), after, label)
	require.Equal(w.t, w.model.tokens, binary.BigEndian.Uint64(qualRegistryValue(w.t, w.store, registryCountKey)), label)
	if !expected {
		// A denied request leaves no retained DRWA state, record or journal entry.
		require.Equal(w.t, before, w.root(), label)
		require.Equal(w.t, journal, w.store.JournalLen(), label)
		require.Len(w.t, w.boundary.outputs, outputs, label)
		require.Equal(w.t, budget, after, label)
		require.Equal(w.t, registry, qualRegistryValue(w.t, w.store, registryCountKey), label)
		return false
	}
	for _, write := range r.writes {
		require.Equal(w.t, write.value, qualRegistryValue(w.t, w.store, write.key), label)
	}
	// Retained usage never decreases.
	require.GreaterOrEqual(w.t, binary.BigEndian.Uint64(after), binary.BigEndian.Uint64(budget), label)
	require.GreaterOrEqual(w.t, binary.BigEndian.Uint64(after[8:]), binary.BigEndian.Uint64(budget[8:]), label)
	return true
}

func (w *sp229World) nextEpoch() {
	w.epoch++
	w.header()
}
