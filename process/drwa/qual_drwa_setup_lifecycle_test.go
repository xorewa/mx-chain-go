package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Phase authority/finality/admin/plane/emergency/supply premises are synthetic.
// Existing convergence ACK/create/complete and native rollback actually execute;
// a host accepting these fixtures is not an admitted native provider.
type qualSetupPhases struct {
	t               *testing.T
	f               *qualLifecycleFixture
	rows            map[string]*qualConvergenceHost
	parentError     error
	transitionCalls int
}

func (h *qualSetupPhases) IsInterfaceNil() bool { return h == nil }
func (h *qualSetupPhases) VerifyTransition(binding []byte) error {
	h.transitionCalls++
	r := h.rows[string(binding)]
	if r == nil {
		return errConvergence
	}
	return r.VerifyTransition(binding)
}
func (h *qualSetupPhases) Admission(binding []byte, retained uint64) error {
	r := h.rows[string(binding)]
	if r == nil {
		return errConvergence
	}
	return r.Admission(binding, retained)
}
func (h *qualSetupPhases) VerifyAck(binding, ack, evidence []byte) (uint32, error) {
	r := h.rows[string(binding)]
	if r == nil {
		return 0, errConvergence
	}
	return r.VerifyAck(binding, ack, evidence)
}
func qualSetupParentKey(binding []byte) []byte {
	return append([]byte("fixture/setup-phase-parent/"), blake2b.NewBlake2b().Compute(string(binding))...)
}
func (h *qualSetupPhases) Complete(binding, commitment []byte) (*vmcommon.VMOutput, error) {
	if h.rows[string(binding)] == nil {
		return nil, errConvergence
	}
	qualRecordPut(h.t, h.f.x.f.store, qualSetupParentKey(binding), qualRecordFrame(binding, commitment))
	return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
}
func (h *qualSetupPhases) VerifyParent(binding, commitment []byte) error {
	if h.parentError != nil {
		return h.parentError
	}
	if h.rows[string(binding)] == nil || !bytes.Equal(qualActivationValue(h.t, h.f.x.f.store, qualSetupParentKey(binding)), qualRecordFrame(binding, commitment)) {
		return errConvergence
	}
	return nil
}

type qualSetupLifecycleHost struct {
	t                         *testing.T
	f                         *qualLifecycleFixture
	proofs                    map[string]setupPhaseEvidence
	calls, reserves           int
	admin, supply, tracking   bool
	plane                     string
	tokenHead                 bool
	verifyError, reserveError error
	verifyHook, reserveHook   func()
}

func (h *qualSetupLifecycleHost) IsInterfaceNil() bool { return h == nil }
func (h *qualSetupLifecycleHost) VerifySetupTransition(context *HeaderTimeContext, view lifecycleReadView, next string, phases []setupPhaseEvidence, certificates []byte) error {
	h.calls++
	require.Same(h.t, h.f.context, context)
	require.Equal(h.t, []byte("TOKEN-abcdef"), view.token)
	require.Equal(h.t, h.f.hash, view.cebHash)
	require.Equal(h.t, []byte("synthetic-exact-PA-setup-certificate"), certificates)
	want := []string{"READY"}
	if next == "OPEN" {
		want = []string{"SEALED", "QUIESCENCE"}
	}
	if !h.admin || next == "OPEN" && (!h.supply || !h.tracking || h.plane != "NORMAL" || h.tokenHead) {
		return errSetupLifecycle
	}
	if len(phases) != len(want) {
		return errSetupLifecycle
	}
	for i, name := range want {
		e := h.proofs[name]
		if !bytes.Equal(phases[i].binding, e.binding) || !bytes.Equal(phases[i].commitment, e.commitment) {
			return errSetupLifecycle
		}
		phases[i].binding[0] ^= 1
		phases[i].commitment[0] ^= 1
	}
	view.token[0] ^= 1
	view.cebHash[0] ^= 1
	view.supplyOrigin[0] ^= 1
	certificates[0] ^= 1
	if h.verifyHook != nil {
		h.verifyHook()
	}
	return h.verifyError
}
func (h *qualSetupLifecycleHost) ReserveSetupTransition(token []byte, epoch uint64, hash, old, next []byte) error {
	h.reserves++
	require.Equal(h.t, []byte("TOKEN-abcdef"), token)
	require.Equal(h.t, uint64(1), epoch)
	require.Equal(h.t, h.f.hash, hash)
	key := append([]byte(lifecycleRecordPrefix), qualRecordFrame(token)...)
	require.Equal(h.t, old, qualActivationValue(h.t, h.f.x.f.store, key))
	require.NotEqual(h.t, old, next)
	token[0] ^= 1
	hash[0] ^= 1
	old[0] ^= 1
	next[0] ^= 1
	qualRecordPut(h.t, h.f.x.f.store, []byte("fixture/setup-transition-budget"), []byte{1})
	if h.reserveHook != nil {
		h.reserveHook()
	}
	return h.reserveError
}

type qualSetupLifecycleFixture struct {
	f           *qualLifecycleFixture
	s           *setupLifecycle
	h           *qualSetupLifecycleHost
	ph          *qualSetupPhases
	transitions map[string]convergenceTransition
	keys        map[string][]byte
	lastOutput  *vmcommon.VMOutput
}

func qualSetupLifecycleNew(t *testing.T) *qualSetupLifecycleFixture {
	return qualSetupLifecycleWithPendingReady(t, false)
}

func qualSetupLifecycleWithPendingReady(t *testing.T, pendingReady bool) *qualSetupLifecycleFixture {
	t.Helper()
	f := qualLifecycleNew(t)
	x := &qualSetupLifecycleFixture{f: f, transitions: make(map[string]convergenceTransition), keys: make(map[string][]byte)}
	x.ph = &qualSetupPhases{t: t, f: f, rows: make(map[string]*qualConvergenceHost)}
	x.h = &qualSetupLifecycleHost{t: t, f: f, proofs: make(map[string]setupPhaseEvidence), admin: true, supply: true, tracking: true, plane: "NORMAL"}
	var err error
	x.s, err = newSetupLifecycle(f.r, x.ph, x.h)
	require.NoError(t, err)
	set := qualRecordFrame([]byte{0, 0, 0, 0}, []byte{0, 0, 0, 1}, []byte{0, 0, 0, 2})
	for i, name := range []string{"READY", "SEALED", "QUIESCENCE"} {
		tr := convergenceTransition{action: bytes.Repeat([]byte{byte(i + 1)}, 32), digest: bytes.Repeat([]byte{9}, 32), token: []byte("TOKEN-abcdef"),
			version: 1, target: bytes.Clone(f.hash), dependencies: bytes.Repeat([]byte{7}, 32), requiredSet: blake2b.NewBlake2b().Compute(string(set)), shards: []uint32{0, 1, 2},
			context: &convergencePhaseContext{family: []byte("SYNTHETIC_SETUP"), phase: []byte(name), lineage: []byte("synthetic-owning-phase-lineage"), predecessor: bytes.Repeat([]byte{6}, 32)}}
		binding := qualRecordFrame(tr.context.family, tr.action, tr.digest, tr.context.phase, tr.token, binary.BigEndian.AppendUint64(nil, 1), tr.target, tr.dependencies, tr.requiredSet, set, tr.context.lineage, tr.context.predecessor)
		key := append([]byte(convergencePrefix), qualRecordFrame(tr.context.family, tr.action, tr.context.phase, tr.context.lineage)...)
		h := &qualConvergenceHost{t: t, store: f.x.f.store, binding: binding, key: key, acks: make(map[string]uint32), faults: make(map[string]error), hooks: make(map[string]func())}
		x.ph.rows[string(binding)] = h
		x.transitions[name] = tr
		x.keys[name] = key
		acks := make([][]byte, 3)
		for j, shard := range tr.shards {
			local := bytes.Repeat([]byte{byte(j + 10)}, 32)
			ack := qualRecordFrame(binding, binary.BigEndian.AppendUint32(nil, shard), local)
			h.acks[string(ack)] = shard
			acks[j] = blake2b.NewBlake2b().Compute(string(ack))
		}
		commitment := blake2b.NewBlake2b().Compute(string(qualRecordFrame(binding, []byte{7}, qualRecordFrame(acks...))))
		x.h.proofs[name] = setupPhaseEvidence{bytes.Clone(binding), commitment}
		require.NoError(t, x.s.phases.create(tr))
		for j, shard := range tr.shards {
			if pendingReady && name == "READY" && j == len(tr.shards)-1 {
				break
			}
			require.NoError(t, x.s.phases.acknowledge(tr, shard, bytes.Repeat([]byte{byte(j + 10)}, 32), []byte("synthetic-S-R-H-M-B-proof")))
		}
		if !pendingReady || name != "READY" {
			require.NoError(t, x.s.phases.complete(tr))
		}
	}
	return x
}
func (x *qualSetupLifecycleFixture) advance(next string, phases ...string) error {
	trs := make([]convergenceTransition, len(phases))
	for i, k := range phases {
		trs[i] = x.transitions[k]
	}
	x.lastOutput = nil
	return x.f.x.f.boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		var err error
		x.lastOutput, err = x.s.advanceOwned(op, x.f.context, []byte("TOKEN-abcdef"), 1, x.f.hash, next, trs, []byte("synthetic-exact-PA-setup-certificate"))
		return []*vmcommon.VMOutput{x.lastOutput}, err
	})
}
func (x *qualSetupLifecycleFixture) lrc(t *testing.T) []byte {
	return qualActivationValue(t, x.f.x.f.store, append([]byte(lifecycleRecordPrefix), qualRecordFrame([]byte("TOKEN-abcdef"))...))
}

func TestQualDRWASetupLifecycleOriginalReceivingAndSeal(t *testing.T) {
	for _, scenario := range []string{"success", "late-refusal", "wrong-operation", "terminal-sealed", "lagging-replica", "missing-ack", "missing-certificate"} {
		t.Run(scenario, func(t *testing.T) {
			x := qualSetupLifecycleWithPendingReady(t, true)
			t.Cleanup(x.f.x.f.end)
			f := x.f
			boundary := f.x.f.boundary
			token := []byte("TOKEN-abcdef")
			if scenario == "terminal-sealed" {
				qualRecordPut(t, f.x.f.store, append([]byte(registrationActivationPrefix), token...),
					qualLifecycleParent(token, f.x.f.owner.id, "WindDownDeny"))
				qualRecordPut(t, f.x.f.store, append([]byte(lifecycleRecordPrefix), qualRecordFrame(token)...),
					qualRecordFrame(token, qualA38U64(1), []byte("WIND_DOWN_SEALED")))
			}
			if scenario == "lagging-replica" {
				// The canonical provider refuses the stale local LRC; the
				// retained local bytes alone cannot authorize another write.
				f.h.faults["lifecycle"] = errLifecycleClosed
			}
			tr := x.transitions["READY"]
			lifecycle := bytes.Clone(x.lrc(t))
			retained := bytes.Clone(qualActivationValue(t, f.x.f.store, x.keys["READY"]))
			root, err := f.x.f.store.RootHash()
			require.NoError(t, err)
			journal, outputCount := f.x.f.store.JournalLen(), len(boundary.outputs)
			failure := errors.New("synthetic original receiving failure")
			var foreign *rollbackOperation
			if scenario == "wrong-operation" {
				other, err := NewRollbackContainment(qualRegistrationStore(t, 0))
				require.NoError(t, err)
				require.NoError(t, other.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
					foreign = op
					return nil, nil
				}))
			}
			err = boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				if scenario != "missing-ack" {
					err := x.s.phases.acknowledgeOwned(op, tr, 2, bytes.Repeat([]byte{12}, 32), []byte("synthetic-S-R-H-M-B-proof"))
					if err != nil {
						return nil, err
					}
					if _, err = x.s.phases.completeOwned(op, tr); err != nil {
						return nil, err
					}
				}
				if foreign != nil {
					op = foreign
				}
				var certificates []byte
				if scenario != "missing-certificate" {
					certificates = []byte("synthetic-exact-PA-setup-certificate")
				}
				out, err := x.s.advanceOwned(op, f.context, token, 1, f.hash, "SETUP_SEALED", []convergenceTransition{tr}, certificates)
				if err != nil {
					require.Nil(t, out)
					if scenario == "missing-certificate" {
						return nil, nil // neither K nor the ACK may survive
					}
					return nil, err
				}
				require.Equal(t, qualRecordFrame(token, qualA38U64(1), []byte("SETUP_SEALED")), x.lrc(t))
				require.Len(t, boundary.outputs, outputCount)
				if scenario == "late-refusal" {
					return []*vmcommon.VMOutput{out}, failure
				}
				return []*vmcommon.VMOutput{out}, nil
			})
			switch scenario {
			case "success":
				require.NoError(t, err)
				require.Equal(t, qualRecordFrame(token, qualA38U64(1), []byte("SETUP_SEALED")), x.lrc(t))
				require.NotEqual(t, retained, qualActivationValue(t, f.x.f.store, x.keys["READY"]))
				require.Len(t, boundary.outputs, outputCount+1)
				return
			case "late-refusal":
				require.ErrorIs(t, err, failure)
			case "wrong-operation":
				require.ErrorIs(t, err, errInvalidMetaContext)
			case "lagging-replica":
				require.ErrorIs(t, err, errLifecycleClosed)
			default:
				require.ErrorIs(t, err, errSetupLifecycle)
			}
			if scenario != "late-refusal" {
				require.Zero(t, x.h.calls)
				require.Zero(t, x.h.reserves)
			}
			require.Equal(t, lifecycle, x.lrc(t))
			require.Equal(t, retained, qualActivationValue(t, f.x.f.store, x.keys["READY"]))
			after, err := f.x.f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.x.f.store.JournalLen())
			require.Len(t, boundary.outputs, outputCount)
		})
	}
}

func TestQualDRWASetupLifecycleRejectsCurrentAckAtSetupBoundary(t *testing.T) {
	x := qualSetupLifecycleNew(t)
	t.Cleanup(x.f.x.f.end)
	tr := x.transitions["READY"]
	// A missing containing context encodes CEB_CURRENTIZATION/CURRENT_ACK.
	// Keep token, CEB and all-shard set intact to exercise phase isolation.
	tr.context = nil
	x.transitions["READY"] = tr
	calls := x.ph.transitionCalls
	old := bytes.Clone(x.lrc(t))
	boundary, store := x.f.x.f.boundary, x.f.x.f.store
	root, err := store.RootHash()
	require.NoError(t, err)
	journal, outputs := store.JournalLen(), len(boundary.outputs)
	err = x.advance("SETUP_SEALED", "READY")
	require.Equal(t, calls, x.ph.transitionCalls, "the legacy phase must be refused locally before its proof provider")
	require.ErrorIs(t, err, errSetupLifecycle)
	require.Zero(t, x.h.calls)
	require.Zero(t, x.h.reserves)
	require.Nil(t, x.lastOutput)
	require.Equal(t, old, x.lrc(t))
	after, err := store.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, journal, store.JournalLen())
	require.Len(t, boundary.outputs, outputs)
}

func TestQualDRWASetupLifecycleRequiresReplicatedDurableParent(t *testing.T) {
	for _, mode := range []string{"exact", "missing-commitment", "short-commitment", "foreign-commitment", "extra-field"} {
		t.Run(mode, func(t *testing.T) {
			x := qualSetupLifecycleNew(t)
			t.Cleanup(x.f.x.f.end)
			token, intentID := []byte("TOKEN-abcdef"), x.f.x.f.owner.id
			key := append([]byte(registrationActivationPrefix), token...)
			// Explicit synthetic local application. The verifier must compare the
			// replica against its independently supplied canonical parent.
			commitment := blake2b.NewBlake2b().Compute("synthetic original readiness commitment")
			fields := [][]byte{token, intentID, []byte("Active"), commitment}
			want := qualRecordFrame(fields...)
			switch mode {
			case "missing-commitment":
				fields = fields[:3]
			case "short-commitment":
				fields[3] = commitment[1:]
			case "foreign-commitment":
				fields[3] = blake2b.NewBlake2b().Compute("different synthetic readiness commitment")
			case "extra-field":
				fields = append(fields, []byte("unallocated field"))
			}
			x.f.h.expectedActivation = want
			qualRecordPut(t, x.f.x.f.store, key, qualRecordFrame(fields...))
			err := x.advance("SETUP_SEALED", "READY")
			if mode != "exact" {
				require.Error(t, err)
				require.Zero(t, x.h.reserves)
				require.Equal(t, qualRecordFrame(token, qualA38U64(1), []byte("SETUP")), x.lrc(t))
				return
			}
			require.NoError(t, err)
			require.Equal(t, qualRecordFrame(token, qualA38U64(1), []byte("SETUP_SEALED")), x.lrc(t))
			require.NoError(t, x.advance("OPEN", "SEALED", "QUIESCENCE"))
			require.Equal(t, qualRecordFrame(token, qualA38U64(1), []byte("OPEN")), x.lrc(t))
			require.Equal(t, want, qualActivationValue(t, x.f.x.f.store, key))
		})
	}
}

func TestQualDRWASetupLifecycleSealOpenAndNoUnseal(t *testing.T) {
	x := qualSetupLifecycleNew(t)
	require.NoError(t, x.advance("SETUP_SEALED", "READY"))
	require.Equal(t, qualRecordFrame([]byte("TOKEN-abcdef"), binary.BigEndian.AppendUint64(nil, 1), []byte("SETUP_SEALED")), x.lrc(t))
	require.ErrorIs(t, x.advance("SETUP_SEALED", "READY"), errSetupLifecycle)
	require.NoError(t, x.advance("OPEN", "SEALED", "QUIESCENCE"))
	require.Equal(t, qualRecordFrame([]byte("TOKEN-abcdef"), binary.BigEndian.AppendUint64(nil, 1), []byte("OPEN")), x.lrc(t))
	require.ErrorIs(t, x.advance("SETUP_SEALED", "READY"), errSetupLifecycle)
	require.ErrorIs(t, x.advance("SETUP", "READY"), errSetupLifecycle)
	require.Equal(t, 4, x.h.calls)
	require.Equal(t, 2, x.h.reserves)
}

func TestQualDRWASetupLifecycleMissingPartialForeignAndWrongPhase(t *testing.T) {
	for _, mode := range []string{"missing", "partial", "parent missing", "parent refusal", "wrong phase", "short shard set", "foreign token", "foreign epoch", "same phase"} {
		t.Run(mode, func(t *testing.T) {
			x := qualSetupLifecycleNew(t)
			next, phases := "SETUP_SEALED", []string{"READY"}
			sentinel := errors.New("canonical parent unavailable")
			switch mode {
			case "missing":
				qualRecordPut(t, x.f.x.f.store, x.keys["READY"], nil)
			case "partial":
				e := x.h.proofs["READY"]
				qualRecordPut(t, x.f.x.f.store, x.keys["READY"], qualRecordFrame(e.binding, []byte("PENDING"), []byte{0}, qualRecordFrame(nil, nil, nil), blake2b.NewBlake2b().Compute(string(qualRecordFrame(e.binding, []byte{0}, qualRecordFrame(nil, nil, nil))))))
			case "parent missing":
				qualRecordPut(t, x.f.x.f.store, qualSetupParentKey(x.h.proofs["READY"].binding), nil)
			case "parent refusal":
				x.ph.parentError = sentinel
			case "wrong phase":
				phases = []string{"SEALED"}
			case "short shard set":
				tr := x.transitions["READY"]
				tr.shards = []uint32{0, 1}
				x.transitions["READY"] = tr
			case "foreign token":
				tr := x.transitions["READY"]
				tr.token = []byte("OTHER-abcdef")
				x.transitions["READY"] = tr
			case "foreign epoch":
				tr := x.transitions["READY"]
				tr.version = 2
				x.transitions["READY"] = tr
			case "same phase":
				require.NoError(t, x.advance("SETUP_SEALED", "READY"))
				x.h.calls, x.h.reserves = 0, 0
				next, phases = "OPEN", []string{"SEALED", "SEALED"}
			}
			old := bytes.Clone(x.lrc(t))
			err := x.advance(next, phases...)
			require.Error(t, err)
			require.Nil(t, x.lastOutput)
			if mode == "parent refusal" {
				require.ErrorIs(t, err, sentinel)
			}
			require.Equal(t, old, x.lrc(t))
			require.Zero(t, x.h.reserves)
			if mode == "wrong phase" {
				require.Equal(t, 1, x.h.calls)
			} else {
				require.Zero(t, x.h.calls)
			}
		})
	}
}

func TestQualDRWASetupLifecycleAuthorityResourceAndLateSaveRollback(t *testing.T) {
	for _, mode := range []string{"authority refusal", "authority write", "resource refusal", "phase changed", "parent changed", "LRC changed", "save failure", "premise changed"} {
		t.Run(mode, func(t *testing.T) {
			x := qualSetupLifecycleNew(t)
			sentinel := errors.New("setup transition refused")
			switch mode {
			case "authority refusal":
				x.h.verifyError = sentinel
			case "authority write":
				x.h.verifyHook = func() { qualRecordPut(t, x.f.x.f.store, []byte("fixture/setup-authority-alias"), []byte{1}) }
			case "resource refusal":
				x.h.reserveError = sentinel
			case "phase changed":
				x.h.reserveHook = func() { qualRecordPut(t, x.f.x.f.store, x.keys["READY"], nil) }
			case "parent changed":
				x.h.reserveHook = func() { qualRecordPut(t, x.f.x.f.store, qualSetupParentKey(x.h.proofs["READY"].binding), nil) }
			case "LRC changed":
				x.h.reserveHook = func() {
					qualRecordPut(t, x.f.x.f.store, append([]byte(lifecycleRecordPrefix), qualRecordFrame([]byte("TOKEN-abcdef"))...), qualRecordFrame([]byte("TOKEN-abcdef"), binary.BigEndian.AppendUint64(nil, 1), []byte("OPEN")))
				}
			case "premise changed":
				x.h.reserveHook = func() { x.h.admin = false }
			case "save failure":
				x.h.reserveHook = func() { x.f.x.f.store.saveErr = sentinel }
			}
			root, err := x.f.x.f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			old := bytes.Clone(x.lrc(t))
			err = x.advance("SETUP_SEALED", "READY")
			x.f.x.f.store.saveErr = nil
			require.Error(t, err)
			require.Nil(t, x.lastOutput)
			if mode == "authority refusal" || mode == "resource refusal" || mode == "save failure" {
				require.ErrorIs(t, err, sentinel)
			}
			if mode == "save failure" || mode == "premise changed" {
				require.Equal(t, 2, x.h.calls)
			} else {
				require.Equal(t, 1, x.h.calls)
			}
			if mode == "authority refusal" || mode == "authority write" {
				require.Zero(t, x.h.reserves)
			} else {
				require.Equal(t, 1, x.h.reserves)
			}
			after, e := x.f.x.f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, old, x.lrc(t))
		})
	}
}

type qualSetupFinalReadStore struct {
	state.AccountsAdapter
	key, replacement []byte
	armed            bool
	reads, writes    int
}

func (s *qualSetupFinalReadStore) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	account, err := s.AccountsAdapter.GetExistingAccount(address)
	if err != nil || !s.armed || !bytes.Equal(address, core.SystemAccountAddress) {
		return account, err
	}
	return &qualSetupFinalReadAccount{UserAccountHandler: account.(state.UserAccountHandler), fault: s}, nil
}

func (s *qualSetupFinalReadStore) SaveAccount(account vmcommon.AccountHandler) error {
	if wrapped, ok := account.(*qualSetupFinalReadAccount); ok {
		account = wrapped.UserAccountHandler
	}
	return s.AccountsAdapter.SaveAccount(account)
}

type qualSetupFinalReadAccount struct {
	state.UserAccountHandler
	fault *qualSetupFinalReadStore
}

func (a *qualSetupFinalReadAccount) RetrieveValue(key []byte) ([]byte, uint32, error) {
	if bytes.Equal(key, a.fault.key) {
		a.fault.reads++
		return bytes.Clone(a.fault.replacement), 0, nil
	}
	return a.UserAccountHandler.RetrieveValue(key)
}

func (a *qualSetupFinalReadAccount) SaveKeyValue(key, value []byte) error {
	if bytes.Equal(key, a.fault.key) {
		a.fault.writes++
	}
	return a.UserAccountHandler.SaveKeyValue(key, value)
}

func TestQualDRWASetupLifecycleRejectsFinalPredecessorSubstitution(t *testing.T) {
	x := qualSetupLifecycleNew(t)
	t.Cleanup(x.f.x.f.end)
	store := x.f.x.f.store
	beforeRoot, err := store.RootHash()
	require.NoError(t, err)
	beforeRoot = bytes.Clone(beforeRoot)
	beforeJournal, beforeLifecycle := store.JournalLen(), bytes.Clone(x.lrc(t))
	token := []byte("TOKEN-abcdef")
	fault := &qualSetupFinalReadStore{
		AccountsAdapter: store.AccountsAdapter,
		key:             append([]byte(lifecycleRecordPrefix), qualRecordFrame(token)...),
		replacement:     qualRecordFrame(token, binary.BigEndian.AppendUint64(nil, 1), []byte("OPEN")),
	}
	store.AccountsAdapter = fault
	// The renewed authority check is read-only. Arm the final physical read
	// fault without changing the committed value, root or journal.
	x.h.verifyHook = func() { fault.armed = x.h.calls == 2 }
	err = x.advance("SETUP_SEALED", "READY")
	fault.armed = false
	require.ErrorIs(t, err, errSetupLifecycle)
	require.Nil(t, x.lastOutput)
	require.Equal(t, 2, x.h.calls)
	require.Equal(t, 1, x.h.reserves)
	require.Equal(t, 1, fault.reads)
	require.Zero(t, fault.writes)
	require.Equal(t, beforeLifecycle, x.lrc(t))
	afterRoot, err := store.RootHash()
	require.NoError(t, err)
	require.Equal(t, beforeRoot, afterRoot)
	require.Equal(t, beforeJournal, store.JournalLen())
}

func TestQualDRWASetupLifecycleOpenRequiresEveryOwningPredicate(t *testing.T) {
	for _, mode := range []string{"admin", "supply", "tracking", "plane", "token head"} {
		t.Run(mode, func(t *testing.T) {
			x := qualSetupLifecycleNew(t)
			require.NoError(t, x.advance("SETUP_SEALED", "READY"))
			x.h.calls, x.h.reserves = 0, 0
			switch mode {
			case "admin":
				x.h.admin = false
			case "supply":
				x.h.supply = false
			case "tracking":
				x.h.tracking = false
			case "plane":
				x.h.plane = "FAIL_SAFE"
			case "token head":
				x.h.tokenHead = true
			}
			old := bytes.Clone(x.lrc(t))
			require.ErrorIs(t, x.advance("OPEN", "SEALED", "QUIESCENCE"), errSetupLifecycle)
			require.Nil(t, x.lastOutput)
			require.Equal(t, old, x.lrc(t))
			require.Equal(t, 1, x.h.calls)
			require.Zero(t, x.h.reserves)
		})
	}
}

func TestQualDRWASetupLifecycleConstructorAndExistingOperation(t *testing.T) {
	x := qualSetupLifecycleNew(t)
	for _, mode := range []string{"nil current", "nil phase", "nil authority", "execution shard"} {
		t.Run(mode, func(t *testing.T) {
			current, phases, authority := x.f.r, convergenceHost(x.ph), setupLifecycleHost(x.h)
			switch mode {
			case "nil current":
				current = nil
			case "nil phase":
				phases = nil
			case "nil authority":
				authority = nil
			case "execution shard":
				f, _, _ := qualSetupNew(t, uint32(core.Fungible), false, true)
				current = f.r
			}
			s, err := newSetupLifecycle(current, phases, authority)
			require.ErrorIs(t, err, errSetupLifecycle)
			require.Nil(t, s)
		})
	}
	out, err := x.s.advanceOwned(nil, x.f.context, []byte("TOKEN-abcdef"), 1, x.f.hash, "SETUP_SEALED",
		[]convergenceTransition{x.transitions["READY"]}, []byte("synthetic-exact-PA-setup-certificate"))
	require.ErrorIs(t, err, errCurrentLifecycle)
	require.Nil(t, out)
	require.Zero(t, x.h.calls)
	require.Zero(t, x.h.reserves)
}

func TestQualDRWASetupLifecycleArgumentAndPhaseBindingRefusals(t *testing.T) {
	for _, mode := range []string{"nil writer", "missing reader", "no certificate", "wrong phase count", "oversize certificate", "unsupported phase", "missing shard", "reordered shards", "bad action binding", "phase provider refusal"} {
		t.Run(mode, func(t *testing.T) {
			x := qualSetupLifecycleNew(t)
			writer := x.s
			tr := x.transitions["READY"]
			trs := []convergenceTransition{tr}
			certificates := []byte("synthetic-exact-PA-setup-certificate")
			next := "SETUP_SEALED"
			sentinel := errors.New("canonical setup phase refused")
			switch mode {
			case "nil writer":
				writer = nil
			case "missing reader":
				writer = &setupLifecycle{phases: x.s.phases, host: x.h}
			case "no certificate":
				certificates = nil
			case "wrong phase count":
				trs = nil
			case "oversize certificate":
				certificates = bytes.Repeat([]byte{1}, x.f.r.current.codec.maxBytes+1)
			case "unsupported phase":
				next = "SETUP"
			case "missing shard":
				trs[0].shards = []uint32{0, 1}
			case "reordered shards":
				trs[0].shards = []uint32{0, 2, 1}
			case "bad action binding":
				trs[0].action = nil
			case "phase provider refusal":
				proof := x.h.proofs["READY"]
				x.ph.rows[string(proof.binding)].faults["transition"] = sentinel
			}
			root, err := x.f.x.f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			journal := x.f.x.f.store.JournalLen()
			old := bytes.Clone(x.lrc(t))
			var output *vmcommon.VMOutput
			err = x.f.x.f.boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				var e error
				output, e = writer.advanceOwned(op, x.f.context, []byte("TOKEN-abcdef"), 1, x.f.hash, next, trs, certificates)
				return []*vmcommon.VMOutput{output}, e
			})
			require.Error(t, err)
			if mode == "phase provider refusal" {
				require.Same(t, sentinel, err)
			}
			require.Nil(t, output)
			require.Zero(t, x.h.calls)
			require.Zero(t, x.h.reserves)
			require.Equal(t, old, x.lrc(t))
			after, e := x.f.x.f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, journal, x.f.x.f.store.JournalLen())
		})
	}
}

func TestQualDRWASetupLifecycleRejectsUnavailablePhaseCodec(t *testing.T) {
	x := qualSetupLifecycleNew(t)
	reader := *x.f.r
	current := *reader.current
	codec := *current.codec
	codec.maxBytes = 0
	current.codec = &codec
	reader.current = &current
	root, err := x.f.x.f.store.RootHash()
	require.NoError(t, err)
	root = bytes.Clone(root)
	journal := x.f.x.f.store.JournalLen()
	s, err := newSetupLifecycle(&reader, x.ph, x.h)
	require.ErrorIs(t, err, errConvergence)
	require.Nil(t, s)
	require.Zero(t, x.h.calls)
	require.Zero(t, x.h.reserves)
	after, err := x.f.x.f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, journal, x.f.x.f.store.JournalLen())
}

func TestQualDRWASetupLifecycleRejectsReplacementCompleteReceipt(t *testing.T) {
	x := qualSetupLifecycleNew(t)
	binding := bytes.Clone(x.h.proofs["READY"].binding)
	key := x.keys["READY"]
	parentKey := qualSetupParentKey(binding)
	beforeReceipt := bytes.Clone(qualActivationValue(t, x.f.x.f.store, key))
	beforeParent := bytes.Clone(qualActivationValue(t, x.f.x.f.store, parentKey))
	beforeLRC := bytes.Clone(x.lrc(t))
	root, err := x.f.x.f.store.RootHash()
	require.NoError(t, err)
	root = bytes.Clone(root)
	journal := x.f.x.f.store.JournalLen()
	// An independent literal fixture has a full bitmap and matching native
	// commitment/parent, but different ACK identities. It is not canonical proof.
	acks := qualRecordFrame(bytes.Repeat([]byte{41}, 32), bytes.Repeat([]byte{42}, 32), bytes.Repeat([]byte{43}, 32))
	commitment := blake2b.NewBlake2b().Compute(string(qualRecordFrame(binding, []byte{7}, acks)))
	replacement := qualRecordFrame(binding, []byte("COMPLETE"), []byte{7}, acks, commitment)
	require.NotEqual(t, beforeReceipt, replacement)
	require.NotEqual(t, x.h.proofs["READY"].commitment, commitment)
	observed := false
	x.h.reserveHook = func() {
		qualRecordPut(t, x.f.x.f.store, key, replacement)
		qualRecordPut(t, x.f.x.f.store, parentKey, qualRecordFrame(binding, commitment))
		require.Equal(t, replacement, qualActivationValue(t, x.f.x.f.store, key))
		require.Greater(t, x.f.x.f.store.JournalLen(), journal)
		actual, e := x.f.x.f.store.RootHash()
		require.NoError(t, e)
		require.NotEqual(t, root, actual)
		observed = true
	}
	err = x.advance("SETUP_SEALED", "READY")
	require.ErrorIs(t, err, errSetupLifecycle)
	require.Nil(t, x.lastOutput)
	require.True(t, observed)
	require.Equal(t, 1, x.h.calls) // Refused before renewed authority or LRC write.
	require.Equal(t, 1, x.h.reserves)
	require.Equal(t, beforeReceipt, qualActivationValue(t, x.f.x.f.store, key))
	require.Equal(t, beforeParent, qualActivationValue(t, x.f.x.f.store, parentKey))
	require.Equal(t, beforeLRC, x.lrc(t))
	after, err := x.f.x.f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, journal, x.f.x.f.store.JournalLen())
}
