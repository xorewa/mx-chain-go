package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// L46 DEVELOPMENT. Authority/semantic schema/currentness/funding/initialization
// and projection/native effect hosts are SYNTHETIC, not admitted native routes.
// AccountsDB/trie, save/rollback/commit/recreation and T05 time are real.
type qualGovernedActionHost struct {
	store                     *qualNativeStore
	envelope                  []byte
	faults                    map[string]error
	hooks                     map[string]func()
	protected, arm, nilOutput bool
	badOutput                 bool
	lifetime                  HeaderMilliseconds
	proposalCalls, effects    int
	minimum, maximum          HeaderMilliseconds
}

func (h *qualGovernedActionHost) IsInterfaceNil() bool { return h == nil }
func (h *qualGovernedActionHost) check(stage string, envelope []byte) error {
	if hook := h.hooks[stage]; hook != nil {
		hook()
	}
	if stage != "initialize" && !bytes.Equal(envelope, h.envelope) {
		return errGovernedActionRecord
	}
	return h.faults[stage]
}
func (h *qualGovernedActionHost) Initialize(identity, token []byte) error {
	return h.check("initialize", identity)
}
func (h *qualGovernedActionHost) Proposal(envelope []byte, retained uint64) (HeaderMilliseconds, HeaderMilliseconds, bool, error) {
	h.proposalCalls++
	if retained == 0 {
		return 0, 0, false, errGovernedActionRecord
	}
	return h.minimum, h.maximum, h.protected, h.check("proposal", envelope)
}
func (h *qualGovernedActionHost) Authorize(id, digest, envelope, certificates []byte) error {
	if !bytes.Equal(certificates, []byte("synthetic-full-authorize")) {
		return errGovernedActionRecord
	}
	return h.check("authorize", envelope)
}
func (h *qualGovernedActionHost) Start(id, digest, envelope, certificates []byte) (bool, HeaderMilliseconds, error) {
	if !bytes.Equal(certificates, []byte("synthetic-current-start")) {
		return false, 0, errGovernedActionRecord
	}
	return h.arm, h.lifetime, h.check("start", envelope)
}
func (h *qualGovernedActionHost) ApplyStart(id, digest, envelope []byte, arm bool, expiry HeaderMilliseconds) (*vmcommon.VMOutput, error) {
	h.effects++
	if err := h.check("apply", envelope); err != nil {
		return nil, err
	}
	if err := qualContainmentBalance(h.store, 97); err != nil {
		return nil, err
	}
	a, err := h.store.GetExistingAccount(core.SystemAccountAddress)
	if err != nil {
		return nil, err
	}
	if err = a.(state.UserAccountHandler).SaveKeyValue([]byte("fixture/gas-native-effect"), []byte("preserved")); err != nil {
		return nil, err
	}
	if err = h.store.SaveAccount(a); err != nil {
		return nil, err
	}
	if h.nilOutput {
		return nil, nil
	}
	output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 31,
		ReturnData:    [][]byte{bytes.Clone(id), bytes.Clone(digest), binary.BigEndian.AppendUint64(nil, uint64(expiry))},
		ReturnMessage: "synthetic-owned-first-effect"}
	if arm {
		output.ReturnMessage = "synthetic-owned-projection"
	}
	if h.badOutput {
		output.ReturnCode = vmcommon.UserError
	}
	return output, nil
}
func (h *qualGovernedActionHost) Cleanup(id, envelope []byte, status, reason string, evidence []byte) error {
	if !bytes.Equal(evidence, []byte("synthetic-no-irreversible-proof")) {
		return errGovernedActionRecord
	}
	return h.check("cleanup", envelope)
}

type qualGovernedActionFixture struct {
	s *qualNativeStore
	o *RollbackContainment
	g *governedActionRecords
	c *qualUnboundHeaderTime
	x *HeaderTimeContext
	h *qualGovernedActionHost
	p governedActionProposal
}

func qualGovernedActionNew(t *testing.T) *qualGovernedActionFixture {
	t.Helper()
	f := &qualGovernedActionFixture{s: qualRegistrationStore(t, 0), c: qualHeaderTimeOwner(t)}
	f.h = &qualGovernedActionHost{store: f.s, faults: make(map[string]error), hooks: make(map[string]func()),
		minimum: 5, maximum: 20, lifetime: 7}
	f.p = governedActionProposal{subject: []byte("program-subject"), class: []byte("synthetic-class"),
		token: []byte("TOKEN-abcdef"), payload: []byte("synthetic-complete-class-body"),
		bindings: []byte("synthetic-frozen-current-dependencies"), earliest: 105, until: 120}
	f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 100)
	f.reopen(t, f.s)
	return f
}
func (f *qualGovernedActionFixture) reopen(t *testing.T, accounts state.AccountsAdapter) {
	t.Helper()
	var err error
	f.o, err = NewRollbackContainment(accounts)
	require.NoError(t, err)
	f.g, err = newGovernedActionRecords(accounts, f.o, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096,
		[]byte("n"), 4, 2, 2, f.h, qualClockSource(f.c, accounts))
	require.NoError(t, err)
}
func (f *qualGovernedActionFixture) initialize(t *testing.T) {
	t.Helper()
	require.NoError(t, f.g.initialize(f.x, f.p.subject, f.p.class, f.p.token))
}
func (f *qualGovernedActionFixture) commit(t *testing.T) []byte {
	t.Helper()
	roots, _, err := f.o.Commit()
	require.NoError(t, err)
	require.Len(t, roots, 1)
	f.reopen(t, f.s)
	return roots[0]
}
func (f *qualGovernedActionFixture) expected(time uint64) (envelope, digest, id []byte) {
	p := f.p
	envelope = qualRecordFrame([]byte("n"), p.subject, p.class, p.token, binary.BigEndian.AppendUint64(nil, p.nonce),
		binary.BigEndian.AppendUint64(nil, time), binary.BigEndian.AppendUint64(nil, uint64(p.earliest)),
		binary.BigEndian.AppendUint64(nil, uint64(p.until)), p.payload, p.bindings)
	hasher := blake2b.NewBlake2b()
	digest = hasher.Compute("DRWA/GAS/PAYLOAD/v1" + string(envelope))
	id = hasher.Compute("DRWA/GAS/v1" + "n" + string(p.subject) + string(p.class) +
		string(binary.BigEndian.AppendUint64(nil, p.nonce)) + string(digest))
	return
}
func (f *qualGovernedActionFixture) propose(t *testing.T) []byte {
	t.Helper()
	time, err := f.x.Milliseconds()
	require.NoError(t, err)
	e, _, expectedID := f.expected(uint64(time))
	f.h.envelope = e
	id, err := f.g.propose(f.x, f.p)
	require.NoError(t, err)
	require.Equal(t, expectedID, id)
	return id
}
func (f *qualGovernedActionFixture) counter() []byte {
	return append([]byte(governedActionPrefix+"nonce@"), qualRecordFrame([]byte("n"), f.p.subject, f.p.class)...)
}
func (f *qualGovernedActionFixture) activeKey() []byte {
	return append([]byte(governedActionPrefix+"active@"), qualRecordFrame([]byte("n"), f.p.token)...)
}
func (f *qualGovernedActionFixture) count(t *testing.T, want int) {
	t.Helper()
	m, err := f.g.members(qualRegistryValue(t, f.s, string(f.activeKey())))
	require.NoError(t, err)
	require.Len(t, m, want)
}
func (f *qualGovernedActionFixture) denied(t *testing.T, operation func() error) {
	t.Helper()
	root, err := f.s.RootHash()
	require.NoError(t, err)
	journal := f.s.JournalLen()
	require.Error(t, operation())
	after, err := f.s.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, journal, f.s.JournalLen())
}

func TestQualDRWAGASAuthoritativeProposalAndStart(t *testing.T) {
	for _, arm := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "arm"}[arm], func(t *testing.T) {
			f := qualGovernedActionNew(t)
			f.initialize(t)
			f.h.arm = arm
			id := f.propose(t)
			envelope, digest, _ := f.expected(100)
			r, key, value, err := f.g.load(id)
			require.NoError(t, err)
			require.Equal(t, qualRecordFrame(envelope, digest, []byte("PROPOSED"), []byte{0}, make([]byte, 8), make([]byte, 8), nil), value)
			require.Equal(t, "PROPOSED", r.status)
			require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 1}, qualRegistryValue(t, f.s, string(f.counter())))
			f.count(t, 1)
			f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 105)
			require.NoError(t, f.g.authorize(f.x, id, []byte("synthetic-full-authorize")))
			journal := f.s.JournalLen()
			require.NoError(t, f.g.authorize(f.x, id, []byte("synthetic-full-authorize")))
			require.Equal(t, journal, f.s.JournalLen())
			require.NoError(t, f.g.start(f.x, id, []byte("synthetic-current-start")))
			r, _, _, err = f.g.load(id)
			require.NoError(t, err)
			require.Equal(t, "IN_PROGRESS", r.status)
			require.Equal(t, HeaderMilliseconds(105), r.started)
			expiry := uint64(0)
			if arm {
				expiry = 112
			}
			require.Equal(t, HeaderMilliseconds(expiry), r.expiry)
			require.Equal(t, qualRecordFrame(envelope, digest, []byte("IN_PROGRESS"), []byte{0}, binary.BigEndian.AppendUint64(nil, 105), binary.BigEndian.AppendUint64(nil, expiry), nil), qualRegistryValue(t, f.s, string(key)))
			qualAssertContainmentBalance(t, f.s, 97)
			require.Equal(t, []byte("preserved"), qualRegistryValue(t, f.s, "fixture/gas-native-effect"))
			f.denied(t, func() error { return f.g.start(f.x, id, []byte("synthetic-current-start")) })
			require.Equal(t, 1, f.h.effects)
			f.count(t, 1)
			f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 999)
			f.denied(t, func() error { return f.g.cleanup(f.x, id, "EXPIRED", []byte("synthetic-no-irreversible-proof")) })
			roots, outputs, err := f.o.Commit()
			require.NoError(t, err)
			var native *vmcommon.VMOutput
			for _, output := range outputs {
				if output != nil {
					native = output
				}
			}
			require.NotNil(t, native)
			require.Equal(t, [][]byte{id, digest, binary.BigEndian.AppendUint64(nil, expiry)}, native.ReturnData)
			require.Equal(t, uint64(31), native.GasRemaining)
			require.NoError(t, f.s.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
			f.reopen(t, f.s)
			r, _, _, err = f.g.load(id)
			require.NoError(t, err)
			require.Equal(t, "IN_PROGRESS", r.status)
			f.count(t, 1)
		})
	}
}

func TestQualDRWAGASProposalDenials(t *testing.T) {
	for _, name := range []string{"missing_counter", "corrupt_counter", "missing_aggregate", "corrupt_aggregate", "future_nonce", "counter_overflow", "below_minimum", "equal_end", "above_maximum", "payload_empty", "bindings_empty", "bad_token", "oversized", "proposal_denied", "context_reset", "wrong_locus", "counter_callback_mutation"} {
		t.Run(name, func(t *testing.T) {
			f := qualGovernedActionNew(t)
			if name != "missing_counter" {
				f.initialize(t)
			}
			switch name {
			case "corrupt_counter":
				qualRecordPut(t, f.s, f.counter(), []byte{1})
			case "missing_aggregate":
				qualRecordPut(t, f.s, f.activeKey(), nil)
			case "corrupt_aggregate":
				qualRecordPut(t, f.s, f.activeKey(), []byte{1})
			case "future_nonce":
				f.p.nonce = 1
			case "counter_overflow":
				f.p.nonce = math.MaxUint64
				qualRecordPut(t, f.s, f.counter(), bytes.Repeat([]byte{255}, 8))
			case "below_minimum":
				f.p.earliest = 104
			case "equal_end":
				f.p.until = 105
			case "above_maximum":
				f.p.until = 121
			case "payload_empty":
				f.p.payload = nil
			case "bindings_empty":
				f.p.bindings = nil
			case "bad_token":
				f.p.token = []byte("bad")
			case "oversized":
				f.p.payload = make([]byte, 4097)
			case "proposal_denied":
				f.h.faults["proposal"] = errors.New("synthetic authority/resource refusal")
			case "context_reset":
				f.h.hooks["proposal"] = f.c.Reset
			case "wrong_locus":
				f.x = qualGovernedContext(t, f.c, 1, 100)
			case "counter_callback_mutation":
				f.h.hooks["proposal"] = func() { qualRecordPut(t, f.s, f.counter(), []byte{0, 0, 0, 0, 0, 0, 0, 9}) }
			}
			f.commit(t)
			e, _, _ := f.expected(100)
			f.h.envelope = e
			f.denied(t, func() error { _, err := f.g.propose(f.x, f.p); return err })
			require.Zero(t, f.h.effects)
		})
	}
}

func TestQualDRWAGASProtectedPartitionAndRefill(t *testing.T) {
	f := qualGovernedActionNew(t)
	f.initialize(t)
	var ids [][]byte
	var envelopes [][]byte
	for i := 0; i < 4; i++ {
		f.p.nonce = uint64(i)
		f.h.protected = i >= 2
		if i == 2 {
			f.h.protected = false
			f.h.envelope, _, _ = f.expected(100)
			f.denied(t, func() error { _, err := f.g.propose(f.x, f.p); return err })
			require.Equal(t, uint64(2), binary.BigEndian.Uint64(qualRegistryValue(t, f.s, string(f.counter()))))
			f.h.protected = true
		}
		ids = append(ids, f.propose(t))
		envelopes = append(envelopes, bytes.Clone(f.h.envelope))
	}
	f.count(t, 4)
	f.p.nonce = 4
	f.h.envelope, _, _ = f.expected(100)
	f.denied(t, func() error { _, err := f.g.propose(f.x, f.p); return err })
	// Current authority loss cannot be disguised as protected admission.
	f.h.envelope = envelopes[0]
	f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 105)
	require.NoError(t, f.g.authorize(f.x, ids[0], []byte("synthetic-full-authorize")))
	f.h.faults["start"] = errors.New("synthetic generation superseded")
	f.denied(t, func() error { return f.g.start(f.x, ids[0], []byte("synthetic-current-start")) })
	f.h.faults["start"] = nil
	require.NoError(t, f.g.start(f.x, ids[0], []byte("synthetic-current-start")))
	f.count(t, 4)
	f.h.envelope = envelopes[1]
	f.denied(t, func() error { return f.g.cleanup(f.x, ids[1], "EXPIRED", []byte("synthetic-no-irreversible-proof")) })
	f.denied(t, func() error { return f.g.cleanup(f.x, ids[1], "STALE_BINDING", []byte("missing-proof")) })
	require.NoError(t, f.g.cleanup(f.x, ids[1], "STALE_BINDING", []byte("synthetic-no-irreversible-proof")))
	f.count(t, 3)
	f.p.nonce, f.p.earliest, f.p.until, f.h.protected = 4, 110, 125, false
	f.propose(t)
	f.count(t, 4)
	// Counter remains advanced after removal; reinitialization cannot reset it.
	require.NoError(t, f.g.initialize(f.x, f.p.subject, f.p.class, f.p.token))
	require.Equal(t, uint64(5), binary.BigEndian.Uint64(qualRegistryValue(t, f.s, string(f.counter()))))
	f.p.nonce = 1
	f.h.envelope, _, _ = f.expected(105)
	f.denied(t, func() error { _, err := f.g.propose(f.x, f.p); return err })
}

func TestQualDRWAGASStartBoundaryAndProofs(t *testing.T) {
	for _, phase := range []string{"authorize", "start"} {
		for _, name := range []string{"before", "earliest", "last", "until", "wrong_proof", "oversized_proof", "host_denial", "reset", "wrong_locus", "record_corrupt"} {
			t.Run(phase+"/"+name, func(t *testing.T) {
				f := qualGovernedActionNew(t)
				f.initialize(t)
				id := f.propose(t)
				f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 105)
				if phase == "start" {
					require.NoError(t, f.g.authorize(f.x, id, []byte("synthetic-full-authorize")))
				}
				proof := []byte("synthetic-full-authorize")
				if phase == "start" {
					proof = []byte("synthetic-current-start")
				}
				time := uint64(105)
				switch name {
				case "before":
					time = 104
				case "last":
					time = 119
				case "until":
					time = 120
				case "wrong_proof":
					proof = []byte("synthetic-partial-or-other-purpose")
				case "oversized_proof":
					proof = make([]byte, 4097)
				case "host_denial":
					f.h.faults[phase] = errors.New("synthetic current authority refused")
				case "reset":
					f.h.hooks[phase] = f.c.Reset
				case "record_corrupt":
					_, key, _, err := f.g.load(id)
					require.NoError(t, err)
					qualRecordPut(t, f.s, key, []byte{1})
				}
				shard := uint32(core.MetachainShardId)
				if name == "wrong_locus" {
					shard = 1
				}
				f.x = qualGovernedContext(t, f.c, shard, time)
				op := func() error { return f.g.authorize(f.x, id, proof) }
				if phase == "start" {
					op = func() error { return f.g.start(f.x, id, proof) }
				}
				if name == "earliest" || name == "last" {
					require.NoError(t, op())
				} else {
					f.denied(t, op)
					require.Zero(t, f.h.effects)
				}
			})
		}
	}
}

func TestQualDRWAGASStartRollbackAndContainment(t *testing.T) {
	for _, name := range []string{"apply", "nil_output", "bad_output", "action_key", "account_save", "rollback_failure", "action_mutation", "arm_overflow", "unselected_key_control"} {
		t.Run(name, func(t *testing.T) {
			f := qualGovernedActionNew(t)
			f.initialize(t)
			id := f.propose(t)
			f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 105)
			require.NoError(t, f.g.authorize(f.x, id, []byte("synthetic-full-authorize")))
			_, key, original, err := f.g.load(id)
			require.NoError(t, err)
			root := f.commit(t)
			fault := errors.New("selected GAS native stage failure")
			accounts := state.AccountsAdapter(f.s)
			switch name {
			case "apply":
				f.h.faults["apply"] = fault
			case "nil_output":
				f.h.nilOutput = true
			case "bad_output":
				f.h.badOutput = true
			case "action_key", "unselected_key_control":
				selected := key
				if name == "unselected_key_control" {
					selected = []byte("not-the-GAS-key")
				}
				accounts = &qualAdminKeyFault{&qualScopedAccountFault{f.s, selected, fault}}
			case "account_save":
				// The host owns native effect saves through the underlying store;
				// this wrapper selects the component's owning GAS SaveAccount.
				accounts = &qualAdminNthSave{AccountsAdapter: f.s, failAt: 1, fault: fault}
			case "rollback_failure":
				f.h.nilOutput = true
				f.s.revertErr = fault
			case "action_mutation":
				f.h.hooks["apply"] = func() { qualRecordPut(t, f.s, key, []byte{1}) }
			case "arm_overflow":
				f.h.arm, f.h.lifetime = true, HeaderMilliseconds(math.MaxUint64)
			}
			f.reopen(t, accounts)
			err = f.g.start(f.x, id, []byte("synthetic-current-start"))
			if name == "unselected_key_control" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			if name == "rollback_failure" {
				_, outputs, commitErr := f.o.Commit()
				require.Error(t, commitErr)
				require.Empty(t, outputs)
				f.s.revertErr = nil
				require.NoError(t, f.o.Recover())
			}
			require.Equal(t, original, qualRegistryValue(t, f.s, string(key)))
			qualAssertContainmentBalance(t, f.s, 100)
			after, err := f.s.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
		})
	}
}

func TestQualDRWAGASConcurrentStartAndRemoval(t *testing.T) {
	f := qualGovernedActionNew(t)
	f.initialize(t)
	id := f.propose(t)
	f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 105)
	require.NoError(t, f.g.authorize(f.x, id, []byte("synthetic-full-authorize")))
	// Synthetic proofs isolate T04 serialization, not lawful simultaneous
	// current-start and structurally stale-cleanup authority.
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, op := range []func() error{
		func() error { return f.g.start(f.x, id, []byte("synthetic-current-start")) },
		func() error { return f.g.cleanup(f.x, id, "STALE_BINDING", []byte("synthetic-no-irreversible-proof")) },
	} {
		wg.Add(1)
		go func(op func() error) { defer wg.Done(); results <- op() }(op)
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			require.True(t, errors.Is(err, ErrExecutionBusy) || errors.Is(err, errGovernedActionRecord))
		}
	}
	require.Equal(t, 1, successes)
	r, _, _, err := f.g.load(id)
	require.NoError(t, err)
	if r.status == "IN_PROGRESS" {
		f.count(t, 1)
		require.Equal(t, 1, f.h.effects)
	} else {
		require.Equal(t, "CANCELLED", r.status)
		f.count(t, 0)
		require.Zero(t, f.h.effects)
	}
}

func TestQualDRWAGASInitializationAndProposalSaveFaults(t *testing.T) {
	for _, phase := range []string{"initialize", "propose"} {
		for _, selected := range []string{"nonce", "action", "active", "account", "unselected_control"} {
			if phase == "initialize" && selected == "action" {
				continue // Initialization has no action-record writer.
			}
			t.Run(phase+"/"+selected, func(t *testing.T) {
				f := qualGovernedActionNew(t)
				if phase == "propose" {
					f.initialize(t)
				}
				f.commit(t)
				envelope, _, id := f.expected(100)
				f.h.envelope = envelope
				fault := errors.New("selected GAS persistence failure")
				var key []byte
				switch selected {
				case "nonce":
					key = f.counter()
				case "active":
					key = f.activeKey()
				case "action":
					key = append([]byte(governedActionPrefix+"action@"), qualRecordFrame([]byte("n"), id)...)
				case "unselected_control":
					key = []byte("not-a-GAS-key")
				}
				accounts := state.AccountsAdapter(&qualAdminKeyFault{&qualScopedAccountFault{f.s, key, fault}})
				if selected == "account" {
					accounts = &qualAdminNthSave{AccountsAdapter: f.s, failAt: 1, fault: fault}
				}
				f.reopen(t, accounts)
				op := func() error { return f.g.initialize(f.x, f.p.subject, f.p.class, f.p.token) }
				if phase == "propose" {
					op = func() error { _, err := f.g.propose(f.x, f.p); return err }
				}
				if selected == "unselected_control" {
					require.NoError(t, op())
				} else {
					var actual error
					f.denied(t, func() error { actual = op(); return actual })
					require.ErrorIs(t, actual, fault)
				}
			})
		}
	}
}

func TestQualDRWAGASUnstartedCleanupAndRollback(t *testing.T) {
	for _, gasState := range []string{"PROPOSED", "EXECUTABLE"} {
		for _, selected := range []string{"expire", "stale", "proof_denial", "action_key", "active_key", "account_save", "counter_mutation", "context_reset"} {
			t.Run(gasState+"/"+selected, func(t *testing.T) {
				f := qualGovernedActionNew(t)
				f.initialize(t)
				id := f.propose(t)
				f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 105)
				if gasState == "EXECUTABLE" {
					require.NoError(t, f.g.authorize(f.x, id, []byte("synthetic-full-authorize")))
				}
				_, actionKey, original, err := f.g.load(id)
				require.NoError(t, err)
				f.commit(t)
				f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 120)
				fault := errors.New("selected exact cleanup failure")
				accounts := state.AccountsAdapter(f.s)
				reason := "EXPIRED"
				switch selected {
				case "stale":
					reason = "STALE_BINDING"
					f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 105)
				case "proof_denial":
					f.h.faults["cleanup"] = fault
				case "action_key":
					accounts = &qualAdminKeyFault{&qualScopedAccountFault{f.s, actionKey, fault}}
				case "active_key":
					accounts = &qualAdminKeyFault{&qualScopedAccountFault{f.s, f.activeKey(), fault}}
				case "account_save":
					accounts = &qualAdminNthSave{AccountsAdapter: f.s, failAt: 1, fault: fault}
				case "counter_mutation":
					f.h.hooks["cleanup"] = func() { qualRecordPut(t, f.s, f.counter(), make([]byte, 8)) }
				case "context_reset":
					f.h.hooks["cleanup"] = f.c.Reset
				}
				f.reopen(t, accounts)
				op := func() error { return f.g.cleanup(f.x, id, reason, []byte("synthetic-no-irreversible-proof")) }
				if selected == "expire" || selected == "stale" {
					require.NoError(t, op())
					f.count(t, 0)
					r, _, _, err := f.g.load(id)
					require.NoError(t, err)
					want := "EXPIRED"
					if selected == "stale" {
						want = "CANCELLED"
					}
					require.Equal(t, want, r.status)
					require.Equal(t, reason, r.reason)
					require.Equal(t, uint64(1), binary.BigEndian.Uint64(qualRegistryValue(t, f.s, string(f.counter()))))
					root := f.commit(t)
					require.NoError(t, f.s.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
					f.reopen(t, f.s)
					r, _, _, err = f.g.load(id)
					require.NoError(t, err)
					require.Equal(t, want, r.status)
					f.count(t, 0)
					f.denied(t, func() error { return f.g.authorize(f.x, id, []byte("synthetic-full-authorize")) })
				} else {
					f.denied(t, op)
					require.Equal(t, original, qualRegistryValue(t, f.s, string(actionKey)))
					f.count(t, 1)
				}
			})
		}
	}
}

func TestQualDRWAGASImmutablePayloadAndIsolation(t *testing.T) {
	f := qualGovernedActionNew(t)
	f.initialize(t)
	id := f.propose(t)
	frozen := bytes.Clone(f.h.envelope)
	f.p.payload[0] ^= 1
	f.p.bindings[0] ^= 1
	f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 105)
	require.NoError(t, f.g.authorize(f.x, id, []byte("synthetic-full-authorize")))
	r, _, _, err := f.g.load(id)
	require.NoError(t, err)
	require.Equal(t, frozen, r.envelope, "later request aliases cannot replace immutable bytes")
	// A different token aggregate is independent; a root action has none but
	// must still pass the mandatory retained resource/funding host.
	firstAggregate := qualRegistryValue(t, f.s, string(f.activeKey()))
	for _, token := range [][]byte{[]byte("OTHER-abcdee"), nil} {
		f.p.subject, f.p.class, f.p.token, f.p.nonce = []byte("another-subject"), []byte("another-class"), token, 0
		if token == nil {
			f.p.class = []byte("root-class")
		}
		f.p.earliest, f.p.until = 110, 125
		f.initialize(t)
		f.propose(t)
	}
	firstKey := append([]byte(governedActionPrefix+"active@"), qualRecordFrame([]byte("n"), []byte("TOKEN-abcdef"))...)
	require.Equal(t, firstAggregate, qualRegistryValue(t, f.s, string(firstKey)))
	f.p.nonce = 1
	f.h.envelope, _, _ = f.expected(105)
	f.h.faults["proposal"] = errors.New("root resource denial remains mandatory")
	f.denied(t, func() error { _, err := f.g.propose(f.x, f.p); return err })
}

func TestQualDRWAGASMalformedRetainedState(t *testing.T) {
	for _, name := range []string{"missing_counter", "regressed_counter", "wrong_digest", "invalid_status", "wrong_category", "short_started", "unstarted_expiry", "wrong_reason", "noncanonical_record", "oversized_record", "missing_active", "wrong_active_root", "wrong_active_count", "duplicate_member", "active_category", "invalid_active_category"} {
		t.Run(name, func(t *testing.T) {
			f := qualGovernedActionNew(t)
			f.initialize(t)
			id := f.propose(t)
			envelope, digest, _ := f.expected(100)
			record := [][]byte{envelope, digest, []byte("PROPOSED"), {0}, make([]byte, 8), make([]byte, 8), nil}
			actionKey := append([]byte(governedActionPrefix+"action@"), qualRecordFrame([]byte("n"), id)...)
			entry := qualRecordFrame(id, []byte{0})
			entries := qualRecordFrame(entry)
			aggregate := [][]byte{binary.BigEndian.AppendUint64(nil, 1), binary.BigEndian.AppendUint64(nil, 1),
				blake2b.NewBlake2b().Compute(string(entries)), entries}
			switch name {
			case "missing_counter":
				qualRecordPut(t, f.s, f.counter(), nil)
			case "regressed_counter":
				qualRecordPut(t, f.s, f.counter(), make([]byte, 8))
			case "missing_active":
				qualRecordPut(t, f.s, f.activeKey(), nil)
			case "wrong_active_root":
				aggregate[2] = bytes.Repeat([]byte{0}, 32)
				qualRecordPut(t, f.s, f.activeKey(), qualRecordFrame(aggregate...))
			case "wrong_active_count":
				aggregate[0] = binary.BigEndian.AppendUint64(nil, 2)
				qualRecordPut(t, f.s, f.activeKey(), qualRecordFrame(aggregate...))
			case "duplicate_member":
				aggregate[0], aggregate[1] = binary.BigEndian.AppendUint64(nil, 2), binary.BigEndian.AppendUint64(nil, 2)
				aggregate[3] = qualRecordFrame(entry, entry)
				aggregate[2] = blake2b.NewBlake2b().Compute(string(aggregate[3]))
				qualRecordPut(t, f.s, f.activeKey(), qualRecordFrame(aggregate...))
			case "active_category", "invalid_active_category":
				category := byte(1)
				if name == "invalid_active_category" {
					category = 2
				}
				aggregate[1] = make([]byte, 8)
				aggregate[3] = qualRecordFrame(qualRecordFrame(id, []byte{category}))
				aggregate[2] = blake2b.NewBlake2b().Compute(string(aggregate[3]))
				qualRecordPut(t, f.s, f.activeKey(), qualRecordFrame(aggregate...))
			case "oversized_record":
				qualRecordPut(t, f.s, actionKey, bytes.Repeat([]byte{0}, 4097))
			default:
				switch name {
				case "wrong_digest":
					record[1] = bytes.Repeat([]byte{0}, 32)
				case "invalid_status":
					record[2] = []byte("OPEN")
				case "wrong_category":
					record[3] = []byte{1}
				case "short_started":
					record[4] = []byte{0}
				case "unstarted_expiry":
					record[5] = binary.BigEndian.AppendUint64(nil, 112)
				case "wrong_reason":
					record[6] = []byte("TIMEOUT")
				}
				encoded := qualRecordFrame(record...)
				if name == "noncanonical_record" {
					encoded = append(encoded, 0x18, 0x01)
				}
				qualRecordPut(t, f.s, actionKey, encoded)
			}
			f.commit(t)
			f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 105)
			f.denied(t, func() error { return f.g.authorize(f.x, id, []byte("synthetic-full-authorize")) })
			require.Zero(t, f.h.effects)
		})
	}
}

func TestQualDRWAGASConstructorAndInitializationGuards(t *testing.T) {
	for _, name := range []string{"nil_host", "foreign_store", "partition_mismatch", "partition_overflow", "empty_domain", "initialize_denied", "initialize_inactive"} {
		t.Run(name, func(t *testing.T) {
			f := qualGovernedActionNew(t)
			if name == "initialize_denied" || name == "initialize_inactive" {
				if name == "initialize_denied" {
					f.h.faults["initialize"] = errors.New("synthetic activation provenance denial")
				} else {
					f.c.Reset()
				}
				f.denied(t, func() error { return f.g.initialize(f.x, f.p.subject, f.p.class, f.p.token) })
				return
			}
			accounts := state.AccountsAdapter(f.s)
			var host governedActionHost = f.h
			domain, total, ordinary, protected := []byte("n"), uint64(4), uint64(2), uint64(2)
			switch name {
			case "nil_host":
				host = (*qualGovernedActionHost)(nil)
			case "foreign_store":
				accounts = qualRegistrationStore(t, 0)
			case "partition_mismatch":
				protected = 3
			case "partition_overflow":
				ordinary, protected = math.MaxUint64, 1
			case "empty_domain":
				domain = nil
			}
			_, err := newGovernedActionRecords(accounts, f.o, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, domain,
				total, ordinary, protected, host, qualClockSource(f.c, accounts))
			require.Error(t, err)
		})
	}
}
