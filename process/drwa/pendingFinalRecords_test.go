package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/batch"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// The host is an explicit storage-unit-test dependency, not canonical proof.
// Witness authentication itself belongs to the native committed-input adapter.
type pendingFinalTestHost struct {
	expected map[string]bool
	check    func(string, []byte) error
	observed int
}

func (h *pendingFinalTestHost) IsInterfaceNil() bool { return h == nil }
func (h *pendingFinalTestHost) Admit(c []byte) error {
	if !h.expected[string(c)] {
		return errPendingFinal
	}
	return nil
}
func (h *pendingFinalTestHost) Initialize([]byte) (*vmcommon.VMOutput, error) {
	return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
}
func (h *pendingFinalTestHost) Canonical(c, witness []byte) error {
	if !h.expected[string(c)] || !bytes.Equal(witness, []byte("unit-test witness")) {
		return errPendingFinal
	}
	if h.check != nil {
		return h.check("canonical", c)
	}
	return nil
}
func (h *pendingFinalTestHost) Observe(c []byte) (*vmcommon.VMOutput, error) {
	if h.check != nil {
		if err := h.check("observe", c); err != nil {
			return nil, err
		}
	}
	h.observed++
	return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, Logs: []*vmcommon.LogEntry{{Identifier: bytes.Clone(c)}}}, nil
}

type pendingFinalTestStore struct {
	*qualNativeStore
	writes, writeFault, saveFault, saves int
	panicWrite, panicCommit, panicSave   bool
}

type pendingFinalTestAccount struct {
	state.UserAccountHandler
	store *pendingFinalTestStore
}

func (a *pendingFinalTestAccount) SaveKeyValue(key, value []byte) error {
	if err := a.UserAccountHandler.SaveKeyValue(key, value); err != nil {
		return err
	}
	a.store.writes++
	if a.store.writes == a.store.writeFault {
		if a.store.panicWrite {
			panic("interrupted P13 key persistence")
		}
		return errors.New("P13 key persistence failed")
	}
	return nil
}
func (s *pendingFinalTestStore) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	a, err := s.qualNativeStore.GetExistingAccount(address)
	if err != nil {
		return nil, err
	}
	return &pendingFinalTestAccount{UserAccountHandler: a.(state.UserAccountHandler), store: s}, nil
}
func (s *pendingFinalTestStore) SaveAccount(account vmcommon.AccountHandler) error {
	if a, ok := account.(*pendingFinalTestAccount); ok {
		account = a.UserAccountHandler
	}
	if err := s.qualNativeStore.SaveAccount(account); err != nil {
		return err
	}
	s.saves++
	if s.saves == s.saveFault {
		if s.panicSave {
			panic("interrupted P13 account persistence")
		}
		return errors.New("P13 account persistence failed")
	}
	return nil
}
func (s *pendingFinalTestStore) Commit() ([]byte, error) {
	root, err := s.qualNativeStore.Commit()
	if s.panicCommit {
		panic("interrupted native commit")
	}
	return root, err
}

type pendingFinalTestFixture struct {
	s           *pendingFinalTestStore
	r           *pendingFinalRecords
	owner       *RollbackContainment
	host        *pendingFinalTestHost
	items       []pendingFinalPromotion
	commitments [][]byte
	encoded     [][]byte
	keys        [][]byte
	budget      int
}

func newPendingFinalTestFixture(t *testing.T, count int, origins ...[]byte) *pendingFinalTestFixture {
	t.Helper()
	s := &pendingFinalTestStore{qualNativeStore: qualContainmentStore(t)}
	a, err := s.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	// Native RetrieveValue reports ErrNilTrie for a committed account that
	// never had storage. Preserve a real unrelated key when creating the fixture.
	require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue([]byte("fixture/preserved"), []byte("unchanged")))
	require.NoError(t, s.SaveAccount(a))
	_, err = s.Commit()
	require.NoError(t, err)
	f := &pendingFinalTestFixture{s: s, host: &pendingFinalTestHost{expected: make(map[string]bool)}}
	f.reopen(t)
	mar := &marshal.GogoProtoMarshalizer{}
	frame := func(fields ...[]byte) []byte {
		b, e := mar.Marshal(batch.New(fields...))
		require.NoError(t, e)
		return b
	}
	for i := 0; i < count; i++ {
		c := pendingFinalCandidate{key: []byte(fmt.Sprintf("record-%d", i)), version: 0, body: []byte(fmt.Sprintf("body-%d", i)), origin: []byte("one executed result")}
		if i < len(origins) {
			c.origin = origins[i]
		}
		encoded := frame(c.key, binary.BigEndian.AppendUint64(nil, 0), nil, c.body, c.origin)
		f.host.expected[string(encoded)] = true
		f.encoded = append(f.encoded, encoded)
		f.items = append(f.items, pendingFinalPromotion{candidate: c, evidence: []byte("unit-test witness")})
		f.commitments = append(f.commitments, blake2b.NewBlake2b().Compute(string(encoded)))
		f.budget += len(encoded) + len(f.items[i].evidence)
		f.keys = append(f.keys, append([]byte(pendingFinalPrefix+"pending@"), frame(c.key)...), append([]byte(pendingFinalPrefix+"item@"), frame(c.origin, c.key)...), append([]byte(pendingFinalPrefix+"final@"), frame(c.key)...))
		require.NoError(t, f.r.stage(c))
	}
	for _, item := range f.items {
		f.keys = append(f.keys, append([]byte(pendingFinalPrefix+"origin@"), frame(item.candidate.origin)...))
	}
	_, _, err = f.owner.Commit()
	require.NoError(t, err)
	f.reopen(t)
	s.writes, s.saves = 0, 0
	return f
}
func (f *pendingFinalTestFixture) reopen(t *testing.T) {
	t.Helper()
	var err error
	f.owner, err = NewRollbackContainment(f.s)
	require.NoError(t, err)
	f.r, err = newPendingFinalRecords(f.s, f.owner, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, f.host)
	require.NoError(t, err)
}
func (f *pendingFinalTestFixture) snapshot(t *testing.T) [][]byte {
	t.Helper()
	root, err := f.s.RootHash()
	require.NoError(t, err)
	values := [][]byte{bytes.Clone(root)}
	a, err := f.s.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	for _, k := range f.keys {
		v, _, e := a.(state.UserAccountHandler).RetrieveValue(k)
		require.NoError(t, e)
		values = append(values, bytes.Clone(v))
	}
	return values
}
func (f *pendingFinalTestFixture) promote() error {
	return f.r.promoteResult(f.items, f.commitments, len(f.items), f.budget)
}

func TestPendingFinalRecords_PromoteResult(t *testing.T) {
	t.Run("bounded result should promote all items and preserve native observations once", func(t *testing.T) {
		f := newPendingFinalTestFixture(t, 2)
		require.NoError(t, f.promote())
		for i, item := range f.items {
			v, hash, err := f.r.final(item.candidate.key)
			require.NoError(t, err)
			require.Equal(t, f.encoded[i], v)
			require.Equal(t, f.commitments[i], hash)
		}
		after := f.snapshot(t)
		require.NoError(t, f.promote())
		require.Equal(t, after, f.snapshot(t))
		require.Equal(t, 2, f.host.observed)
		roots, outputs, err := f.owner.Commit()
		require.NoError(t, err)
		require.Len(t, outputs, 2)
		for i, output := range outputs {
			require.Equal(t, f.encoded[i], output.Logs[0].Identifier)
		}
		require.NoError(t, f.s.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
		f.reopen(t)
		require.NoError(t, f.promote())
		require.Equal(t, after, f.snapshot(t))
		require.Empty(t, f.owner.outputs)
	})
	for _, name := range []string{"missing item", "excess item", "wrong commitment", "wrong order", "duplicate key", "foreign origin", "missing witness", "nonfinal witness", "conflicting witness", "wrong origin witness", "over bytes", "encoded over bytes", "zero count bound", "zero byte bound"} {
		t.Run(name+" should leave P13 bytes identical", func(t *testing.T) {
			f := newPendingFinalTestFixture(t, 2)
			if name == "foreign origin" {
				f = newPendingFinalTestFixture(t, 2, []byte("first result"), []byte("other result"))
			}
			before := f.snapshot(t)
			items := append([]pendingFinalPromotion(nil), f.items...)
			commitments := append([][]byte(nil), f.commitments...)
			limit, budget := 2, f.budget
			switch name {
			case "missing item":
				items = items[:1]
			case "excess item":
				limit = 1
			case "wrong commitment":
				commitments[1] = []byte("foreign")
			case "wrong order":
				items[0], items[1] = items[1], items[0]
			case "duplicate key":
				items[1] = items[0]
				commitments[1] = commitments[0]
			case "foreign origin":
				// Both candidates are staged and individually admitted. Only
				// the one-result import rule rejects their combined use.
			case "missing witness":
				items[1].evidence = nil
			case "nonfinal witness", "conflicting witness", "wrong origin witness":
				items[1].evidence = []byte(name)
			case "over bytes":
				budget--
			case "encoded over bytes":
				budget = 1
			case "zero count bound":
				limit = 0
			case "zero byte bound":
				budget = 0
			}
			require.Error(t, f.r.promoteResult(items, commitments, limit, budget))
			require.Equal(t, before, f.snapshot(t))
			require.Empty(t, f.owner.outputs)
			// A rejected colliding/foreign item must not consume a local slot.
			if name == "foreign origin" {
				for i, item := range f.items {
					require.NoError(t, f.r.promoteResult([]pendingFinalPromotion{item}, [][]byte{f.commitments[i]}, 1, len(f.encoded[i])+len(item.evidence)))
				}
			} else {
				require.NoError(t, f.promote())
			}
		})
	}
	for _, step := range []string{"canonical", "observe"} {
		for _, target := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s callback changing item %d should roll back every item", step, target), func(t *testing.T) {
				f := newPendingFinalTestFixture(t, 2)
				before := f.snapshot(t)
				f.host.check = func(stage string, c []byte) error {
					if stage == step && bytes.Equal(c, f.encoded[0]) {
						a, err := f.s.GetExistingAccount(core.SystemAccountAddress)
						require.NoError(t, err)
						require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(f.keys[target*3+2], f.encoded[target]))
						require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(f.keys[target*3], nil))
						require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(f.keys[target*3+1], nil))
						// Forge the COMPLETE future promotion, including its
						// shared origin manifest, to test the callback guard
						// rather than an incomplete state rejected later.
						manifest, e := f.r.codec.frame(f.commitments[1-target])
						require.NoError(t, e)
						originKey, e := f.r.key("origin", f.items[target].candidate.origin)
						require.NoError(t, e)
						require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(originKey, manifest))
						require.NoError(t, f.s.SaveAccount(a))
					}
					return nil
				}
				require.Error(t, f.promote())
				require.Equal(t, before, f.snapshot(t))
				require.Empty(t, f.owner.outputs)
			})
		}
	}
}

func TestPendingFinalRecords_Persistence(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		for step := 1; step <= 8; step++ {
			t.Run(fmt.Sprintf("key write %d interrupted %t should restore exact pending state", step, interrupted), func(t *testing.T) {
				f := newPendingFinalTestFixture(t, 2)
				before := f.snapshot(t)
				f.s.writeFault, f.s.panicWrite = step, interrupted
				if interrupted {
					require.Panics(t, func() { _ = f.promote() })
					require.ErrorIs(t, f.promote(), ErrExecutionInterrupted)
					require.NoError(t, f.owner.Recover())
				} else {
					require.Error(t, f.promote())
				}
				require.Equal(t, before, f.snapshot(t))
				require.Empty(t, f.owner.outputs)
				f.s.writeFault = 0
				f.coldRestartWithPruning(t, before)
				require.NoError(t, f.promote())
			})
		}
	}
	for _, interrupted := range []bool{false, true} {
		for step := 1; step <= 2; step++ {
			t.Run(fmt.Sprintf("account save %d interrupted %t should roll back the promoted prefix", step, interrupted), func(t *testing.T) {
				f := newPendingFinalTestFixture(t, 2)
				before := f.snapshot(t)
				f.s.saveFault, f.s.panicSave = step, interrupted
				if interrupted {
					require.Panics(t, func() { _ = f.promote() })
					require.ErrorIs(t, f.promote(), ErrExecutionInterrupted)
					require.NoError(t, f.owner.Recover())
				} else {
					require.Error(t, f.promote())
				}
				require.Equal(t, before, f.snapshot(t))
				require.Empty(t, f.owner.outputs)
				f.s.saveFault, f.s.panicSave = 0, false
				f.coldRestartWithPruning(t, before)
				require.NoError(t, f.promote())
			})
		}
	}

	t.Run("interrupted native commit should forbid retry and require retained root recovery", func(t *testing.T) {
		f := newPendingFinalTestFixture(t, 2)
		before := f.snapshot(t)
		require.NoError(t, f.promote())
		f.s.panicCommit = true
		require.Panics(t, func() { _, _, _ = f.owner.Commit() })
		require.Empty(t, f.owner.outputs)
		require.ErrorIs(t, f.promote(), ErrExecutionInterrupted)
		_, outputs, err := f.owner.Commit()
		require.ErrorIs(t, err, ErrExecutionInterrupted)
		require.Nil(t, outputs)
		f.s.panicCommit = false
		require.NoError(t, f.owner.Recover())
		require.Equal(t, before, f.snapshot(t))
		f.coldRestartWithPruning(t, before)
		require.NoError(t, f.promote())
	})
	t.Run("pruned retained root should keep recovery unavailable until restored", func(t *testing.T) {
		f := newPendingFinalTestFixture(t, 2)
		before := f.snapshot(t)
		node, err := f.s.backing.Get(before[0])
		require.NoError(t, err)
		require.NoError(t, f.promote())
		f.s.panicCommit = true
		require.Panics(t, func() { _, _, _ = f.owner.Commit() })
		require.NoError(t, f.s.backing.Remove(before[0]))
		require.Error(t, f.owner.Recover())
		require.ErrorIs(t, f.promote(), ErrExecutionInterrupted)
		require.Empty(t, f.owner.outputs)
		require.NoError(t, f.s.backing.Put(before[0], node))
		require.NoError(t, f.owner.Recover())
		require.Equal(t, before, f.snapshot(t))
	})
}

func TestRollbackContainment_Abort(t *testing.T) {
	t.Run("consuming block replacement should revert promotion and dependent state together", func(t *testing.T) {
		f := newPendingFinalTestFixture(t, 2)
		before := f.snapshot(t)
		require.NoError(t, f.promote())
		require.NoError(t, f.owner.Execute(func() (*vmcommon.VMOutput, error) {
			a, err := f.s.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue([]byte("dependent P13 state"), []byte("discard")))
			return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, f.s.SaveAccount(a)
		}))
		require.NoError(t, f.owner.Abort())
		require.Equal(t, before, f.snapshot(t))
		a, err := f.s.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, err)
		v, _, err := a.(state.UserAccountHandler).RetrieveValue([]byte("dependent P13 state"))
		require.NoError(t, err)
		require.Empty(t, v)
		require.Empty(t, f.owner.outputs)
		require.ErrorIs(t, f.promote(), ErrExecutionClosed)
		_, output, err := f.owner.Commit()
		require.ErrorIs(t, err, ErrExecutionClosed)
		require.Empty(t, output)
		f.reopen(t)
		require.NoError(t, f.promote())
	})
	t.Run("failed reconstruction should retain containment until native roots can be restored", func(t *testing.T) {
		f := newPendingFinalTestFixture(t, 1)
		before := f.snapshot(t)
		require.NoError(t, f.promote())
		failure := errors.New("native root unavailable")
		f.s.recreateErr = failure
		require.ErrorIs(t, f.owner.Abort(), failure)
		require.Empty(t, f.owner.outputs)
		require.ErrorIs(t, f.owner.Abort(), failure)
		require.ErrorIs(t, f.promote(), failure)
		f.s.recreateErr = nil
		require.NoError(t, f.owner.Recover())
		require.Equal(t, before, f.snapshot(t))
		require.ErrorIs(t, f.owner.Abort(), ErrExecutionClosed)
	})
	t.Run("busy or committed owner should refuse abort", func(t *testing.T) {
		f := newPendingFinalTestFixture(t, 1)
		require.NoError(t, f.owner.Execute(func() (*vmcommon.VMOutput, error) {
			require.ErrorIs(t, f.owner.Abort(), ErrExecutionBusy)
			return nil, nil
		}))
		_, _, err := f.owner.Commit()
		require.NoError(t, err)
		require.ErrorIs(t, f.owner.Abort(), ErrExecutionClosed)
	})
}

type pendingFinalTestMarshalizer struct {
	marshal.Marshalizer
	encodeErr, decodeErr error
	calls, faultAt       int
}

func (m *pendingFinalTestMarshalizer) Marshal(value interface{}) ([]byte, error) {
	m.calls++
	if m.calls == m.faultAt {
		return nil, errors.New("codec boundary unavailable")
	}
	if m.encodeErr != nil {
		return nil, m.encodeErr
	}
	return m.Marshalizer.Marshal(value)
}

func (m *pendingFinalTestMarshalizer) Unmarshal(value interface{}, encoded []byte) error {
	m.calls++
	if m.calls == m.faultAt {
		return errors.New("codec boundary unavailable")
	}
	if m.decodeErr != nil {
		return m.decodeErr
	}
	return m.Marshalizer.Unmarshal(value, encoded)
}

func TestPendingFinalRecords_DependencyFailures(t *testing.T) {
	t.Run("malformed candidate should reject before any promotion", func(t *testing.T) {
		f := newPendingFinalTestFixture(t, 1)
		before := f.snapshot(t)
		c := f.items[0].candidate
		c.key = nil
		require.Error(t, f.r.promote(c, f.items[0].evidence))
		require.Equal(t, before, f.snapshot(t))
		require.Zero(t, f.host.observed)
	})
	t.Run("native decoder failure should preserve the original pending obligation", func(t *testing.T) {
		f := newPendingFinalTestFixture(t, 1)
		before := f.snapshot(t)
		failure := errors.New("native decoder unavailable")
		f.r.codec.marshaller = &pendingFinalTestMarshalizer{Marshalizer: &marshal.GogoProtoMarshalizer{}, decodeErr: failure}
		require.ErrorIs(t, f.promote(), failure)
		require.Equal(t, before, f.snapshot(t))
		require.Empty(t, f.owner.outputs)
	})
	t.Run("native key encoding failure should prevent verifier execution", func(t *testing.T) {
		f := newPendingFinalTestFixture(t, 1)
		before := f.snapshot(t)
		failure := errors.New("native encoder unavailable")
		f.r.codec.marshaller = &pendingFinalTestMarshalizer{Marshalizer: &marshal.GogoProtoMarshalizer{}, encodeErr: failure}
		called := false
		require.ErrorIs(t, f.r.verifyState(f.items[0].candidate, func() error { called = true; return nil }), failure)
		require.False(t, called)
		require.Equal(t, before, f.snapshot(t))
	})
}

// Discard all AccountsDB/trie caches. A missing retained root must reject cold
// reconstruction; restoring its exact native node permits only the old state.
// This is memory-backed native restart/pruning evidence, not a physical crash.
func (f *pendingFinalTestFixture) coldRestartWithPruning(t *testing.T, before [][]byte) {
	t.Helper()
	root := before[0]
	node, err := f.s.backing.Get(root)
	require.NoError(t, err)
	require.NoError(t, f.s.backing.Remove(root))
	fresh := func() state.AccountsAdapter {
		args, _ := qualContainmentArgs(t, f.s.backing)
		db, e := state.NewAccountsDB(args)
		require.NoError(t, e)
		return db
	}
	missing := fresh()
	require.Error(t, missing.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	require.NoError(t, f.s.backing.Put(root, node))
	restored := fresh()
	require.NoError(t, restored.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	f.s.AccountsAdapter = restored
	f.reopen(t)
	require.Equal(t, before, f.snapshot(t))
	require.Empty(t, f.owner.outputs)
}

func TestPendingFinalRecords_StagePersistence(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		for step := 1; step <= 4; step++ {
			t.Run(fmt.Sprintf("stage step %d interrupted %t should recover identical state", step, interrupted), func(t *testing.T) {
				f := newPendingFinalTestFixture(t, 0)
				c := pendingFinalCandidate{key: []byte("new record"), body: []byte("new body"), origin: []byte("new origin")}
				encoded, err := f.r.encode(c)
				require.NoError(t, err)
				f.host.expected[string(encoded)] = true
				f.items = []pendingFinalPromotion{{candidate: c, evidence: []byte("unit-test witness")}}
				for _, kind := range []string{"pending", "final"} {
					k, e := f.r.key(kind, c.key)
					require.NoError(t, e)
					f.keys = append(f.keys, k)
				}
				k, err := f.r.key("item", c.origin, c.key)
				require.NoError(t, err)
				f.keys = append(f.keys, k)
				k, err = f.r.key("origin", c.origin)
				require.NoError(t, err)
				f.keys = append(f.keys, k)
				before := f.snapshot(t)
				if step == 4 {
					f.s.saveFault = 1
					f.s.panicSave = interrupted
				} else {
					f.s.writeFault, f.s.panicWrite = step, interrupted
				}
				if interrupted {
					require.Panics(t, func() { _ = f.r.stage(c) })
					require.ErrorIs(t, f.r.stage(c), ErrExecutionInterrupted)
					require.NoError(t, f.owner.Recover())
				} else {
					require.Error(t, f.r.stage(c))
				}
				require.Equal(t, before, f.snapshot(t))
				require.Empty(t, f.owner.outputs)
				f.s.writeFault, f.s.saveFault = 0, 0
				f.s.panicSave = false
				f.coldRestartWithPruning(t, before)
				require.NoError(t, f.r.stage(c))
				roots, outputs, err := f.owner.Commit()
				require.NoError(t, err)
				require.Len(t, outputs, 1)
				after := f.snapshot(t)
				require.Equal(t, roots[0], after[0])
				f.coldRestartWithPruning(t, after)
				require.NoError(t, f.r.stage(c))
				require.Equal(t, []*vmcommon.VMOutput{nil}, f.owner.outputs, "native state-only output slot carries no observation")
				require.Equal(t, after, f.snapshot(t))
			})
		}
	}
}

func TestPendingFinalRecords_OriginManifest(t *testing.T) {
	f := newPendingFinalTestFixture(t, 2)
	before := f.snapshot(t)
	mar := &marshal.GogoProtoMarshalizer{}
	for _, name := range []string{"missing", "over bytes", "malformed", "empty", "wrong digest size", "duplicate", "unknown protobuf field"} {
		t.Run(name+" should reject without state mutation", func(t *testing.T) {
			raw, err := mar.Marshal(batch.New(f.commitments...))
			require.NoError(t, err)
			switch name {
			case "missing":
				raw = nil
			case "over bytes":
				raw = bytes.Repeat([]byte{0}, 4097)
			case "malformed":
				raw = []byte{0xff}
			case "empty":
				raw, err = mar.Marshal(batch.New())
			case "wrong digest size":
				raw, err = mar.Marshal(batch.New([]byte("short")))
			case "duplicate":
				raw, err = mar.Marshal(batch.New(f.commitments[0], f.commitments[0]))
			case "unknown protobuf field":
				raw = append(raw, 0xa0, 0x06, 0x01)
			}
			require.NoError(t, err)
			_, err = f.r.decodeOriginItems(raw)
			require.Error(t, err)
			require.Equal(t, before, f.snapshot(t))
		})
	}
}

func FuzzPendingFinalRecords_DecodeOriginItems(f *testing.F) {
	f.Add([]byte{0xff})
	f.Add([]byte{})
	mar := &marshal.GogoProtoMarshalizer{}
	valid, err := mar.Marshal(batch.New(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4097 {
			return
		}
		x := newPendingFinalTestFixture(t, 1)
		before := x.snapshot(t)
		items, err := x.r.decodeOriginItems(raw)
		if err == nil {
			require.NotEmpty(t, items)
			seen := make(map[string]bool)
			for _, item := range items {
				require.Len(t, item, 32)
				require.False(t, seen[string(item)])
				seen[string(item)] = true
			}
			encoded, e := mar.Marshal(batch.New(items...))
			require.NoError(t, e)
			require.Equal(t, raw, encoded)
		}
		require.Equal(t, before, x.snapshot(t))
	})
}

func TestPendingFinalRecords_OrdinaryPath(t *testing.T) {
	t.Run("native operation without a P13 import should preserve native state and output", func(t *testing.T) {
		direct := newPendingFinalTestFixture(t, 0)
		wrapped := newPendingFinalTestFixture(t, 0)
		require.NoError(t, qualContainmentBalance(direct.s.qualNativeStore, 120))
		directRoot, err := direct.s.Commit()
		require.NoError(t, err)
		observation := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, ReturnData: [][]byte{[]byte("native result")}}
		require.NoError(t, wrapped.owner.Execute(func() (*vmcommon.VMOutput, error) {
			return observation, qualContainmentBalance(wrapped.s.qualNativeStore, 120)
		}))
		roots, outputs, err := wrapped.owner.Commit()
		require.NoError(t, err)
		require.Equal(t, directRoot, roots[0])
		require.Equal(t, []*vmcommon.VMOutput{observation}, outputs)
		qualAssertContainmentBalance(t, direct.s.qualNativeStore, 120)
		qualAssertContainmentBalance(t, wrapped.s.qualNativeStore, 120)
	})
}

func TestPendingFinalRecords_CodecBoundaries(t *testing.T) {
	for _, promote := range []bool{false, true} {
		fixture := func(t *testing.T) (*pendingFinalTestFixture, func() error, *pendingFinalTestMarshalizer) {
			f := newPendingFinalTestFixture(t, 2)
			operation := f.promote
			if !promote {
				f = newPendingFinalTestFixture(t, 0)
				c := pendingFinalCandidate{key: []byte("new record"), body: []byte("body"), origin: []byte("origin")}
				raw, err := f.r.encode(c)
				require.NoError(t, err)
				f.host.expected[string(raw)] = true
				for _, kind := range []string{"pending", "final"} {
					k, e := f.r.key(kind, c.key)
					require.NoError(t, e)
					f.keys = append(f.keys, k)
				}
				k, err := f.r.key("item", c.origin, c.key)
				require.NoError(t, err)
				f.keys = append(f.keys, k)
				k, err = f.r.key("origin", c.origin)
				require.NoError(t, err)
				f.keys = append(f.keys, k)
				operation = func() error { return f.r.stage(c) }
			}
			mar := &pendingFinalTestMarshalizer{Marshalizer: f.r.codec.marshaller}
			f.r.codec.marshaller = mar
			return f, operation, mar
		}
		_, healthy, trace := fixture(t)
		require.NoError(t, healthy())
		boundaries := trace.calls
		for step := 1; step <= boundaries; step++ {
			t.Run(fmt.Sprintf("promote %t native codec boundary %d should retain exact state", promote, step), func(t *testing.T) {
				f, operation, mar := fixture(t)
				before := f.snapshot(t)
				mar.faultAt = step
				require.Error(t, operation())
				mar.faultAt = 0
				require.Equal(t, before, f.snapshot(t))
				require.Empty(t, f.owner.outputs)
			})
		}
	}
}

func TestPendingFinalRecords_ReadBounds(t *testing.T) {
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
