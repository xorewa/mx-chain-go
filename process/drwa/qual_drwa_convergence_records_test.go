package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// L46 DEVELOPMENT. Actual AccountsDB, Batch-independent fixture bytes, native
// journal/save/commit/recreation and T04 run. Canonical G3/current GAS/dependency/
// configured-set/funding verification is a SYNTHETIC mandatory-host contract.
// No real ACK producer, transport, finality, disk crash or GAS consumer is proven.
type qualConvergenceHost struct {
	t                                    *testing.T
	store                                *qualNativeStore
	binding, key                         []byte
	acks                                 map[string]uint32
	faults                               map[string]error
	hooks                                map[string]func()
	verifyCalls, admissionCalls          int
	ackCalls, completeCalls, parentCalls int
	wrongProducer                        bool
	nilOutput, deniedOutput              bool
}

const qualConvergenceParent = "fixture/T29/parent-phase-commitment"

func (h *qualConvergenceHost) IsInterfaceNil() bool { return h == nil }
func (h *qualConvergenceHost) check(stage string, binding []byte) error {
	if hook := h.hooks[stage]; hook != nil {
		hook()
	}
	if !bytes.Equal(binding, h.binding) {
		return errConvergence
	}
	return h.faults[stage]
}
func (h *qualConvergenceHost) VerifyTransition(binding []byte) error {
	h.verifyCalls++
	return h.check("transition", binding)
}
func (h *qualConvergenceHost) Admission(binding []byte, retained uint64) error {
	h.admissionCalls++
	require.Greater(h.t, retained, uint64(len(h.key)+len(binding)))
	return h.check("admission", binding)
}
func (h *qualConvergenceHost) VerifyAck(binding, ack, evidence []byte) (uint32, error) {
	h.ackCalls++
	if err := h.check("ack", binding); err != nil {
		return 0, err
	}
	producer, ok := h.acks[string(ack)]
	if !ok || !bytes.Equal(evidence, []byte("synthetic-S-R-H-M-B-proof")) {
		return 0, errConvergence
	}
	if h.wrongProducer {
		producer = (producer + 1) % 3
	}
	return producer, nil
}
func (h *qualConvergenceHost) Complete(binding, commitment []byte) (*vmcommon.VMOutput, error) {
	h.completeCalls++
	if err := h.check("complete", binding); err != nil {
		return nil, err
	}
	qualRecordPut(h.t, h.store, []byte(qualConvergenceParent), qualRecordFrame(binding, commitment))
	if hook := h.hooks["after_parent"]; hook != nil {
		hook()
	}
	if h.nilOutput {
		return nil, nil
	}
	output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 27,
		ReturnData: [][]byte{[]byte("parent-phase-applied")}, Logs: []*vmcommon.LogEntry{{Identifier: []byte("parent-log")}}}
	if h.deniedOutput {
		output.ReturnCode = vmcommon.UserError
	}
	return output, nil
}
func (h *qualConvergenceHost) VerifyParent(binding, commitment []byte) error {
	h.parentCalls++
	if err := h.check("parent", binding); err != nil {
		return err
	}
	if !bytes.Equal(qualRegistryValue(h.t, h.store, qualConvergenceParent), qualRecordFrame(binding, commitment)) {
		return errConvergence
	}
	return nil
}

type qualConvergenceFixture struct {
	store        *qualNativeStore
	owner        *RollbackContainment
	records      *convergenceRecords
	host         *qualConvergenceHost
	tr           convergenceTransition
	key, binding []byte
	local        map[uint32][]byte
}

func qualConvergenceNew(t *testing.T, count int) *qualConvergenceFixture {
	t.Helper()
	f := &qualConvergenceFixture{store: qualRegistrationStore(t, 0), local: make(map[uint32][]byte)}
	f.tr = convergenceTransition{action: bytes.Repeat([]byte{1}, 32), digest: bytes.Repeat([]byte{2}, 32),
		token: []byte("TOKEN-abcdef"), version: 7, target: bytes.Repeat([]byte{3}, 32), dependencies: bytes.Repeat([]byte{4}, 32)}
	ids := make([][]byte, count)
	for i := range ids {
		f.tr.shards = append(f.tr.shards, uint32(i))
		ids[i] = []byte{0, 0, 0, byte(i)}
		f.local[uint32(i)] = bytes.Repeat([]byte{byte(i + 10)}, 32)
	}
	set := qualRecordFrame(ids...)
	f.tr.requiredSet = blake2b.NewBlake2b().Compute(string(set))
	f.binding = qualRecordFrame([]byte("CEB_CURRENTIZATION"), f.tr.action, f.tr.digest, []byte("CURRENT_ACK"), f.tr.token,
		[]byte{0, 0, 0, 0, 0, 0, 0, 7}, f.tr.target, f.tr.dependencies, f.tr.requiredSet, set)
	f.key = append([]byte(convergencePrefix), qualRecordFrame([]byte("CEB_CURRENTIZATION"), f.tr.action, []byte("CURRENT_ACK"))...)
	f.host = &qualConvergenceHost{t: t, store: f.store, binding: f.binding, key: f.key,
		acks: make(map[string]uint32), faults: make(map[string]error), hooks: make(map[string]func())}
	for _, shard := range f.tr.shards {
		f.host.acks[string(qualRecordFrame(f.binding, binary.BigEndian.AppendUint32(nil, shard), f.local[shard]))] = shard
	}
	f.reopen(t, f.store)
	return f
}
func (f *qualConvergenceFixture) reopen(t *testing.T, accounts state.AccountsAdapter) {
	t.Helper()
	var err error
	f.owner, err = NewRollbackContainment(accounts)
	require.NoError(t, err)
	f.records, err = newConvergenceRecords(accounts, f.owner, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, 16, f.host)
	require.NoError(t, err)
}
func (f *qualConvergenceFixture) ack(shard uint32) error {
	return f.records.acknowledge(f.tr, shard, f.local[shard], []byte("synthetic-S-R-H-M-B-proof"))
}
func (f *qualConvergenceFixture) create(t *testing.T) {
	t.Helper()
	require.NoError(t, f.records.create(f.tr))
}
func (f *qualConvergenceFixture) expected(status string, credited ...uint32) ([]byte, []byte) {
	bitmap := make([]byte, (len(f.tr.shards)+7)/8)
	acks := make([][]byte, len(f.tr.shards))
	for _, shard := range credited {
		bitmap[shard/8] |= 1 << uint(shard%8)
		acks[shard] = blake2b.NewBlake2b().Compute(string(qualRecordFrame(f.binding,
			binary.BigEndian.AppendUint32(nil, shard), f.local[shard])))
	}
	ackBytes := qualRecordFrame(acks...)
	commitment := blake2b.NewBlake2b().Compute(string(qualRecordFrame(f.binding, bitmap, ackBytes)))
	return qualRecordFrame(f.binding, []byte(status), bitmap, ackBytes, commitment), commitment
}
func (f *qualConvergenceFixture) assert(t *testing.T, status string, credited ...uint32) {
	t.Helper()
	expected, _ := f.expected(status, credited...)
	require.Equal(t, expected, qualRegistryValue(t, f.store, string(f.key)))
}

func TestQualDRWAConvergenceSingleAck(t *testing.T) {
	f := qualConvergenceNew(t, 3)
	f.create(t)
	require.NoError(t, f.ack(0))
	f.assert(t, "PENDING", 0)
	require.Empty(t, qualRegistryValue(t, f.store, qualConvergenceParent))
}

func TestQualDRWAConvergenceCanonicalReemission(t *testing.T) {
	f := qualConvergenceNew(t, 3)
	f.create(t)
	require.NoError(t, f.ack(0))
	before := qualRegistryValue(t, f.store, string(f.key))
	journal := f.store.JournalLen()
	local := bytes.Repeat([]byte{88}, 32)
	f.host.acks[string(qualRecordFrame(f.binding, []byte{0, 0, 0, 0}, local))] = 0
	require.NoError(t, f.records.acknowledge(f.tr, 0, local, []byte("synthetic-S-R-H-M-B-proof")))
	require.Equal(t, before, qualRegistryValue(t, f.store, string(f.key)), "first receipt is retained")
	require.Equal(t, journal, f.store.JournalLen())
	require.Equal(t, 2, f.host.ackCalls, "re-emission is independently authenticated")
	// A host callback mutating the original caller buffer cannot alter the
	// encoded binding already retained by the construction before that callback.
	f.host.hooks["ack"] = func() { f.tr.action[0] ^= 1 }
	require.NoError(t, f.ack(1))
	f.assert(t, "PENDING", 0, 1)
}

func TestQualDRWAConvergenceVectorsAndOrders(t *testing.T) {
	orders := [][]uint32{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	var final []byte
	for _, order := range orders {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			f := qualConvergenceNew(t, 3)
			f.create(t)
			f.assert(t, "PENDING")
			n := f.store.JournalLen()
			f.create(t)
			require.Equal(t, n, f.store.JournalLen())
			require.Equal(t, 1, f.host.admissionCalls)
			var seen []uint32
			for _, shard := range order {
				require.NoError(t, f.ack(shard))
				seen = append(seen, shard)
				f.assert(t, "PENDING", seen...)
				n = f.store.JournalLen()
				require.NoError(t, f.ack(shard))
				require.Equal(t, n, f.store.JournalLen())
			}
			require.NoError(t, f.records.complete(f.tr))
			f.assert(t, "COMPLETE", 0, 1, 2)
			expected, commitment := f.expected("COMPLETE", 0, 1, 2)
			require.Equal(t, qualRecordFrame(f.binding, commitment), qualRegistryValue(t, f.store, qualConvergenceParent))
			if final == nil {
				final = expected
			} else {
				require.Equal(t, final, expected)
			}
			n = f.store.JournalLen()
			require.NoError(t, f.records.complete(f.tr))
			f.create(t)
			require.NoError(t, f.ack(0))
			require.Equal(t, n, f.store.JournalLen())
			require.Equal(t, 1, f.host.completeCalls)
			_, outputs, err := f.owner.Commit()
			require.NoError(t, err)
			var parent *vmcommon.VMOutput
			for _, output := range outputs {
				if output != nil {
					parent = output
				}
			}
			require.NotNil(t, parent)
			require.Equal(t, uint64(27), parent.GasRemaining)
			require.Equal(t, [][]byte{[]byte("parent-phase-applied")}, parent.ReturnData)
			require.Equal(t, []byte("parent-log"), parent.Logs[0].Identifier)
		})
	}
}

func TestQualDRWAConvergenceMissingAndAuthenticatedDuplicates(t *testing.T) {
	for _, count := range []int{1, 3, 8, 9, 16} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := qualConvergenceNew(t, count)
			f.create(t)
			require.ErrorIs(t, f.records.complete(f.tr), errConvergence)
			for shard := uint32(0); shard < uint32(count)-1; shard++ {
				require.NoError(t, f.ack(shard))
			}
			require.ErrorIs(t, f.records.complete(f.tr), errConvergence, "no passage of time or partial set completes")
			require.Zero(t, f.host.completeCalls)
			require.NoError(t, f.ack(uint32(count)-1))
			f.assert(t, "PENDING", f.tr.shards...)
			fault := errors.New("canonical evidence no longer authenticates")
			f.host.faults["ack"] = fault
			require.ErrorIs(t, f.ack(0), fault, "set bit never bypasses authentication")
			f.assert(t, "PENDING", f.tr.shards...)
			delete(f.host.faults, "ack")
			require.NoError(t, f.records.complete(f.tr))
			f.host.faults["ack"] = fault
			require.ErrorIs(t, f.ack(0), fault, "completed phase never bypasses authentication")
			f.assert(t, "COMPLETE", f.tr.shards...)
		})
	}
}

func TestQualDRWAConvergenceRefusals(t *testing.T) {
	for _, name := range []string{"absent", "producer", "unknown_shard", "meta_shard", "execution", "proof", "transition", "ack", "wrong_body", "next_action"} {
		t.Run(name, func(t *testing.T) {
			f := qualConvergenceNew(t, 3)
			if name != "absent" {
				f.create(t)
				require.NoError(t, f.ack(0))
			}
			before := bytes.Clone(qualRegistryValue(t, f.store, string(f.key)))
			candidate, shard, local, proof := f.tr, uint32(1), f.local[1], []byte("synthetic-S-R-H-M-B-proof")
			switch name {
			case "producer":
				f.host.wrongProducer = true
			case "unknown_shard":
				shard = 3
			case "meta_shard":
				shard = core.MetachainShardId
			case "execution":
				local = bytes.Repeat([]byte{99}, 32)
			case "proof":
				proof = []byte("non-final-result")
			case "transition":
				f.host.faults["transition"] = errConvergence
			case "ack":
				f.host.faults["ack"] = errConvergence
			case "wrong_body":
				candidate.digest = bytes.Repeat([]byte{99}, 32)
				_, f.host.binding, _ = f.records.encode(candidate)
				f.host.acks[string(qualRecordFrame(f.host.binding, []byte{0, 0, 0, 1}, local))] = 1
			case "next_action":
				candidate.action = bytes.Repeat([]byte{99}, 32)
				_, f.host.binding, _ = f.records.encode(candidate)
				f.host.acks[string(qualRecordFrame(f.host.binding, []byte{0, 0, 0, 1}, local))] = 1
			}
			require.Error(t, f.records.acknowledge(candidate, shard, local, proof))
			require.Equal(t, before, qualRegistryValue(t, f.store, string(f.key)))
			require.Zero(t, f.host.completeCalls)
		})
	}
	for _, field := range []string{"digest", "token", "version", "target", "dependencies", "required_set"} {
		t.Run("create_conflict/"+field, func(t *testing.T) {
			f := qualConvergenceNew(t, 3)
			f.create(t)
			require.NoError(t, f.ack(0))
			candidate := f.tr
			switch field {
			case "digest":
				candidate.digest = bytes.Repeat([]byte{88}, 32)
			case "token":
				candidate.token = []byte("OTHER-abcdef")
			case "version":
				candidate.version++
			case "target":
				candidate.target = bytes.Repeat([]byte{88}, 32)
			case "dependencies":
				candidate.dependencies = bytes.Repeat([]byte{88}, 32)
			case "required_set":
				candidate.shards = []uint32{0, 1}
				candidate.requiredSet = blake2b.NewBlake2b().Compute(string(qualRecordFrame([]byte{0, 0, 0, 0}, []byte{0, 0, 0, 1})))
			}
			_, binding, err := f.records.encode(candidate)
			require.NoError(t, err)
			f.host.binding = binding // allow host; native immutable retained body must still reject
			require.ErrorIs(t, f.records.create(candidate), errConvergence)
			f.assert(t, "PENDING", 0)
		})
	}
}

func TestQualDRWAConvergenceMalformedRecords(t *testing.T) {
	for _, name := range []string{"empty", "truncated", "unknown_field", "binding", "status", "bitmap_size", "padding", "receipt_count", "receipt_missing", "receipt_unset", "receipt_width", "commitment", "premature_complete", "oversized"} {
		t.Run(name, func(t *testing.T) {
			f := qualConvergenceNew(t, 3)
			f.create(t)
			original, _ := f.expected("PENDING")
			p := &convergenceProgress{status: "PENDING", bitmap: []byte{0}, acks: make([][]byte, 3)}
			binding := f.binding
			switch name {
			case "binding":
				binding = []byte("other")
			case "status":
				p.status = "TIMED_OUT_READY"
			case "bitmap_size":
				p.bitmap = []byte{0, 0}
			case "padding":
				p.bitmap = []byte{8}
			case "receipt_count":
				p.acks = make([][]byte, 2)
			case "receipt_missing":
				p.bitmap = []byte{1}
			case "receipt_unset":
				p.acks[0] = bytes.Repeat([]byte{5}, 32)
			case "receipt_width":
				p.bitmap = []byte{1}
				p.acks[0] = []byte{5}
			case "premature_complete":
				p.status = "COMPLETE"
			}
			acks := qualRecordFrame(p.acks...)
			commitment := blake2b.NewBlake2b().Compute(string(qualRecordFrame(binding, p.bitmap, acks)))
			value := qualRecordFrame(binding, []byte(p.status), p.bitmap, acks, commitment)
			switch name {
			case "empty":
				value = nil
			case "truncated":
				value = original[:len(original)-1]
			case "unknown_field":
				value = append(bytes.Clone(original), 0x28, 0)
			case "commitment":
				value[len(value)-1] ^= 1
			case "oversized":
				value = bytes.Repeat([]byte{0}, 4097)
			}
			qualRecordPut(t, f.store, f.key, value)
			require.Error(t, f.ack(0))
			require.Equal(t, value, qualRegistryValue(t, f.store, string(f.key)))
			require.Error(t, f.records.complete(f.tr))
			require.Zero(t, f.host.completeCalls)
		})
	}
}

func TestQualDRWAConvergenceBounds(t *testing.T) {
	for _, name := range []string{"token", "action", "digest", "target", "dependencies", "set_hash", "empty_set", "count", "duplicate", "order", "meta", "execution", "evidence", "empty_evidence", "full_record"} {
		t.Run(name, func(t *testing.T) {
			f := qualConvergenceNew(t, 3)
			candidate := f.tr
			switch name {
			case "token":
				candidate.token = bytes.Repeat([]byte{'a'}, 4097)
			case "action":
				candidate.action = nil
			case "digest":
				candidate.digest = []byte{1}
			case "target":
				candidate.target = []byte{1}
			case "dependencies":
				candidate.dependencies = []byte{1}
			case "set_hash":
				candidate.requiredSet = bytes.Repeat([]byte{99}, 32)
			case "empty_set":
				candidate.shards = nil
			case "count":
				candidate.shards = make([]uint32, 17)
				ids := make([][]byte, 17)
				for i := range candidate.shards {
					candidate.shards[i] = uint32(i)
					ids[i] = binary.BigEndian.AppendUint32(nil, uint32(i))
				}
				candidate.requiredSet = blake2b.NewBlake2b().Compute(string(qualRecordFrame(ids...)))
			case "duplicate":
				candidate.shards = []uint32{0, 0, 2}
			case "order":
				candidate.shards = []uint32{0, 2, 1}
			case "meta":
				candidate.shards = []uint32{0, 1, core.MetachainShardId}
			case "execution":
				require.Error(t, f.records.acknowledge(candidate, 0, []byte{1}, []byte("proof")))
				require.Zero(t, f.host.verifyCalls)
				return
			case "evidence":
				require.Error(t, f.records.acknowledge(candidate, 0, f.local[0], bytes.Repeat([]byte{1}, 4097)))
				require.Zero(t, f.host.verifyCalls)
				return
			case "empty_evidence":
				require.Error(t, f.records.acknowledge(candidate, 0, f.local[0], nil))
				require.Zero(t, f.host.verifyCalls)
				return
			case "full_record":
				full, _ := f.expected("COMPLETE", 0, 1, 2)
				f.records.codec.maxBytes = len(full) - 1
			}
			require.Error(t, f.records.create(candidate))
			require.Zero(t, f.host.verifyCalls)
			require.Zero(t, f.host.admissionCalls)
			require.Empty(t, qualRegistryValue(t, f.store, string(f.key)))
		})
	}
	for _, name := range []string{"nil_host", "nil_owner", "foreign_store", "zero_bound", "negative_bound", "excess_bound", "nil_hasher", "nil_marshaller"} {
		t.Run("constructor/"+name, func(t *testing.T) {
			f := qualConvergenceNew(t, 3)
			store := state.AccountsAdapter(f.store)
			owner := f.owner
			host := convergenceHost(f.host)
			bound := 16
			mar := &marshal.GogoProtoMarshalizer{}
			hash := blake2b.NewBlake2b()
			switch name {
			case "nil_host":
				host = nil
			case "nil_owner":
				owner = nil
			case "foreign_store":
				store = qualRegistrationStore(t, 0)
			case "zero_bound":
				bound = 0
			case "negative_bound":
				bound = -1
			case "excess_bound":
				bound = 4096
			case "nil_hasher":
				hash = nil
			case "nil_marshaller":
				mar = nil
			}
			_, err := newConvergenceRecords(store, owner, mar, hash, 4096, bound, host)
			require.Error(t, err)
		})
	}
}

func TestQualDRWAConvergenceAtomicParent(t *testing.T) {
	for _, name := range []string{"admission", "create_save", "ack_save", "parent", "parent_verification", "nil_output", "denied_output", "progress_after_parent", "changed_progress"} {
		t.Run(name, func(t *testing.T) {
			f := qualConvergenceNew(t, 3)
			fault := errors.New("native convergence boundary fault")
			if name == "admission" || name == "create_save" {
				if name == "admission" {
					f.host.faults["admission"] = fault
				} else {
					f.store.saveErr = fault
				}
				require.ErrorIs(t, f.records.create(f.tr), fault)
				f.store.saveErr = nil
				require.Empty(t, qualRegistryValue(t, f.store, string(f.key)))
				return
			}
			f.create(t)
			require.NoError(t, f.ack(0))
			if name == "ack_save" {
				f.store.saveErr = fault
				require.ErrorIs(t, f.ack(1), fault)
				f.store.saveErr = nil
				f.assert(t, "PENDING", 0)
				return
			}
			require.NoError(t, f.ack(1))
			require.NoError(t, f.ack(2))
			before := qualRegistryValue(t, f.store, string(f.key))
			switch name {
			case "parent":
				f.host.faults["complete"] = fault
			case "parent_verification":
				f.host.faults["parent"] = fault
			case "nil_output":
				f.host.nilOutput = true
			case "denied_output":
				f.host.deniedOutput = true
			case "progress_after_parent":
				f.host.hooks["after_parent"] = func() { f.store.saveErr = fault }
			case "changed_progress":
				f.host.hooks["after_parent"] = func() { qualRecordPut(t, f.store, f.key, []byte("corrupt")) }
			}
			require.Error(t, f.records.complete(f.tr))
			f.store.saveErr = nil
			require.Equal(t, before, qualRegistryValue(t, f.store, string(f.key)))
			require.Empty(t, qualRegistryValue(t, f.store, qualConvergenceParent))
			_, outputs, err := f.owner.Commit()
			require.NoError(t, err)
			for _, output := range outputs {
				require.Nil(t, output, "failed parent output cannot escape")
			}
		})
	}
}

func TestQualDRWAConvergenceRestartAndRollback(t *testing.T) {
	f := qualConvergenceNew(t, 3)
	f.create(t)
	require.NoError(t, f.ack(0))
	root, _, err := f.owner.Commit()
	require.NoError(t, err)
	f.reopen(t, f.store)
	require.NoError(t, f.ack(1))
	f.assert(t, "PENDING", 0, 1)
	require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(root[0])))
	f.reopen(t, f.store)
	f.assert(t, "PENDING", 0)
	require.NoError(t, f.ack(1))
	require.NoError(t, f.ack(1))
	require.NoError(t, f.ack(2))
	require.NoError(t, f.records.complete(f.tr))
	root, _, err = f.owner.Commit()
	require.NoError(t, err)
	require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(root[0])))
	f.reopen(t, f.store)
	f.assert(t, "COMPLETE", 0, 1, 2)
	require.NoError(t, f.ack(1))
	require.NoError(t, f.records.complete(f.tr))
	require.Zero(t, f.store.JournalLen())
	f.host.faults["parent"] = errConvergence
	require.ErrorIs(t, f.records.complete(f.tr), errConvergence)
	require.ErrorIs(t, f.records.create(f.tr), errConvergence)
	f.assert(t, "COMPLETE", 0, 1, 2)
}
