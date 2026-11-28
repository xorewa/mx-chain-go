package drwa

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

// sp223Acks builds the three shards' acknowledgements of the given bindings.
func sp223Acks(t *testing.T, nonce uint64, bindings ...[]byte) []*sp223Ack {
	t.Helper()
	acks := make([]*sp223Ack, 3)
	for shard := range acks {
		acks[shard] = sp223Acknowledge(t, uint32(shard), nonce, bindings...)
	}
	return acks
}

func sp223FamilyPhases() [][2]string {
	var all [][2]string
	for family, definition := range convergenceFamilies {
		for phase := range definition.phases {
			all = append(all, [2]string{family, phase})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i][0]+"/"+all[i][1] < all[j][0]+"/"+all[j][1] })
	return all
}

// Every admitted family and phase, through the production host: creation with
// its receipt and budget charge, one canonically final acknowledgement per
// required shard, completion with the durable parent receipt. The identity
// and binding are compared with an independently framed vector.
func TestQualSP223EveryFamilyAndPhaseThroughTheProductionHost(t *testing.T) {
	pairs := sp223FamilyPhases()
	require.Len(t, pairs, 27)
	for index, pair := range pairs {
		t.Run(pair[0]+"/"+pair[1], func(t *testing.T) {
			w := sp223New(t, sp223Ample())
			tr := w.transition(pair[0], pair[1], byte(10+index), true)
			key, binding, err := w.records.encode(tr)
			require.NoError(t, err)

			// Independent vector: the seven coordinates of Part A L1038-1052.
			set := qualRecordFrame([]byte{0, 0, 0, 0}, []byte{0, 0, 0, 1}, []byte{0, 0, 0, 2})
			fields := [][]byte{[]byte(pair[0]), tr.action, tr.digest, []byte(pair[1]), []byte("TOKEN-abcdef"),
				{0, 0, 0, 0, 0, 0, 0, 7}, tr.target, tr.dependencies, w.hasher.Compute(string(set)), set}
			identity := [][]byte{[]byte(pair[0]), tr.action, []byte(pair[1])}
			if tr.context != nil {
				fields = append(fields, tr.context.lineage, tr.context.predecessor)
				identity = append(identity, tr.context.lineage)
			}
			require.Equal(t, qualRecordFrame(fields...), binding)
			require.Equal(t, append([]byte("ELRONDDRWA@convergence@"), qualRecordFrame(identity...)...), key)

			before := w.value(sp223BudgetKey)
			require.NoError(t, w.records.create(tr))
			receipt := "ELRONDDRWA@convergenceReceipt@" + string(w.hasher.Compute(string(qualRecordFrame(identity...))))
			require.Equal(t, w.hasher.Compute(string(binding)), w.value(receipt))
			charged := w.value(sp223BudgetKey)
			records := uint64(2)
			if convergenceFamilies[pair[0]].entitlement {
				records = 3
			}
			require.Equal(t, binary.BigEndian.Uint64(before)+records, binary.BigEndian.Uint64(charged))
			require.Greater(t, binary.BigEndian.Uint64(charged[8:])-binary.BigEndian.Uint64(before[8:]), uint64(len(key)+len(binding)))

			acks := sp223Acks(t, 11, binding)
			w.denied("completion before any acknowledgement", func() error { return w.records.complete(tr) })
			for shard, ack := range acks {
				require.NoError(t, w.deliver(tr, ack))
				_, progress, e := w.records.observe(tr)
				require.NoError(t, e)
				require.Equal(t, "PENDING", progress.status)
				for i := range acks {
					require.Equal(t, i <= shard, progress.bitmap[0]&(1<<uint(i)) != 0)
				}
				if shard < len(acks)-1 {
					w.denied("completion with a missing shard", func() error { return w.records.complete(tr) })
				}
			}
			progressBytes := w.value(sp223BudgetKey)
			require.Equal(t, charged, progressBytes, "acknowledgements use the capacity reserved at creation")
			require.NoError(t, w.records.complete(tr))
			_, progress, err := w.records.observe(tr)
			require.NoError(t, err)
			require.Equal(t, "COMPLETE", progress.status)
			parent := "ELRONDDRWA@convergenceParent@" + string(w.hasher.Compute(string(qualRecordFrame(identity...))))
			require.Equal(t, qualRecordFrame(w.hasher.Compute(string(binding)), progress.commitment), w.value(parent))
			require.Equal(t, binary.BigEndian.Uint64(charged)+1, binary.BigEndian.Uint64(w.value(sp223BudgetKey)))
			require.NoError(t, w.host.VerifyParent(binding, progress.commitment))

			// Completed work is idempotent and a completed phase is never created again.
			root := w.root()
			require.NoError(t, w.records.complete(tr))
			require.NoError(t, w.records.create(tr))
			require.NoError(t, w.deliver(tr, acks[0]))
			require.Equal(t, root, w.root())
		})
	}
}

// Families and phases that are not admitted are refused before any state:
// unknown names, the plane and release families the owner left out of code,
// a phase of another family, a family with no installed owner, and a
// transition its owner did not create.
func TestQualSP223UnadmittedFamiliesAndPhasesAreRefused(t *testing.T) {
	w := sp223New(t, sp223Ample())
	for _, pair := range [][2]string{{"SYNTHETIC_SETUP", "READY"}, {"PLANE", "DRWAReleaseReadyAck"}, {"RELEASE_PROFILE", "DRWAReleaseReadyAck"},
		{ConvergenceFamilyRoot, "CURRENT_ACK"}, {ConvergenceFamilyBootstrap, "ROOT_FENCE_ACK"}, {ConvergenceFamilyRetirement, "SETUP_SEALED"},
		{"bootstrap_readiness", "TYPE_PROFILE_READINESS"}} {
		tr := w.transition(pair[0], pair[1], 9, false)
		b, err := w.host.decode(w.binding(tr))
		require.NoError(t, err)
		w.owner.admitted[sp223BindingID(*b)] = struct{}{} // even an owner's word does not admit it
		w.denied(pair[0]+"/"+pair[1], func() error { return w.records.create(tr) })
	}
	unowned := w.transition(ConvergenceFamilyRoot, "ROOT_FENCE_ACK", 9, false)
	w.denied("a transition its owner did not create", func() error { return w.records.create(unowned) })

	delete(w.host.args.Owners, ConvergenceFamilyRoot)
	owned := w.transition(ConvergenceFamilyRoot, "ROOT_FENCE_ACK", 9, true)
	w.denied("a family with no installed owner", func() error { return w.records.create(owned) })

	_, err := NewConvergenceHost(ArgsConvergenceHost{Accounts: w.store, Records: w.host.args.Records, Reader: w.reader, Block: w.block,
		Limits: w.limits, EvidenceBytes: 1, Owners: map[string]ConvergenceFamilyOwner{"PLANE": w.owner}})
	require.Error(t, err, "an owner cannot be installed for a family that is not defined")
}

// An acknowledgement counts only for the exact family, instance, phase,
// subject, target, dependencies and required shard set, lineage and
// predecessor it was made for, from the shard that made it.
func TestQualSP223AcknowledgementOfAnotherContextDoesNotCount(t *testing.T) {
	w := sp223New(t, sp223Ample())
	tr := w.transition(ConvergenceFamilyCEB, "PREPARED_ACK", 20, true)
	require.NoError(t, w.records.create(tr))
	binding := w.binding(tr)

	variants := map[string]func(*convergenceTransition){
		"family":       func(v *convergenceTransition) { v.context.family = []byte(ConvergenceFamilyRecoveryCEB) },
		"instance":     func(v *convergenceTransition) { v.action = bytes.Repeat([]byte{0x77}, 32) },
		"digest":       func(v *convergenceTransition) { v.digest = bytes.Repeat([]byte{0x77}, 32) },
		"phase":        func(v *convergenceTransition) { v.context.phase = []byte("CLOSURE_ACK") },
		"subject":      func(v *convergenceTransition) { v.token = []byte("OTHER-abcdef") },
		"version":      func(v *convergenceTransition) { v.version = 8 },
		"target":       func(v *convergenceTransition) { v.target = bytes.Repeat([]byte{0x77}, 32) },
		"dependencies": func(v *convergenceTransition) { v.dependencies = bytes.Repeat([]byte{0x77}, 32) },
		"shard set": func(v *convergenceTransition) {
			v.shards = []uint32{0, 1}
			v.requiredSet = w.hasher.Compute(string(qualRecordFrame([]byte{0, 0, 0, 0}, []byte{0, 0, 0, 1})))
		},
		"lineage":     func(v *convergenceTransition) { v.context.lineage = []byte("other-lineage") },
		"predecessor": func(v *convergenceTransition) { v.context.predecessor = bytes.Repeat([]byte{0x77}, 32) },
	}
	for name, change := range variants {
		other := tr
		context := *tr.context
		other.context = &context
		change(&other)
		w.admit(other)
		otherBinding := w.binding(other)
		require.NotEqual(t, binding, otherBinding, name)
		// The shard acknowledged the other context only.
		ack := sp223Acknowledge(t, 0, 11, otherBinding)
		w.enter(ack)
		w.denied(name+": evidence of the other context", func() error {
			return w.records.acknowledge(tr, 0, ack.origin, ack.evidence(t, otherBinding))
		})
		// Nor can the item made for the other context be presented under this one's key.
		w.denied(name+": absent item", func() error {
			witness := ack.witness(t, otherBinding)
			return w.records.acknowledge(tr, 0, ack.origin, sp223Evidence(t, witness))
		})
	}
	_, progress, err := w.records.observe(tr)
	require.NoError(t, err)
	require.Zero(t, progress.bitmap[0])
}

// Authentication of the producer and of canonical finality: the payload's
// shard is a claim, the evidence decides.
func TestQualSP223AcknowledgementMustBeAuthenticatedAndCanonicalFinal(t *testing.T) {
	w := sp223New(t, sp223Ample())
	tr := w.transition(ConvergenceFamilyRoot, "ROOT_FENCE_ACK", 30, true)
	require.NoError(t, w.records.create(tr))
	binding := w.binding(tr)
	acks := sp223Acks(t, 11, binding)
	good := acks[1]
	evidence := func(change func(*canonicalResultWitness)) []byte {
		witness := good.witness(t, binding)
		change(&witness)
		return sp223Evidence(t, witness)
	}
	w.enter(good)
	cases := map[string]func() error{
		"another shard's evidence under this shard's name": func() error {
			return w.records.acknowledge(tr, 0, good.origin, good.evidence(t, binding))
		},
		"this shard's name on another shard's execution": func() error {
			return w.records.acknowledge(tr, 1, acks[0].origin, acks[0].evidence(t, binding))
		},
		"a local execution identity that is not the executed block": func() error {
			return w.records.acknowledge(tr, 1, bytes.Repeat([]byte{9}, 32), good.evidence(t, binding))
		},
		"a result with only one settled descendant": func() error {
			return w.records.acknowledge(tr, 1, good.origin, evidence(func(x *canonicalResultWitness) {
				x.MetaHeaders, x.MetaProofs = x.MetaHeaders[:2], x.MetaProofs[:2]
			}))
		},
		"a missing header proof": func() error {
			return w.records.acknowledge(tr, 1, good.origin, evidence(func(x *canonicalResultWitness) { x.HeaderProof = nil }))
		},
		"an altered account proof": func() error {
			return w.records.acknowledge(tr, 1, good.origin, evidence(func(x *canonicalResultWitness) {
				x.Account.AccountProof[0] = append(bytes.Clone(x.Account.AccountProof[0]), 1)
			}))
		},
		"an altered data proof": func() error {
			return w.records.acknowledge(tr, 1, good.origin, evidence(func(x *canonicalResultWitness) {
				x.Account.DataProof = x.Account.DataProof[:len(x.Account.DataProof)-1]
			}))
		},
		"a carrying header of another execution": func() error {
			return w.records.acknowledge(tr, 1, good.origin, evidence(func(x *canonicalResultWitness) {
				x.Account.Header = acks[2].f.w.Account.Header
			}))
		},
		"evidence that is not the framed form": func() error { return w.records.acknowledge(tr, 1, good.origin, []byte("carrier arrival")) },
		"evidence with a trailing field": func() error {
			return w.records.acknowledge(tr, 1, good.origin, append(good.evidence(t, binding), 0x0a, 0x00))
		},
		"evidence that names its own consuming": func() error { return w.records.acknowledge(tr, 1, good.origin, good.f.w.Consumer) },
	}
	for name, run := range cases {
		w.denied(name, run)
	}
	// Evidence settled for another consuming block is not evidence for this one.
	w.enter(acks[0])
	w.denied("evidence of another consuming block", func() error {
		return w.records.acknowledge(tr, 1, good.origin, good.evidence(t, binding))
	})
	w.block.hash = nil
	w.denied("no block in execution", func() error { return w.records.acknowledge(tr, 1, good.origin, good.evidence(t, binding)) })
	w.denied("the metachain as a producer", func() error {
		return w.records.acknowledge(tr, core.MetachainShardId, good.origin, good.evidence(t, binding))
	})
	require.NoError(t, w.deliver(tr, good))
	_, progress, err := w.records.observe(tr)
	require.NoError(t, err)
	require.Equal(t, byte(2), progress.bitmap[0])
}

// Duplicate and conflicting acknowledgements: the same shard counts once, an
// authenticated duplicate changes nothing, and a second, different canonical
// execution of the same shard cannot replace or add to the first.
func TestQualSP223DuplicateAndConflictingAcknowledgements(t *testing.T) {
	w := sp223New(t, sp223Ample())
	tr := w.transition(ConvergenceFamilySetup, "SETUP_READY_ACK", 40, true)
	require.NoError(t, w.records.create(tr))
	binding := w.binding(tr)
	first := sp223Acknowledge(t, 2, 11, binding)
	require.NoError(t, w.deliver(tr, first))
	root := w.root()
	for i := 0; i < 3; i++ {
		require.NoError(t, w.deliver(tr, first))
		require.Equal(t, root, w.root())
	}
	conflicting := sp223Acknowledge(t, 2, 12, binding)
	require.NotEqual(t, first.origin, conflicting.origin)
	w.denied("a second execution of the same shard", func() error { return w.deliver(tr, conflicting) })
	w.enter(first)
	w.denied("a duplicate without its evidence", func() error {
		return w.records.acknowledge(tr, 2, first.origin, []byte("looks like the first"))
	})
	_, progress, err := w.records.observe(tr)
	require.NoError(t, err)
	require.Equal(t, byte(4), progress.bitmap[0])
	w.denied("one shard counted three times is not three shards", func() error { return w.records.complete(tr) })
}

// Two transitions on one subject at the same time: each has its own progress;
// an acknowledgement of one never advances the other; each completes on its
// own complete set. One shard's execution may acknowledge both.
func TestQualSP223TwoTransitionsOnOneSubject(t *testing.T) {
	w := sp223New(t, sp223Ample())
	a := w.transition(ConvergenceFamilyCEB, "CLOSURE_ACK", 50, true)
	b := w.transition(ConvergenceFamilyRebindFence, "FENCE_ACTIVATION_ACK", 60, true)
	require.Equal(t, a.token, b.token)
	require.NoError(t, w.records.create(a))
	require.NoError(t, w.records.create(b))
	both := sp223Acks(t, 11, w.binding(a), w.binding(b))
	for _, ack := range both {
		require.NoError(t, w.deliver(a, ack))
	}
	_, progress, err := w.records.observe(b)
	require.NoError(t, err)
	require.Zero(t, progress.bitmap[0], "the other transition's acknowledgements do not count")
	w.denied("completion of the transition nobody acknowledged", func() error { return w.records.complete(b) })
	require.NoError(t, w.records.complete(a))
	require.NoError(t, w.deliver(b, both[0]))
	require.NoError(t, w.deliver(b, both[2]))
	w.denied("completion with shard 1 missing", func() error { return w.records.complete(b) })
	require.NoError(t, w.deliver(b, both[1]))
	require.NoError(t, w.records.complete(b))
}

// Replay after restart: progress, receipts and the budget are read back from
// the committed store; a replayed acknowledgement adds nothing; a completed
// phase cannot be created again even when its live progress is gone.
func TestQualSP223ReplayAfterRestartAndCompaction(t *testing.T) {
	w := sp223New(t, sp223Ample())
	tr := w.transition(ConvergenceFamilyRetirement, "WIND_DOWN_SEALED", 70, true)
	require.NoError(t, w.records.create(tr))
	binding := w.binding(tr)
	acks := sp223Acks(t, 11, binding)
	require.NoError(t, w.deliver(tr, acks[0]))
	w.restart()
	_, progress, err := w.records.observe(tr)
	require.NoError(t, err)
	require.Equal(t, byte(1), progress.bitmap[0])
	root := w.root()
	require.NoError(t, w.deliver(tr, acks[0]))
	require.NoError(t, w.records.create(tr))
	require.Equal(t, root, w.root())
	require.NoError(t, w.deliver(tr, acks[1]))
	require.NoError(t, w.deliver(tr, acks[2]))
	require.NoError(t, w.records.complete(tr))
	w.restart()
	_, progress, err = w.records.observe(tr)
	require.NoError(t, err)
	require.Equal(t, "COMPLETE", progress.status)

	// Compaction of the live progress: the receipts stay and refuse a new
	// creation of the same phase instance and a replay of its acknowledgements.
	key, _, err := w.records.encode(tr)
	require.NoError(t, err)
	qualRecordPut(t, w.store, key, nil)
	w.restart()
	budget := w.value(sp223BudgetKey)
	w.denied("creation after compaction", func() error { return w.records.create(tr) })
	w.denied("acknowledgement after compaction", func() error { return w.deliver(tr, acks[0]) })
	require.Equal(t, budget, w.value(sp223BudgetKey))
	require.NoError(t, w.host.VerifyParent(binding, progress.commitment))
}

// Reorganisation: an acknowledgement counted in a block that is replaced
// leaves with that block, and with it everything that depended on it.
func TestQualSP223ReorganisedBlockTakesItsAcknowledgementAway(t *testing.T) {
	w := sp223New(t, sp223Ample())
	tr := w.transition(ConvergenceFamilyBootstrap, "TYPE_PROFILE_READINESS", 80, true)
	require.NoError(t, w.records.create(tr))
	binding := w.binding(tr)
	acks := sp223Acks(t, 11, binding)
	require.NoError(t, w.deliver(tr, acks[0]))
	require.NoError(t, w.deliver(tr, acks[1]))
	w.restart() // the committed block before the one that is replaced
	committed := w.root()

	snapshot := w.store.JournalLen()
	require.NoError(t, w.deliver(tr, acks[2]))
	require.NoError(t, w.records.complete(tr))
	_, progress, err := w.records.observe(tr)
	require.NoError(t, err)
	require.Equal(t, "COMPLETE", progress.status)
	require.NoError(t, w.store.RevertToSnapshot(snapshot))
	w.build()
	require.Equal(t, committed, w.root())
	_, progress, err = w.records.observe(tr)
	require.NoError(t, err)
	require.Equal(t, "PENDING", progress.status)
	require.Equal(t, byte(3), progress.bitmap[0])
	require.Error(t, w.host.VerifyParent(binding, progress.commitment))
	w.denied("completion on the replacing chain without the acknowledgement", func() error { return w.records.complete(tr) })
	// The replacing chain settles the shard's execution again and may count it.
	require.NoError(t, w.deliver(tr, acks[2]))
	require.NoError(t, w.records.complete(tr))
}

// Completed versus cancelled outcome (IA-07). A continuation or cancellation
// phase is entitled by one predecessor outcome, once. The acknowledgements of
// the cancelled target do not count for it, a second successor of the same
// outcome is refused, and recovery of another lineage does not revive it.
func TestQualSP223ContinuationEntitlementIsSingleUse(t *testing.T) {
	w := sp223New(t, sp223Ample())
	cancelled := w.transition(ConvergenceFamilyCEB, "PREPARED_ACK", 90, true)
	require.NoError(t, w.records.create(cancelled))
	old := sp223Acks(t, 11, w.binding(cancelled))
	require.NoError(t, w.deliver(cancelled, old[0]))

	outcome := bytes.Repeat([]byte{0xc1}, 32) // the cancelled action's durable outcome receipt
	continuation := w.transition(ConvergenceFamilyContinuation, "cancellation-fence", 91, false)
	continuation.context.predecessor = outcome
	w.admit(continuation)
	require.NoError(t, w.records.create(continuation))

	for shard := range old {
		w.enter(old[shard])
		w.denied("the cancelled target's acknowledgement", func() error {
			return w.records.acknowledge(continuation, uint32(shard), old[shard].origin, old[shard].evidence(t, w.binding(cancelled)))
		})
	}
	// A second successor of the same outcome: concurrent entitlement consumption.
	rival := w.transition(ConvergenceFamilyContinuation, "cancellation-fence", 92, false)
	rival.context.predecessor = outcome
	w.admit(rival)
	w.denied("a second successor of the same outcome", func() error { return w.records.create(rival) })
	// The same instance in a later phase carries that phase's own predecessor.
	next := w.transition(ConvergenceFamilyContinuation, "CLOSURE_ACK", 91, true)
	require.NoError(t, w.records.create(next))
	// Recovery has its own action, target and fresh convergence; it neither
	// consumes nor restores the continuation's entitlement.
	recovery := w.transition(ConvergenceFamilyRecoveryCEB, "PREPARED_ACK", 93, false)
	recovery.context.predecessor = outcome
	w.admit(recovery)
	require.NoError(t, w.records.create(recovery))
	w.restart()
	w.denied("a second successor after restart", func() error { return w.records.create(rival) })
	// The cancelled phase stays as it was: pending, never completed by its successor.
	_, progress, err := w.records.observe(cancelled)
	require.NoError(t, err)
	require.Equal(t, "PENDING", progress.status)
}

// Phase creation is charged to the chain-global retained budget of SP2-29
// before anything is written: one below, at and one above each bound.
func TestQualSP223CreationIsBoundedByTheRetainedBudget(t *testing.T) {
	probe := sp223New(t, sp223Ample())
	tr := probe.transition(ConvergenceFamilySetup, "SETUP_SEALED", 100, true)
	start := probe.value(sp223BudgetKey)
	require.NoError(t, probe.records.create(tr))
	used := probe.value(sp223BudgetKey)
	needRecords, needBytes := binary.BigEndian.Uint64(used), binary.BigEndian.Uint64(used[8:])
	needRate := binary.BigEndian.Uint64(used[24:])
	require.Equal(t, binary.BigEndian.Uint64(start)+2, needRecords)
	for _, dimension := range []string{"records", "bytes", "rate"} {
		for offset, admitted := range map[int]bool{-1: false, 0: true, 1: true} {
			t.Run(fmt.Sprintf("%s/%+d", dimension, offset), func(t *testing.T) {
				limits := sp223Ample()
				switch dimension {
				case "records":
					limits.Records = uint64(int64(needRecords) + int64(offset))
				case "bytes":
					limits.RetainedBytes = uint64(int64(needBytes) + int64(offset))
				case "rate":
					limits.NewRecordsPerEpoch = uint64(int64(needRate) + int64(offset))
				}
				w := sp223New(t, limits)
				same := w.transition(ConvergenceFamilySetup, "SETUP_SEALED", 100, true)
				if !admitted {
					w.denied("creation over the bound", func() error { return w.records.create(same) })
					return
				}
				require.NoError(t, w.records.create(same))
				require.Equal(t, used, w.value(sp223BudgetKey))
			})
		}
	}
	// The parent receipt is a retained record too.
	limits := sp223Ample()
	limits.Records = needRecords
	w := sp223New(t, limits)
	same := w.transition(ConvergenceFamilySetup, "SETUP_SEALED", 100, true)
	require.NoError(t, w.records.create(same))
	for _, ack := range sp223Acks(t, 11, w.binding(same)) {
		require.NoError(t, w.deliver(same, ack))
	}
	w.denied("completion with no capacity for the parent receipt", func() error { return w.records.complete(same) })
}

// The shard half: the item is written once, in the shard's own account.
func TestQualSP223ShardAcknowledgementWriter(t *testing.T) {
	w := sp223New(t, sp223Ample())
	binding := w.binding(w.transition(ConvergenceFamilyRoot, "ROOT_CURRENT_ACK", 110, true))
	ack := sp223Acknowledge(t, 1, 11, binding)
	key, value, err := convergenceAckItem(ack.codec, binding, 1)
	require.NoError(t, err)
	require.Equal(t, append([]byte("ELRONDDRWA@convergenceAck@"), w.hasher.Compute(string(binding))...), key)
	require.Equal(t, w.hasher.Compute(string(qualRecordFrame(binding, []byte{0, 0, 0, 1}))), value)
	require.Equal(t, value, qualRegistryValue(t, ack.f.s.qualNativeStore, string(key)))

	_, err = NewConvergenceAckWriter(ack.codec, core.MetachainShardId)
	require.Error(t, err)
	_, err = NewConvergenceAckWriter(nil, 1)
	require.Error(t, err)
	writer, err := NewConvergenceAckWriter(ack.codec, 1)
	require.NoError(t, err)
	require.False(t, writer.IsInterfaceNil())
	require.Error(t, writer.Acknowledge(nil))
	require.Error(t, writer.Acknowledge(bytes.Repeat([]byte{1}, 5000)))
	// An item of another shard under the same phase instance is a conflict.
	other, err := NewConvergenceAckWriter(ack.codec, 2)
	require.NoError(t, err)
	root, err := ack.f.s.RootHash()
	require.NoError(t, err)
	require.Error(t, other.Acknowledge(binding))
	after, err := ack.f.s.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
}

// The finality import owner of the metachain block processor is the host's
// block source: it names the block only between BeginBlock and EndBlock, by
// the exact header bytes whose hash the block processor committed.
func TestQualSP223FinalityImportNamesTheBlockInExecution(t *testing.T) {
	n := newSP222Node(t, core.MetachainShardId, true)
	var source ConvergenceBlockSource = n.imp
	require.False(t, source.IsInterfaceNil())
	require.Equal(t, core.MetachainShardId, n.imp.SelfShardID())
	_, _, _, err := source.ExecutingBlock()
	require.ErrorIs(t, err, ErrFinalityImport)

	h := n.next(false)
	require.NoError(t, n.begin(h))
	hash, raw, epoch, err := source.ExecutingBlock()
	require.NoError(t, err)
	require.Equal(t, n.hash(h), hash)
	expected, err := n.mar.Marshal(h)
	require.NoError(t, err)
	require.Equal(t, expected, raw)
	require.Equal(t, h.GetEpoch(), epoch)
	n.commit(h)
	_, _, _, err = source.ExecutingBlock()
	require.ErrorIs(t, err, ErrFinalityImport)

	// A reverted execution names nothing either.
	h = n.next(false)
	require.NoError(t, n.begin(h))
	n.revert()
	_, _, _, err = source.ExecutingBlock()
	require.ErrorIs(t, err, ErrFinalityImport)
}
