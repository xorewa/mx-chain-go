package drwa

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/stretchr/testify/require"
)

// D-09: Part A 3.4 requires exactly the stored nonce even for a new action ID.
func TestQualFA01RecordsStaleNonceDistinctPayload(t *testing.T) {
	f := qualGovernedActionNew(t)
	f.initialize(t)
	first := f.propose(t)
	f.p.payload = bytes.Clone(f.p.bindings)
	envelope, _, second := f.expected(100)
	require.NotEqual(t, first, second)
	f.h.envelope = envelope
	f.denied(t, func() error { _, err := f.g.propose(f.x, f.p); return err })
	f.count(t, 1)
	require.Equal(t, uint64(1), binary.BigEndian.Uint64(qualRegistryValue(t, f.s, string(f.counter()))))
	f.p.nonce = 1
	f.propose(t)
	f.count(t, 2)
}

// D-34: independent stored category-01 bytes, native root recreation and the
// owning T21 authorize path must agree with the same protected active member.
func TestQualFA01RecordsProtectedGASPersistence(t *testing.T) {
	v := qualGASVectorsLoad(t)
	for _, status := range []string{"proposed", "executable"} {
		t.Run(status, func(t *testing.T) {
			f := qualGovernedActionNew(t)
			f.h.protected = true
			f.initialize(t)
			id := f.propose(t)
			key := qualGASVectorBytes(t, v.Keys["action"])
			want := qualGASVectorBytes(t, qualFA01ProtectedGASProposed)
			require.Equal(t, want, qualRegistryValue(t, f.s, string(key)))
			root := f.commit(t)
			require.NoError(t, f.s.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
			f.reopen(t, f.s)
			f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 105)
			r, _, stored, err := f.g.load(id)
			require.NoError(t, err)
			require.True(t, r.protected)
			require.Equal(t, want, stored)
			require.Equal(t, qualGASVectorBytes(t, v.Records["active_protected"].Hex), qualRegistryValue(t, f.s, string(f.activeKey())))
			require.NoError(t, f.g.authorize(f.x, id, []byte("synthetic-full-authorize")))
			want = qualGASVectorBytes(t, qualFA01ProtectedGASExecutable)
			require.Equal(t, want, qualRegistryValue(t, f.s, string(key)))
			if status == "executable" {
				root = f.commit(t)
				require.NoError(t, f.s.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
				f.reopen(t, f.s)
				require.NoError(t, f.g.authorize(f.x, id, []byte("synthetic-full-authorize")))
			}
			r, _, stored, err = f.g.load(id)
			require.NoError(t, err)
			require.True(t, r.protected)
			require.Equal(t, want, stored)
		})
	}
}

// FA-01 RT-03 uses the existing EXPERIMENTAL fixtures and synthetic hosts.
// These checks grant no native canonicality, profile or runtime admission.
// D-26: Part A 6.1 requires the exact final predecessor at stage and promotion.
func TestQualFA01RecordsPredecessor(t *testing.T) {
	t.Run("empty_slot_wrong_predecessor", func(t *testing.T) {
		f := qualPendingFinalNew(t)
		f.c.predecessor = bytes.Repeat([]byte{9}, 32)
		f.h.expected = qualRecordFrame(f.c.key, make([]byte, 8), f.c.predecessor, f.c.body, f.c.origin)
		require.ErrorIs(t, f.r.stage(f.c), errPendingFinal)
		require.Empty(t, qualRegistryValue(t, f.s, string(f.pendingKey)))
		require.Empty(t, qualRegistryValue(t, f.s, string(f.itemKey)))
		require.Zero(t, f.h.initializations)
	})
	t.Run("final_changed_after_stage", func(t *testing.T) {
		f := qualPendingFinalNew(t)
		require.NoError(t, f.r.stage(f.c))
		other := qualRecordFrame(f.c.key, make([]byte, 8), nil, f.c.origin, f.c.body)
		qualRecordPut(t, f.s, f.finalKey, other)
		require.ErrorIs(t, f.promote(), errPendingFinal)
		require.Equal(t, other, qualRegistryValue(t, f.s, string(f.finalKey)))
		f.stagedWithFinal(t)
		require.Zero(t, f.h.observations)
	})
}

func (f *qualPendingFinalFixture) stagedWithFinal(t *testing.T) {
	t.Helper()
	require.Equal(t, f.encoded, qualRegistryValue(t, f.s, string(f.pendingKey)))
	require.Equal(t, f.digest, qualRegistryValue(t, f.s, string(f.itemKey)))
}

// D-28: the required-set hash is independently rebuilt for every shard list;
// a stale hash must not mask membership/order checks (Part A E.17.3).
func TestQualFA01RecordsRequiredShardSet(t *testing.T) {
	for name, shards := range map[string][]uint32{
		"control": {0, 1, 2}, "duplicate": {0, 0, 2},
		"descending": {1, 0, 2}, "metachain": {0, 1, core.MetachainShardId},
	} {
		t.Run(name, func(t *testing.T) {
			f := qualConvergenceNew(t, 3)
			c := f.tr
			c.shards = shards
			ids := make([][]byte, len(shards))
			for i, shard := range shards {
				ids[i] = binary.BigEndian.AppendUint32(nil, shard)
			}
			set := qualRecordFrame(ids...)
			c.requiredSet = blake2b.NewBlake2b().Compute(string(set))
			f.host.binding = qualRecordFrame([]byte("CEB_CURRENTIZATION"), c.action, c.digest,
				[]byte("CURRENT_ACK"), c.token, binary.BigEndian.AppendUint64(nil, c.version),
				c.target, c.dependencies, c.requiredSet, set)
			if name == "control" {
				require.NoError(t, f.records.create(c))
				require.NotEmpty(t, qualRegistryValue(t, f.store, string(f.key)))
				return
			}
			require.ErrorIs(t, f.records.create(c), errConvergence)
			require.Zero(t, f.host.verifyCalls)
			require.Empty(t, qualRegistryValue(t, f.store, string(f.key)))
		})
	}
}

type qualFA01ReferenceHost struct {
	*qualCurrentLocalHost
	observed []currentLocalReference
}

func (h *qualFA01ReferenceHost) VerifyDependency(ref currentLocalReference, material []byte) error {
	h.observed = append(h.observed, currentLocalReference{
		bytes.Clone(ref.kind), bytes.Clone(ref.id), bytes.Clone(ref.version), bytes.Clone(ref.hash),
	})
	return h.qualCurrentLocalHost.VerifyDependency(ref, material)
}

// D-29 T22-11: decoder-owned nested buffers must be frozen before callbacks.
func TestQualFA01RecordsDependencyReferenceOwnership(t *testing.T) {
	for _, field := range []string{"kind", "id", "version", "hash"} {
		t.Run(field, func(t *testing.T) {
			f := qualCurrentLocalNew(t)
			ref := f.host.refs[1]
			want := currentLocalReference{bytes.Clone(ref.kind), bytes.Clone(ref.id), bytes.Clone(ref.version), bytes.Clone(ref.hash)}
			h := &qualFA01ReferenceHost{qualCurrentLocalHost: f.host}
			f.r.host = h
			f.host.hooks["dependency"] = func() {
				if f.host.calls["dependency"] != 1 {
					return
				}
				ref := f.host.refs[1]
				switch field {
				case "kind":
					ref.kind[0] ^= 1
				case "id":
					ref.id[0] ^= 1
				case "version":
					ref.version[0] ^= 1
				case "hash":
					ref.hash[0] ^= 1
				}
			}
			_, err := f.resolve()
			require.NoError(t, err)
			require.Len(t, h.observed, len(f.host.refs))
			require.Equal(t, want, h.observed[1], "later verifier must see the original complete reference")
		})
	}
}

func TestQualFA01RecordsDependencyBackstops(t *testing.T) {
	t.Run("absent_read", func(t *testing.T) {
		f := qualCurrentLocalNew(t)
		qualRecordPut(t, f.store, f.keys[0], nil)
		_, err := f.r.read(f.keys[0])
		require.ErrorIs(t, err, errCurrentLocalDependency)
	})
	t.Run("different_key_same_material", func(t *testing.T) {
		f := qualCurrentLocalNew(t)
		v, err := f.resolve()
		require.NoError(t, err)
		// Change only a retained key, leaving every material byte unchanged.
		v.keys[2][0] ^= 1
		require.ErrorIs(t, f.r.revalidate(v), errCurrentLocalDependency)
	})
}

func TestQualFA01RecordsPendingItemBackstops(t *testing.T) {
	t.Run("promoted_with_live_item", func(t *testing.T) {
		f := qualPendingFinalNew(t)
		require.NoError(t, f.r.stage(f.c))
		require.NoError(t, f.promote())
		qualRecordPut(t, f.s, f.itemKey, f.digest)
		require.ErrorIs(t, f.promote(), errPendingFinal)
		require.Equal(t, f.digest, qualRegistryValue(t, f.s, string(f.itemKey)))
		require.Equal(t, 1, f.h.observations)
	})
	t.Run("orphan_before_initialize", func(t *testing.T) {
		f := qualPendingFinalNew(t)
		qualRecordPut(t, f.s, f.itemKey, f.digest)
		require.ErrorIs(t, f.r.stage(f.c), errPendingFinal)
		// A later post-initialization check cannot replace the early refusal.
		require.Zero(t, f.h.initializations)
		require.Empty(t, qualRegistryValue(t, f.s, "fixture/T23/nonce"))
	})
}

func TestQualFA01RecordsConvergenceBackstops(t *testing.T) {
	t.Run("complete_missing_acks", func(t *testing.T) {
		f := qualConvergenceNew(t, 3)
		value, _ := f.expected("COMPLETE")
		qualRecordPut(t, f.store, f.key, value)
		_, err := f.records.load(f.key, f.binding, len(f.tr.shards))
		require.ErrorIs(t, err, errConvergence)
	})
	t.Run("out_of_set_before_host", func(t *testing.T) {
		f := qualConvergenceNew(t, 3)
		f.create(t)
		calls := f.host.verifyCalls
		// Bounded denial prevents the missing-index mutant from reaching an
		// array panic. The assertion measures forbidden verifier invocation.
		f.host.faults["transition"] = errConvergence
		require.ErrorIs(t, f.records.acknowledge(f.tr, 3, f.local[0], []byte("synthetic-S-R-H-M-B-proof")), errConvergence)
		require.Equal(t, calls, f.host.verifyCalls)
		require.Zero(t, f.host.ackCalls)
		f.assert(t, "PENDING")
	})
}

// Independent Python category-01 vectors from T39_GAS_record_vectors_05.json.
const qualFA01ProtectedGASProposed = "0aa1010a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e636965730a2033ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b0a0850524f504f5345440a01010a0800000000000000000a0800000000000000000a00"
const qualFA01ProtectedGASExecutable = "0aa1010a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e636965730a2033ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b0a0a45584543555441424c450a01010a0800000000000000000a0800000000000000000a00"
