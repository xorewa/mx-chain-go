package drwa

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/stretchr/testify/require"
)

// T18 M5: storage-pressure observations, separate from metadata correctness.
// The existing T23 host is explicitly synthetic: it proves no class admission,
// real holder initialization, funding, canonical import or native route.
// Native AccountsDB/trie/journal/commit/recreation remain real. Disabled pruning
// retains historical trie nodes; those bytes are not a production database size.
func TestQualDRWAHeadWritePressureSamples(t *testing.T) {
	for _, count := range []int{1, 64, 1024} {
		t.Run(fmt.Sprintf("heads_%d", count), func(t *testing.T) {
			f := qualPendingFinalNew(t)
			set := func(key []byte, version uint64, predecessor []byte) {
				f.c = pendingFinalCandidate{key: bytes.Clone(key), version: version,
					predecessor: bytes.Clone(predecessor), body: bytes.Repeat([]byte{0x51}, 32),
					origin: binary.BigEndian.AppendUint64(bytes.Repeat([]byte{0x61}, 24), version)}
				f.encoded = qualRecordFrame(f.c.key, binary.BigEndian.AppendUint64(nil, version),
					f.c.predecessor, f.c.body, f.c.origin)
				f.digest = blake2b.NewBlake2b().Compute(string(f.encoded))
				f.h.expected = bytes.Clone(f.encoded)
			}
			commit := func() []byte {
				roots, _, err := f.o.Commit()
				require.NoError(t, err)
				require.Len(t, roots, 1)
				require.Zero(t, f.s.JournalLen())
				f.reopen(t)
				return roots[0]
			}
			backingSize := func() (nodes, size int) {
				f.s.backing.RangeKeys(func(key, value []byte) bool {
					nodes++
					size += len(key) + len(value)
					return true
				})
				return
			}
			beforeNodes, beforeBytes := backingSize()
			heldKey := []byte("ELIGIBILITY/TOKEN-abcdef/held-00000000")
			set(heldKey, 0, nil)
			held, heldEncoded := f.c, bytes.Clone(f.encoded)
			require.NoError(t, f.r.stage(held))
			commit()

			// Count actual backing I/O through existing memory-store observers;
			// they delegate native storage unchanged. No per-write scan is added.
			var reads, writes, writtenBytes atomic.Int64
			f.s.backing.GetCalledNoReturn = func([]byte) { reads.Add(1) }
			f.s.backing.PutCalled = func(key, value []byte) error {
				writes.Add(1)
				writtenBytes.Add(int64(len(key) + len(value)))
				return nil
			}
			logicalBytes := 0
			started := time.Now() // observation only, never DRWA policy time
			for i := 0; i < count; i++ {
				key := []byte(fmt.Sprintf("ELIGIBILITY/TOKEN-abcdef/holder-%08x", i))
				set(key, 0, nil)
				require.NoError(t, f.r.stage(f.c))
				journal := f.s.JournalLen()
				initializations := f.h.initializations
				require.NoError(t, f.r.stage(f.c))
				require.Equal(t, initializations, f.h.initializations)
				require.Equal(t, journal, f.s.JournalLen())

				// An otherwise admissible different body must not displace the
				// pending successor or initialize a second record under pressure.
				competing := f.c
				competing.body = bytes.Repeat([]byte{0x52}, 32)
				f.h.expected = qualRecordFrame(competing.key, make([]byte, 8), nil,
					competing.body, competing.origin)
				root, err := f.s.RootHash()
				require.NoError(t, err)
				require.ErrorIs(t, f.r.stage(competing), errPendingFinal)
				after, err := f.s.RootHash()
				require.NoError(t, err)
				require.Equal(t, root, after)
				require.Equal(t, journal, f.s.JournalLen())
				require.Equal(t, initializations, f.h.initializations)
				f.h.expected = bytes.Clone(f.encoded)
				require.NoError(t, f.promote())
				observations := f.h.observations
				journal = f.s.JournalLen()
				require.NoError(t, f.promote())
				require.Equal(t, observations, f.h.observations)
				require.Equal(t, journal, f.s.JournalLen())
				commit()
				finalKey := append([]byte(pendingFinalPrefix+"final@"), qualRecordFrame(key)...)
				logicalBytes += len(finalKey) + len(f.encoded)
			}
			populateNs := time.Since(started).Nanoseconds()
			populatedNodes, populatedBytes := backingSize()
			require.Greater(t, populatedNodes, beforeNodes)
			require.Greater(t, populatedBytes, beforeBytes)
			populateReads, populateWrites := reads.Load(), writes.Load()
			populateWrittenBytes := writtenBytes.Load()

			// Repeated replacement grows retained historical trie storage, but
			// final/ remains one current head. No deletion/pruning is credited.
			key := []byte("ELIGIBILITY/TOKEN-abcdef/holder-00000000")
			set(key, 0, nil)
			firstHead := bytes.Clone(f.encoded)
			predecessor := bytes.Clone(f.digest)
			started = time.Now()
			const successors = 32
			for version := uint64(1); version <= successors; version++ {
				set(key, version, predecessor)
				require.NoError(t, f.r.stage(f.c))
				require.NoError(t, f.promote())
				commit()
				predecessor = bytes.Clone(f.digest)
			}
			churnNs := time.Since(started).Nanoseconds()
			latest, digest, err := f.r.final(key)
			require.NoError(t, err)
			require.Equal(t, f.encoded, latest)
			require.Equal(t, f.digest, digest)
			require.NotEqual(t, firstHead, latest)
			// Successor format adds one retained predecessor, not one active
			// record for every update. The same fixed-size slot is replaced.
			logicalBytes += len(latest) - len(firstHead)
			for i := 1; i < count; i++ {
				other := []byte(fmt.Sprintf("ELIGIBILITY/TOKEN-abcdef/holder-%08x", i))
				value, _, err := f.r.final(other)
				require.NoError(t, err)
				want := qualRecordFrame(other, make([]byte, 8), nil, bytes.Repeat([]byte{0x51}, 32),
					binary.BigEndian.AppendUint64(bytes.Repeat([]byte{0x61}, 24), 0))
				require.Equal(t, want, value)
			}

			root, err := f.s.RootHash()
			require.NoError(t, err)
			require.NoError(t, f.s.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
			f.reopen(t)
			f.c, f.encoded, f.h.expected = held, heldEncoded, bytes.Clone(heldEncoded)
			final, _, err := f.r.final(heldKey)
			require.NoError(t, err)
			require.Empty(t, final, "unpromoted item is never a final head")
			require.NoError(t, f.promote(), "accepted pending fixture remains serviceable")
			root = commit()
			require.NoError(t, f.s.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
			f.reopen(t)
			final, _, err = f.r.final(heldKey)
			require.NoError(t, err)
			require.Equal(t, heldEncoded, final)
			require.Equal(t, count+1+successors, f.h.initializations)
			require.Equal(t, count+1+successors, f.h.observations)
			afterNodes, afterBytes := backingSize()
			measurement := map[string]interface{}{
				"heads": count, "successors": successors, "auto_balance_data_tries": false,
				"populate_ns": populateNs, "churn_ns": churnNs,
				"current_sampled_head_key_value_bytes": logicalBytes,
				"backing_before_nodes":                 beforeNodes, "backing_before_key_value_bytes": beforeBytes,
				"backing_populated_nodes": populatedNodes, "backing_populated_key_value_bytes": populatedBytes,
				"backing_after_nodes": afterNodes, "backing_after_key_value_bytes": afterBytes,
				"populate_backing_reads": populateReads, "populate_backing_writes": populateWrites,
				"populate_backing_written_key_value_bytes": populateWrittenBytes,
				"total_backing_reads":                      reads.Load(), "total_backing_writes": writes.Load(),
				"total_backing_written_key_value_bytes": writtenBytes.Load(),
				"go_version":                            runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH,
				"gomaxprocs": runtime.GOMAXPROCS(0), "held_pending_records": 1,
				"synthetic_host": true, "deployment_capacity_acceptance": false,
			}
			raw, err := json.Marshal(measurement)
			require.NoError(t, err)
			t.Logf("T18_HEAD_PRESSURE_SAMPLE %s", raw)
		})
	}
}
