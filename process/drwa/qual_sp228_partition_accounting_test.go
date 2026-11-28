package drwa

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/batch"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/stretchr/testify/require"
)

// Independent expected representation uses the native Batch serializer, not
// the arithmetic used by the profile constructor. All sizes are small,
// synthetic shape observations, not approved profile limits.
func TestQualSP228CapacityRepresentationModel(t *testing.T) {
	cases := 0
	for _, hashSize := range []int{16, 32, 127, 128} {
		for _, count := range []int{1, 2, 3, 4, 8} {
			members := make([][]byte, count)
			for i := range members {
				var err error
				id := make([]byte, hashSize)
				id[0] = byte(i)
				members[i], err = batch.New(id, []byte{byte(i % 2)}).Marshal()
				require.NoError(t, err)
			}
			nested, err := batch.New(members...).Marshal()
			require.NoError(t, err)
			encoded, err := batch.New(make([]byte, 8), make([]byte, 8), make([]byte, hashSize), nested).Marshal()
			require.NoError(t, err)
			for _, byteLimit := range []int{len(encoded) - 1, len(encoded), len(encoded) + 1} {
				want := len(encoded) <= byteLimit
				require.Equal(t, want, governedActionCapacityFits(uint64(count), uint64(hashSize), uint64(byteLimit)),
					"count=%d hash=%d bytes=%d", count, hashSize, byteLimit)
				cases++
			}
			if hashSize == 32 {
				t.Logf("synthetic %d member aggregate: %d bytes", count, len(encoded))
			}
		}
	}
	require.Equal(t, 60, cases)
}

func TestQualSP228CapacityLocalConfigurationValidation(t *testing.T) {
	f := qualGovernedActionNew(t)
	for _, tc := range []struct {
		name                       string
		total, ordinary, protected uint64
		bytes                      int
		valid                      bool
	}{
		{"independent positive parts", 4, 2, 2, 4096, true},
		{"protected-only configured part", 2, 0, 2, 4096, true},
		{"absent protected capacity", 4, 4, 0, 4096, false},
		{"inconsistent total", 4, 2, 1, 4096, false},
		{"storage representation too small", 4, 2, 2, 32, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := newGovernedActionRecords(f.s, f.o, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), tc.bytes,
				[]byte("n"), tc.total, tc.ordinary, tc.protected, f.h, qualClockSource(f.c, f.s))
			if tc.valid {
				require.NoError(t, err)
				require.NotNil(t, g)
			} else {
				require.ErrorIs(t, err, errGovernedActionRecord)
				require.Nil(t, g)
			}
		})
	}
	for _, tc := range [][3]uint64{{0, 32, 4096}, {2, 0, 4096}, {2, 32, 31}, {2, 32, ^uint64(0)}, {2, 32, 48}} {
		require.False(t, governedActionCapacityFits(tc[0], tc[1], tc[2]), fmt.Sprint(tc))
	}
}

// Benign accounting lifecycle with one ordinary and one protected fixture
// entry, both classified by the existing synthetic host. This is not native
// eligibility/funding or an operational recovery test.
func TestQualSP228PartitionAccountingAndExpiry(t *testing.T) {
	f := qualGovernedActionNew(t)
	f.initialize(t)
	ordinary := f.propose(t)
	ordinaryEnvelope := append([]byte(nil), f.h.envelope...)
	f.p.nonce++
	f.h.protected = true
	protected := f.propose(t)
	check := func(want map[string]bool) {
		members, err := f.g.members(qualRegistryValue(t, f.s, string(f.activeKey())))
		require.NoError(t, err)
		got := make(map[string]bool)
		for _, member := range members {
			got[string(member.id)] = member.protected
		}
		require.Equal(t, want, got)
	}
	both := map[string]bool{string(ordinary): false, string(protected): true}
	check(both)
	f.commit(t)
	f.s = qualSP224Reopen(t, f.s)
	f.h.store = f.s
	f.reopen(t, f.s)
	check(both)
	r, _, _, err := f.g.load(protected)
	require.NoError(t, err)
	require.Equal(t, "PROPOSED", r.status)
	require.Equal(t, 0, f.h.effects)
	f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 120)
	f.h.envelope = ordinaryEnvelope
	require.NoError(t, f.g.cleanup(f.x, ordinary, "EXPIRED", []byte("synthetic-no-irreversible-proof")))
	check(map[string]bool{string(protected): true})
	r, _, _, err = f.g.load(ordinary)
	require.NoError(t, err)
	require.Equal(t, "EXPIRED", r.status)
	f.commit(t)
	f.s = qualSP224Reopen(t, f.s)
	f.h.store = f.s
	f.reopen(t, f.s)
	check(map[string]bool{string(protected): true})
}

func TestQualSP228AbstractPartitionAccountingModel(t *testing.T) {
	f := qualGovernedActionNew(t)
	cases := 0
	for ordinary := 0; ordinary <= 2; ordinary++ {
		for protected := 0; protected <= 2; protected++ {
			// Independent expected accounting: one live identifier is one unit
			// of total capacity and exactly one unit of its recorded part.
			expected := make(map[string]bool)
			var records []governedActionMember
			for i := 0; i < ordinary+protected; i++ {
				id := make([]byte, 32)
				id[0] = byte(i + 1)
				category := i >= ordinary
				expected[string(id)] = category
				records = append(records, governedActionMember{id: id, protected: category})
			}
			encoded, err := f.g.aggregate(records)
			require.NoError(t, err)
			retained := &batch.Batch{}
			require.NoError(t, retained.Unmarshal(encoded))
			require.Len(t, retained.Data, 4)
			require.Equal(t, uint64(ordinary+protected), binary.BigEndian.Uint64(retained.Data[0]))
			require.Equal(t, uint64(ordinary), binary.BigEndian.Uint64(retained.Data[1]))
			actual, err := f.g.members(encoded)
			require.NoError(t, err)
			got := make(map[string]bool)
			for _, record := range actual {
				got[string(record.id)] = record.protected
			}
			require.Equal(t, expected, got)
			require.Len(t, actual, ordinary+protected)
			cases++
		}
	}
	require.Equal(t, 9, cases)
}

func TestQualSP228PartitionDistinctTokenAccounting(t *testing.T) {
	f := qualGovernedActionNew(t)
	f.initialize(t)
	first := f.propose(t)
	firstKey := append([]byte(nil), f.activeKey()...)
	f.p.subject = []byte("second-programme")
	f.p.token = []byte("TOKEN-123abc")
	f.initialize(t)
	f.h.protected = true
	second := f.propose(t)
	secondKey := f.activeKey()
	require.NotEqual(t, firstKey, secondKey)
	for _, tc := range []struct {
		key, id   []byte
		protected bool
	}{{firstKey, first, false}, {secondKey, second, true}} {
		members, err := f.g.members(qualRegistryValue(t, f.s, string(tc.key)))
		require.NoError(t, err)
		require.Equal(t, []governedActionMember{{id: tc.id, protected: tc.protected}}, members)
	}
}

// Pure representation benchmark; no proposal, authority, storage write or
// native effect. These small sizes describe the fixture, not release limits.
func BenchmarkQualSP228AggregateRepresentation(b *testing.B) {
	for _, count := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			g := &governedActionRecords{
				codec: &registrationRecords{marshaller: &marshal.GogoProtoMarshalizer{}, hasher: blake2b.NewBlake2b(), maxBytes: 4096},
				total: uint64(count), ordinary: uint64(count / 2), protected: uint64(count - count/2),
			}
			members := make([]governedActionMember, count)
			for i := range members {
				id := make([]byte, 32)
				id[0] = byte(i + 1)
				members[i] = governedActionMember{id: id, protected: i >= count/2}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encoded, err := g.aggregate(members)
				if err != nil {
					b.Fatal(err)
				}
				decoded, err := g.members(encoded)
				if err != nil || len(decoded) != count {
					b.Fatalf("representation: count=%d error=%v", len(decoded), err)
				}
			}
		})
	}
}
