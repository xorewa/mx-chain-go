package drwa

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

type qualRegistryTransportFixture struct {
	reader  *ResultAccountReader
	anchor  *metaRegistryAnchor
	count   AccountItemWitness
	members []registryMemberWitness
	limit   int
}

// Count and membership bytes are literal independent vectors, not encoded by
// the transport. Roots/proofs come from a real native committed account store.
// Candidate selection uses the real native ancestry validator from the earlier
// context fixture. There is no claimed native network/finality validation.
func qualRegistryTransport(t *testing.T, auto bool, count []byte, marker []byte, overrideIDs ...[]byte) *qualRegistryTransportFixture {
	return qualRegistryTransportAtLocus(t, auto, count, marker, false, overrideIDs...)
}

func qualRegistryTransportAtLocus(t *testing.T, auto bool, count []byte, marker []byte, localWriter bool, overrideIDs ...[]byte) *qualRegistryTransportFixture {
	t.Helper()
	f := qualNativeReaderFixture(t, auto, 1)
	a, err := f.adb.LoadAccount(bytes.Clone(core.SystemAccountAddress))
	require.NoError(t, err)
	u := a.(state.UserAccountHandler)
	require.NoError(t, u.SaveKeyValue([]byte("ELRONDDRWA@registry@count"), count))
	ids := [][]byte{[]byte("AAA-abcdef"), []byte("BBB-123456")}
	if bytes.Equal(count, []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
		ids = nil
	}
	if len(overrideIDs) != 0 {
		ids = overrideIDs
	}
	if !localWriter {
		for _, id := range ids {
			require.NoError(t, u.SaveKeyValue(append([]byte("ELRONDDRWA@registry@member@"), id...), marker))
		}
	}
	require.NoError(t, f.adb.SaveAccount(u))
	if localWriter {
		s, e := newProtectedState(f.adb)
		require.NoError(t, e)
		for _, id := range ids {
			require.NoError(t, s.materializeMembership(id))
		}
	}
	root, err := f.adb.Commit()
	require.NoError(t, err)
	// A fresh native cache is independent of the producing account store.
	r, err := NewResultAccountReader(qualReaderArgs(auto))
	require.NoError(t, err)
	c := qualNativeMetaContext(t)
	c.references[1].LastExecutionResult.ExecutionResult.BaseExecutionResult.RootHash = bytes.Clone(root)
	// Retain the authenticated native last result in a later header without a
	// new result-list entry. The ordinary H/S reader cannot use that empty list.
	c.references[1].ExecutionResults = nil
	c.references[1].LastExecutionResult = c.references[0].LastExecutionResult
	c.references[0].LastExecutionResult.ExecutionResult.BaseExecutionResult.RootHash = bytes.Clone(root)
	b, err := c.c.marshaller.Marshal(c.references[0])
	require.NoError(t, err)
	c.references[1].PrevHash = c.c.hasher.Compute(string(b))
	c.encode(t)
	anchor, err := c.read()
	require.NoError(t, err)
	item := func(key []byte) AccountItemWitness {
		accountProof, _, e := f.tr.GetProof(core.SystemAccountAddress)
		require.NoError(t, e)
		a, e := f.adb.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, e)
		dataKey := key
		if auto {
			dataKey = f.args.Hasher.Compute(string(key))
		}
		dataProof, _, e := a.(state.UserAccountHandler).DataTrie().(common.Trie).GetProof(dataKey)
		require.NoError(t, e)
		return AccountItemWitness{AccountProof: accountProof, DataProof: dataProof}
	}
	q := &qualRegistryTransportFixture{reader: r, anchor: anchor, count: item([]byte("ELRONDDRWA@registry@count"))}
	prefix := []byte("ELRONDDRWA@registry@member@")
	if localWriter {
		prefix = []byte("ELRONDDRWA@membership@")
	}
	for _, id := range ids {
		q.members = append(q.members, registryMemberWitness{tokenID: bytes.Clone(id), proof: item(append(bytes.Clone(prefix), id...))})
	}
	witnesses := []AccountItemWitness{q.count}
	for _, member := range q.members {
		witnesses = append(witnesses, member.proof)
	}
	for _, w := range witnesses {
		for _, nodes := range [][][]byte{w.AccountProof, w.DataProof} {
			for _, node := range nodes {
				q.limit += len(node)
			}
		}
	}
	return q
}

func TestQualDRWARegistryTransport(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprintf("auto_%t", auto), func(t *testing.T) {
			for _, name := range []string{"valid", "reordered", "duplicate", "missing_member", "extra_member", "missing_anchor", "missing_candidate", "missing_meta", "missing_executed", "missing_root", "wrong_root",
				"count_over_cap", "member_over_cap", "member_over_cap_before_proof", "malformed_count", "wrong_marker", "long_marker", "wrong_member", "invalid_identifier", "wrong_account_proof", "wrong_data_proof", "missing_account_proof", "missing_data_proof", "empty_node", "aggregate_budget", "transport_H", "transport_S", "zero_count", "huge_count"} {
				t.Run(name, func(t *testing.T) {
					count := []byte{0, 0, 0, 0, 0, 0, 0, 2}
					marker := []byte{1}
					if name == "malformed_count" {
						count = []byte{2}
					}
					if name == "wrong_marker" {
						marker = []byte{2}
					}
					if name == "long_marker" {
						marker = []byte{1, 1}
					}
					if name == "zero_count" {
						count = []byte{0, 0, 0, 0, 0, 0, 0, 0}
					}
					if name == "huge_count" {
						count = bytes.Repeat([]byte{0xff}, 8)
					}
					var overrides [][]byte
					if name == "invalid_identifier" {
						overrides = [][]byte{bytes.Repeat([]byte("A"), 4096), []byte("BBB-123456")}
					}
					f := qualRegistryTransport(t, auto, count, marker, overrides...)
					cap := uint64(2)
					switch name {
					case "reordered":
						f.members[0], f.members[1] = f.members[1], f.members[0]
					case "duplicate":
						f.members[1] = f.members[0]
					case "missing_member":
						f.members = f.members[:1]
					case "extra_member":
						f.members = append(f.members, f.members[0])
						cap = 3
					case "missing_anchor":
						f.anchor = nil
					case "missing_candidate":
						f.anchor.candidateHash = nil
					case "missing_meta":
						f.anchor.metaHash = nil
					case "missing_executed":
						f.anchor.executedHash = nil
					case "missing_root":
						f.anchor.root = nil
					case "wrong_root":
						f.anchor.root[0] ^= 1
					case "count_over_cap":
						cap = 1
						f.members = f.members[:1]
					case "member_over_cap":
						cap = 1
					case "member_over_cap_before_proof":
						cap = 1
						f.count.DataProof = nil
					case "wrong_member":
						f.members[0].tokenID = []byte("CCC-abcdef")
					case "wrong_account_proof":
						_, e := f.reader.readRegistryItem(f.anchor, []byte("ELRONDDRWA@registry@count"), f.count, f.limit)
						require.NoError(t, e)
						f.count.AccountProof[0][0] ^= 1
					case "wrong_data_proof":
						_, e := f.reader.readRegistryItem(f.anchor, []byte("ELRONDDRWA@registry@member@BBB-123456"), f.members[1].proof, f.limit)
						require.NoError(t, e)
						f.members[1].proof.DataProof[0][0] ^= 1
					case "missing_account_proof":
						f.count.AccountProof = nil
					case "missing_data_proof":
						f.members[1].proof.DataProof = nil
					case "empty_node":
						f.count.AccountProof[0] = nil
					case "aggregate_budget":
						f.limit--
					case "transport_H":
						f.count.Header = []byte("untrusted header")
					case "transport_S":
						f.count.ExecutedHeader = []byte("untrusted execution")
					case "zero_count":
						f.members = nil
					}
					tr, err := newRegistryTransport(f.reader, cap, f.limit)
					require.NoError(t, err)
					view, err := tr.reconstruct(f.anchor, f.count, f.members)
					if name == "valid" || name == "reordered" || name == "zero_count" {
						require.NoError(t, err)
						require.Len(t, view.members, len(f.members))
						for _, id := range []string{"AAA-abcdef", "BBB-123456"} {
							_, ok := view.members[id]
							require.Equal(t, name != "zero_count", ok)
						}
						for _, pair := range [][2][]byte{{f.anchor.root, view.anchor.root}, {f.anchor.candidateHash, view.anchor.candidateHash},
							{f.anchor.metaHash, view.anchor.metaHash}, {f.anchor.executedHash, view.anchor.executedHash}} {
							pair[0][0] ^= 1
							require.NotEqual(t, pair[0], pair[1])
						}
						if name != "zero_count" {
							f.members[0].tokenID[0] ^= 1
							_, ok := view.members["AAA-abcdef"]
							require.True(t, ok)
						}
					} else {
						require.Error(t, err)
						require.Nil(t, view)
						if name == "member_over_cap_before_proof" {
							require.Equal(t, errInvalidRegistryTransport, err)
						}
					}
				})
			}
		})
	}
}

// RT-01 counterexample: even with an authenticated count matching cardinality,
// native shard-local writes on the same account/root cannot supply metachain
// registry entries. Native proofs authenticate the old local domain exactly;
// the production transport derives the disjoint registry domain itself.
func TestQualDRWARegistryTransportLocalWriter(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprintf("auto_%t", auto), func(t *testing.T) {
			f := qualRegistryTransportAtLocus(t, auto, []byte{0, 0, 0, 0, 0, 0, 0, 2}, []byte{1}, true)
			tr, err := newRegistryTransport(f.reader, 2, f.limit)
			require.NoError(t, err)
			view, err := tr.reconstruct(f.anchor, f.count, f.members)
			require.Error(t, err)
			require.Nil(t, view)
		})
	}
}

func TestQualDRWARegistryTransportConcurrent(t *testing.T) {
	f := qualRegistryTransport(t, false, []byte{0, 0, 0, 0, 0, 0, 0, 2}, []byte{1})
	tr, err := newRegistryTransport(f.reader, 2, f.limit)
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			view, e := tr.reconstruct(f.anchor, f.count, f.members)
			require.NoError(t, e)
			if view != nil {
				require.Len(t, view.members, 2)
			}
		}()
	}
	wg.Wait()
}

func TestQualDRWARegistryTransportDependencies(t *testing.T) {
	f := qualRegistryTransport(t, false, []byte{0, 0, 0, 0, 0, 0, 0, 2}, []byte{1})
	for _, name := range []string{"reader", "budget"} {
		t.Run(name, func(t *testing.T) {
			r, limit := f.reader, f.limit
			if name == "reader" {
				r = nil
			} else {
				limit = 0
			}
			tr, err := newRegistryTransport(r, 2, limit)
			require.Error(t, err)
			require.Nil(t, tr)
		})
	}
}

func TestQualDRWARegistryItemGuard(t *testing.T) {
	for _, name := range []string{"nil_anchor", "candidate", "meta", "executed", "root", "key", "H", "S"} {
		t.Run(name, func(t *testing.T) {
			f := qualRegistryTransport(t, false, []byte{0, 0, 0, 0, 0, 0, 0, 2}, []byte{1})
			key := []byte("ELRONDDRWA@registry@count")
			switch name {
			case "nil_anchor":
				f.anchor = nil
			case "candidate":
				f.anchor.candidateHash = nil
			case "meta":
				f.anchor.metaHash = nil
			case "executed":
				f.anchor.executedHash = nil
			case "root":
				f.anchor.root = nil
			case "key":
				key = nil
			case "H":
				f.count.Header = []byte("untrusted")
			case "S":
				f.count.ExecutedHeader = []byte("untrusted")
			}
			value, err := f.reader.readRegistryItem(f.anchor, key, f.count, f.limit)
			require.Error(t, err)
			require.Nil(t, value)
		})
	}
}

func TestQualDRWARegistryProofBudget(t *testing.T) {
	for _, name := range []string{"valid", "empty_account", "empty_data", "empty_account_node", "empty_data_node", "negative", "minimum", "aggregate"} {
		t.Run(name, func(t *testing.T) {
			w := AccountItemWitness{AccountProof: [][]byte{{1}}, DataProof: [][]byte{{2, 3}}}
			limit := 3
			switch name {
			case "empty_account":
				w.AccountProof = nil
			case "empty_data":
				w.DataProof = nil
			case "empty_account_node":
				w.AccountProof[0] = nil
			case "empty_data_node":
				w.DataProof[0] = nil
			case "negative":
				limit = -1
			case "minimum":
				limit = -int(^uint(0)>>1) - 1
			case "aggregate":
				limit = 2
			}
			n, err := registryProofBytes(w, limit)
			if name == "valid" {
				require.NoError(t, err)
				require.Equal(t, 3, n)
			} else {
				require.Error(t, err)
				require.Zero(t, n)
			}
		})
	}
}
