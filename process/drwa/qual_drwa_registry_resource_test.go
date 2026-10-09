package drwa

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualRegistryResourceAccountReads struct {
	state.AccountsAdapter
	reads int
}

func (a *qualRegistryResourceAccountReads) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	a.reads++
	return a.AccountsAdapter.GetExistingAccount(address)
}

// T09-M10: exploratory native local materialization measurements. The projection
// is synthetic and deliberately replaces the two-member transport fixture; its
// cardinalities are not max_ever_regulated_tokens proposals. Native AccountsDB,
// trie, journal and commits remain real. This does not prove canonical transport,
// physical database size, whole-profile capacity, node restart or AN-03 ingress.
func TestQualDRWARegistryResourceSamples(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, count := range []int{1, 64, 1024} {
			t.Run(fmt.Sprintf("auto_%t/n_%d", auto, count), func(t *testing.T) {
				m, view, db, adapter := qualRegistryMaterialization(t, auto)
				observed := &qualRegistryResourceAccountReads{AccountsAdapter: adapter}
				m.state.accounts = observed
				view.members = make(map[string]struct{}, count)
				for i := 0; i < count; i++ {
					view.members[fmt.Sprintf("QUAL-%06x", i)] = struct{}{}
				}
				candidate := bytes.Clone(view.anchor.candidateHash)
				first := []byte("QUAL-000000")
				last := []byte(fmt.Sprintf("QUAL-%06x", count-1))
				absent := []byte("OTHER-ffffff")
				present, err := m.classify(candidate, absent)
				require.Error(t, err, "unprepared does not authorize absence")
				require.False(t, present)
				before, err := db.RootHash()
				require.NoError(t, err)
				started := time.Now() // measurement only; never a policy clock
				err = m.prepare(context.Background(), view)
				populateNs := time.Since(started).Nanoseconds()
				require.NoError(t, err)
				journalEntries := db.JournalLen()
				require.Positive(t, journalEntries)
				for _, id := range [][]byte{first, last} {
					present, err = m.classify(candidate, id)
					require.NoError(t, err)
					require.True(t, present)
				}

				// The existing qualification adapter rejects every attempted
				// GetExistingAccount. A prepared map must not need that read.
				adapter.readError = errors.New("account read prohibited during prepared lookup")
				readsBeforeLookup := observed.reads
				valid := true
				lookup := func() {
					got, e := m.classify(candidate, first)
					valid = valid && got && e == nil
					got, e = m.classify(candidate, absent)
					valid = valid && !got && e == nil
				}
				const pairs = 1000
				allocs := testing.AllocsPerRun(pairs, lookup)
				started = time.Now()
				for i := 0; i < pairs; i++ {
					lookup()
				}
				lookupNs := time.Since(started).Nanoseconds()
				require.True(t, valid, "every measured lookup preserves its independent expected result")
				require.Equal(t, readsBeforeLookup, observed.reads, "prepared lookup attempts no GetExistingAccount, even if a read error could be ignored")
				wrong := bytes.Clone(candidate)
				wrong[0] ^= 1
				present, err = m.classify(wrong, absent)
				require.Error(t, err, "wrong candidate does not authorize absence")
				require.False(t, present)
				adapter.readError = nil
				roots, _, err := m.owner.Commit()
				require.NoError(t, err)
				require.Len(t, roots, 1)
				require.NotEqual(t, before, roots[0])
				require.Zero(t, db.JournalLen())
				present, err = m.classify(candidate, absent)
				require.ErrorIs(t, err, ErrExecutionClosed)
				require.False(t, present)

				account, err := db.GetExistingAccount(core.SystemAccountAddress)
				require.NoError(t, err)
				u := account.(state.UserAccountHandler)
				read := func(key []byte) []byte {
					value, _, e := u.RetrieveValue(key)
					require.NoError(t, e)
					return value
				}
				// Independent literal experimental key layout; key+value byte
				// lengths exclude trie encoding, nodes, heap and storage overhead.
				registryKey := []byte("ELRONDDRWA@registry@count")
				countKey := []byte("ELRONDDRWA@membershipIndex@count")
				require.Equal(t, make([]byte, 8), read(registryKey), "local reconstruction never registers a token")
				encodedCount := make([]byte, 8)
				binary.BigEndian.PutUint64(encodedCount, uint64(count))
				require.Equal(t, encodedCount, read(countKey))
				payloadBytes := len(registryKey) + 8 + len(countKey) + 8
				for i := 0; i < count; i++ {
					id := []byte(fmt.Sprintf("QUAL-%06x", i))
					markerKey := append([]byte("ELRONDDRWA@membership@"), id...)
					ordinalKey := append([]byte("ELRONDDRWA@membershipIndex@entry@"), make([]byte, 8)...)
					binary.BigEndian.PutUint64(ordinalKey[len(ordinalKey)-8:], uint64(i))
					require.Equal(t, []byte{1}, read(markerKey))
					require.Equal(t, id, read(ordinalKey))
					payloadBytes += len(markerKey) + 1 + len(ordinalKey) + len(id)
				}

				// A second isolated reconstruction exercises the full existing
				// ordinal set. Duplicate saves must preserve the committed root
				// and journal. This is local persistence, not node restart.
				second, err := newRegistryMaterialization(adapter, &view.anchor)
				require.NoError(t, err)
				started = time.Now()
				err = second.prepare(context.Background(), view)
				reconstructNs := time.Since(started).Nanoseconds()
				require.NoError(t, err)
				require.Zero(t, db.JournalLen())
				after, err := db.RootHash()
				require.NoError(t, err)
				require.Equal(t, roots[0], after)
				present, err = second.classify(candidate, last)
				require.NoError(t, err)
				require.True(t, present)
				require.NoError(t, second.abort())
				present, err = second.classify(candidate, absent)
				require.ErrorIs(t, err, ErrExecutionClosed)
				require.False(t, present)

				measurement := struct {
					AutoBalanceDataTries bool    `json:"auto_balance_data_tries"`
					Members              int     `json:"members"`
					PopulateNs           int64   `json:"populate_ns"`
					ReconstructNs        int64   `json:"reconstruct_existing_ns"`
					LookupPairs          int     `json:"lookup_pairs"`
					LookupNs             int64   `json:"lookup_pairs_total_ns"`
					AllocsPerPair        float64 `json:"lookup_allocs_per_pair"`
					PayloadBytes         int     `json:"experimental_key_value_bytes"`
					JournalEntries       int     `json:"populate_journal_entries"`
				}{auto, count, populateNs, reconstructNs, pairs, lookupNs, allocs, payloadBytes, journalEntries}
				raw, err := json.Marshal(measurement)
				require.NoError(t, err)
				t.Logf("T09_RESOURCE_SAMPLE %s", raw)
			})
		}
	}
}
