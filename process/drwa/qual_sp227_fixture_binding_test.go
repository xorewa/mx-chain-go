package drwa

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// SP2-27 fixture identity. The roster fixture is the SP2-03 synthetic policy
// binding (programme document DRWA_SP2_Synthetic_Policy_Bindings_DRAFT.json,
// SHA-256 4f4de27fa6d64a4c710c0c8eda48abd6657e7f8db362036b5bc02338a107e746,
// 163,088 bytes) with one change: the two path values under
// owner_policy_source are written relative to the programme folder. Every
// other byte, including all sixty rosters, is the source's. The comparison
// with the source file is recorded in the SP2-27 evidence folder
// (fixture_source_check); this test pins the committed bytes and the counts
// the SP2-03 record states, so the fixture cannot drift from that record.
func TestQualSP227FixtureBoundToSP203(t *testing.T) {
	raw, err := os.ReadFile("testdata/sp2_27_synthetic_rosters.json")
	require.NoError(t, err)
	sum := sha256.Sum256(raw)
	require.Equal(t, "026537ab9760f34d89d5695a9593c533a201b1854fa948b2bc5b569e264b5cf6", hex.EncodeToString(sum[:]))
	require.Len(t, raw, 162996)

	var data struct {
		Synthetic bool     `json:"synthetic_only"`
		Revision  int      `json:"fixture_format_revision"`
		Bound     []string `json:"bound_rows"`
		Register  []string `json:"experimental_register_rows"`
		Source    struct {
			Grant        string `json:"grant"`
			LedgerSHA    string `json:"ledger_sha256"`
			AcceptedSHA  string `json:"accepted_copy_sha256"`
			AcceptedCopy string `json:"accepted_copy"`
		} `json:"owner_policy_source"`
		Programmes []struct {
			ID      string   `json:"fixture_programme_id"`
			Actors  []string `json:"function_actor_ids"`
			Rosters []string `json:"available_roster_ids"`
		} `json:"programmes"`
		Actors []struct {
			ID        string `json:"fixture_actor_id"`
			Programme string `json:"programme"`
		} `json:"function_actors"`
		Rosters []struct {
			ID        string `json:"fixture_roster_id"`
			Programme string `json:"programme"`
			Role      string `json:"role_name"`
			N         uint64 `json:"eligible_member_count"`
			Threshold uint64 `json:"configured_threshold"`
			Members   []struct {
				ID     string `json:"fixture_member_id"`
				Handle string `json:"key_handle"`
			} `json:"registered_members"`
			Standby []struct {
				ID     string `json:"fixture_member_id"`
				Handle string `json:"key_handle"`
			} `json:"unregistered_standby"`
		} `json:"programme_authority_roster_fixtures"`
		Counts struct {
			Programmes int `json:"programmes"`
			Actors     int `json:"function_actors"`
			Rosters    int `json:"rosters"`
			Members    int `json:"registered_member_handles"`
			Standby    int `json:"standby_handles"`
		} `json:"counts"`
	}
	require.NoError(t, json.Unmarshal(raw, &data))
	require.True(t, data.Synthetic)
	require.Equal(t, 1, data.Revision)
	require.Equal(t, []string{"SP2-03"}, data.Bound)
	require.Equal(t, []string{"XV-SP2-03-ROSTER", "XV-SP2-03-JURISDICTION", "XV-SP2-03-LAYOUT"}, data.Register)
	// The owner inputs the SP2-03 record names.
	require.Equal(t, "SP2-INPUTS-001", data.Source.Grant)
	require.Equal(t, "330d8f1dd16433533d0a2848d58713259068e939ca21d27f753099a74e591454", data.Source.LedgerSHA)
	require.Equal(t, "b1e6fe717860912ca75e3e08e4569abe02b70072ebf779ceadd1bd837d24ced0", data.Source.AcceptedSHA)

	// SP2-03 record: six programmes, 48 function actors, 60 role pools, each
	// with five registered members, threshold three and one standby.
	require.Equal(t, 6, data.Counts.Programmes)
	require.Equal(t, 48, data.Counts.Actors)
	require.Equal(t, 60, data.Counts.Rosters)
	require.Equal(t, 300, data.Counts.Members)
	require.Equal(t, 60, data.Counts.Standby)
	require.Len(t, data.Programmes, 6)
	require.Len(t, data.Actors, 48)
	require.Len(t, data.Rosters, 60)

	// The admission role of Part A L1262 and the nine programme roles of
	// L1325-1333, by their exact names.
	roles := []string{
		"programme-scoped Issuer/Program Admission Authority",
		"Program Administration Authority", "Supply Authority", "Compliance Decision Authority", "Financial-Crime Authority",
		"Emergency Authority", "Transfer-Authorization Authority", "Administrative-Transfer Authority",
		"Independent Reconciliation Authority", "Program Recovery Authority",
	}
	sort.Strings(roles)
	// The constitution names nine of them. Transfer-Authorization Authority has
	// no row in the adopted purpose policy and no selector in the code.
	selectors := []string{scopedIPAA, scopedPA, scopedSA, scopedCDA, scopedFCA, scopedEA, scopedATA, scopedIRA, scopedPR, "Transfer-Authorization Authority"}
	sort.Strings(selectors)
	require.Equal(t, roles, selectors)

	programmes := make(map[string][]string)
	actors := make(map[string]int)
	for _, a := range data.Actors {
		actors[a.Programme]++
	}
	handles, members := make(map[string]bool), make(map[string]bool)
	registered, standby := 0, 0
	for _, r := range data.Rosters {
		programmes[r.Programme] = append(programmes[r.Programme], r.Role)
		require.EqualValues(t, 5, r.N)
		require.EqualValues(t, 3, r.Threshold)
		require.Len(t, r.Members, 5)
		require.Len(t, r.Standby, 1)
		// D01 written out independently: the smallest t with 5t >= 3n.
		floor := uint64(0)
		for 5*floor < 3*r.N {
			floor++
		}
		require.Equal(t, floor, r.Threshold)
		require.NoError(t, validateProgrammeAuthorityThreshold(r.N, r.Threshold))
		for _, m := range r.Members {
			require.False(t, handles[m.Handle] || members[m.ID], "a member and its key handle appear once in the whole fixture")
			handles[m.Handle], members[m.ID] = true, true
			registered++
		}
		for _, m := range r.Standby {
			require.False(t, handles[m.Handle] || members[m.ID])
			handles[m.Handle], members[m.ID] = true, true
			standby++
		}
	}
	require.Equal(t, 300, registered)
	require.Equal(t, 60, standby)
	require.Len(t, programmes, 6)
	for _, p := range data.Programmes {
		got := append([]string(nil), programmes[p.ID]...)
		sort.Strings(got)
		require.Equal(t, roles, got, "each programme has each of the ten roles once")
		require.Len(t, p.Rosters, 10)
		require.Len(t, p.Actors, 8)
		require.Equal(t, 8, actors[p.ID])
	}

	// The loader the constitution tests use consumes this same file and binds
	// one generated native Ed25519 key to every handle: 300 registered, 60 standby.
	bound := qualSP227Rosters(t)
	require.Len(t, bound, 60)
	keys := make(map[string]bool)
	for i, b := range bound {
		require.Equal(t, data.Rosters[i].ID, b.ID)
		require.Equal(t, data.Rosters[i].Role, b.Role)
		require.Equal(t, data.Rosters[i].Programme, b.Programme)
		require.Len(t, b.Members, 5)
		require.Len(t, b.Standby, 1)
		for _, key := range append(append([][]byte(nil), b.Members...), b.Standby...) {
			require.Len(t, key, 32)
			require.False(t, keys[string(key)])
			keys[string(key)] = true
		}
	}
	require.Len(t, keys, 360)
}
