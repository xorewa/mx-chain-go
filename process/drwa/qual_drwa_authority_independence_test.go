package drwa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"testing"

	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
	"github.com/stretchr/testify/require"
)

// SP2-27 structural/signature experiments only, using the exact SP2-03 binding
// and its existing XV-SP2-03-ROSTER/LAYOUT fields. No fixture appoints an unknown
// purpose. Public bindings are logged BEFORE proof verification; private keys
// stay in memory. Native Sign/Verify and the existing within-set verifier own
// cryptography. This file supplies no canonical certificate/claim/cancellation.
type qualSP227Member struct {
	ID     string `json:"fixture_member_id"`
	Handle string `json:"key_handle"`
}

type qualSP227Roster struct {
	ID        string            `json:"fixture_roster_id"`
	Programme string            `json:"programme"`
	Role      string            `json:"role_name"`
	N         int               `json:"eligible_member_count"`
	Threshold uint64            `json:"configured_threshold"`
	Members   []qualSP227Member `json:"registered_members"`
	Standby   []qualSP227Member `json:"unregistered_standby"`
}

type qualSP227Binding struct {
	ID, Programme, Role string
	Members             [][]byte
	Private             []crypto.PrivateKey
	Standby             [][]byte
	StandbyPrivate      []crypto.PrivateKey
	Threshold           uint64
}

func qualSP227Rosters(t *testing.T) []qualSP227Binding {
	t.Helper()
	raw, err := os.ReadFile("testdata/sp2_27_synthetic_rosters.json")
	require.NoError(t, err)
	var data struct {
		Synthetic bool `json:"synthetic_only"`
		Counts    struct {
			Rosters int `json:"rosters"`
			Members int `json:"registered_member_handles"`
		} `json:"counts"`
		Rosters []qualSP227Roster `json:"programme_authority_roster_fixtures"`
	}
	require.NoError(t, json.Unmarshal(raw, &data))
	require.True(t, data.Synthetic)
	require.Len(t, data.Rosters, data.Counts.Rosters)
	keygen := signing.NewKeyGenerator(ed25519.NewEd25519())
	bindings := make([]qualSP227Binding, len(data.Rosters))
	seenHandles, seenPublic := make(map[string]bool), make(map[string]bool)
	memberCount := 0
	for i, roster := range data.Rosters {
		require.Len(t, roster.Members, roster.N)
		bound := qualSP227Binding{ID: roster.ID, Programme: roster.Programme, Role: roster.Role, Threshold: roster.Threshold}
		for group, members := range [][]qualSP227Member{roster.Members, roster.Standby} {
			for _, member := range members {
				require.False(t, seenHandles[member.Handle], "symbolic member appears once")
				seenHandles[member.Handle] = true
				private, public := keygen.GeneratePair()
				encoded, encodeErr := public.ToByteArray()
				require.NoError(t, encodeErr)
				require.False(t, seenPublic[string(encoded)], "all registered and standby key material is distinct")
				seenPublic[string(encoded)] = true
				// Public material only. This raw output binds the actual native
				// generation to its exact symbolic member before any oracle use.
				t.Logf("SP2-27_PUBLIC_KEY roster=%s programme=%s role=%q member=%s handle=%s standby=%t scheme=ED25519_M_OF_N public=%s",
					roster.ID, roster.Programme, roster.Role, member.ID, member.Handle, group != 0, hex.EncodeToString(encoded))
				if group == 0 {
					bound.Members = append(bound.Members, encoded)
					bound.Private = append(bound.Private, private)
					memberCount++
				} else {
					bound.Standby = append(bound.Standby, encoded)
					bound.StandbyPrivate = append(bound.StandbyPrivate, private)
				}
			}
		}
		bindings[i] = bound
	}
	require.Equal(t, data.Counts.Members, memberCount)
	return bindings
}

func TestQualSP227BoundRosters(t *testing.T) {
	bindings := qualSP227Rosters(t)
	// Existing W03 signature-only experimental bytes and reviewed bound. This
	// is deliberately not a new purpose/domain/cancellation certificate format.
	digest := []byte("W03 synthetic signature-only bytes")
	signer := &singlesig.Ed25519Signer{}
	for _, roster := range bindings {
		t.Run(roster.ID, func(t *testing.T) {
			indices := make([]uint64, roster.Threshold)
			signatures := make([][]byte, roster.Threshold)
			for i := range indices {
				indices[i] = uint64(i)
				var err error
				signatures[i], err = signer.Sign(roster.Private[i], digest)
				require.NoError(t, err)
			}
			verify := func(ids []uint64, sigs [][]byte) error {
				return verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", roster.Threshold, roster.Members,
					ids, sigs, digest, uint64(len(roster.Members)), uint64(len(digest)))
			}
			require.NoError(t, verify(indices, signatures))
			require.Error(t, verify(indices[:len(indices)-1], signatures[:len(signatures)-1]), "unavailability does not lower the denominator")
			for _, private := range roster.StandbyPrivate {
				changed := append([][]byte(nil), signatures...)
				standbySignature, err := signer.Sign(private, digest)
				require.NoError(t, err)
				changed[len(changed)-1] = standbySignature
				require.Error(t, verify(indices, changed), "unregistered standby cannot fill a registered vote")
			}
		})
	}
	// Every full-roster pair, including distinct programmes. Passing this
	// structural check supplies no undelegated scope/purpose or human independence.
	for i, left := range bindings {
		for _, right := range bindings[i+1:] {
			require.NoError(t, validateProgrammeAuthorityIndependentPair([]byte(left.ID), []byte(right.ID), left.Members, right.Members))
		}
	}
}

func TestQualSP227IndependentPair(t *testing.T) {
	bindings := qualSP227Rosters(t)
	left, right := bindings[0], bindings[1]
	leftID, rightID := []byte(left.ID), []byte(right.ID)
	require.NoError(t, validateProgrammeAuthorityIndependentPair(leftID, rightID, left.Members, right.Members))
	require.NoError(t, validateProgrammeAuthorityIndependentPair(rightID, leftID, right.Members, left.Members))
	for _, row := range []struct {
		name            string
		leftID, rightID []byte
		left, right     [][]byte
	}{
		{"missing_left_id", nil, rightID, left.Members, right.Members},
		{"missing_right_id", leftID, nil, left.Members, right.Members},
		{"same_id", leftID, bytes.Clone(leftID), left.Members, right.Members},
		{"missing_left_roster", leftID, rightID, nil, right.Members},
		{"missing_right_roster", leftID, rightID, left.Members, nil},
		{"empty_left_key", leftID, rightID, [][]byte{nil}, right.Members},
		{"empty_right_key", leftID, rightID, left.Members, [][]byte{nil}},
	} {
		t.Run(row.name, func(t *testing.T) {
			require.ErrorIs(t, validateProgrammeAuthorityIndependentPair(row.leftID, row.rightID, row.left, row.right), errInvalidAuthoritySignatures)
		})
	}
	for i := range left.Members {
		for j := range right.Members {
			changed := append([][]byte(nil), right.Members...)
			changed[j] = bytes.Clone(left.Members[i])
			require.ErrorIs(t, validateProgrammeAuthorityIndependentPair(leftID, rightID, left.Members, changed),
				errInvalidAuthoritySignatures, "every full-roster position, including unsigned members, must be disjoint")
		}
	}
	leftBefore, rightBefore := bytes.Join(left.Members, nil), bytes.Join(right.Members, nil)
	var wg sync.WaitGroup
	results := make(chan error, 16)
	// Reuse the existing W03 signature fixture's 16-reader concurrency bound.
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- validateProgrammeAuthorityIndependentPair(leftID, rightID, left.Members, right.Members)
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	require.Equal(t, leftBefore, bytes.Join(left.Members, nil))
	require.Equal(t, rightBefore, bytes.Join(right.Members, nil))
	require.Equal(t, []byte(left.ID), leftID)
	require.Equal(t, []byte(right.ID), rightID)
}
