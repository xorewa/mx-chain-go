package drwa

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// N05/M8: manifest-selected experimental values, not accepted release inputs.
// Native AccountsDB/trie/commit/reopen and the existing bounded transport are
// exercised; genesis provenance, complete profile and activation remain owed.
func qualDRWADevelopmentMinimumGenesis(t *testing.T) minimumGenesis {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "..", "evidence", "sp1_t09_needed_2026-10-13_02")
	profile, err := os.ReadFile(filepath.Join(dir, "N05_MINIMUM_PROFILE.json"))
	require.NoError(t, err)
	release, err := os.ReadFile(filepath.Join(dir, "N05_GENESIS_RELEASE.json"))
	require.NoError(t, err)
	var selected struct {
		MaxEver    uint64 `json:"max_ever_regulated_tokens"`
		ProofBytes uint64 `json:"registry_proof_bytes"`
	}
	require.NoError(t, json.Unmarshal(profile, &selected))
	require.Equal(t, uint64(64), selected.MaxEver)
	require.Equal(t, uint64(1048576), selected.ProofBytes)
	return minimumGenesis{profileDigest: sha256.Sum256(profile), releaseDigest: sha256.Sum256(release), maxEverTokens: selected.MaxEver, registryProofBytes: selected.ProofBytes}
}

func TestQualDRWADevelopmentMinimumGenesisReopen(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprint(auto), func(t *testing.T) {
			args := qualReaderArgs(auto)
			db := qualGenesisAccountsFromArgs(t, args)
			s, err := newProtectedState(db)
			require.NoError(t, err)
			owner, err := NewRollbackContainment(db)
			require.NoError(t, err)
			g := qualDRWADevelopmentMinimumGenesis(t)
			require.NoError(t, owner.Execute(func() (*vmcommon.VMOutput, error) { return nil, s.provisionMinimumGenesis(g) }))
			roots, _, err := owner.Commit()
			require.NoError(t, err)
			reopened := qualGenesisAccountsFromArgs(t, args)
			require.NoError(t, reopened.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
			reader, err := newProtectedState(reopened)
			require.NoError(t, err)
			got, err := reader.readMinimumGenesis()
			require.NoError(t, err)
			require.Equal(t, g, got)
			account, err := reopened.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			plane, _, err := account.(state.UserAccountHandler).RetrieveValue([]byte("ELRONDDRWA@plane@state"))
			require.NoError(t, err)
			expected := append([]byte("NORMAL"), []byte{0, 0, 0, 0, 0, 0, 0, 0}...)
			expected = append(expected, g.releaseDigest[:]...)
			require.Equal(t, expected, plane)
			capValue, _, err := account.(state.UserAccountHandler).RetrieveValue([]byte("ELRONDDRWA@param@maxEverRegulatedTokens"))
			require.NoError(t, err)
			require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 64}, capValue)
			// No operation/decorator is attached to this dormant storage construction.
			before, err := reopened.RootHash()
			require.NoError(t, err)
			require.ErrorIs(t, reader.provisionMinimumGenesis(g), errInvalidGenesisState)
			after, err := reopened.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Zero(t, reopened.JournalLen())
		})
	}
}

func TestQualDRWADevelopmentMinimumGenesisInvalidInput(t *testing.T) {
	for _, fault := range []string{"profile", "release", "cap", "budget", "budget_over_int"} {
		t.Run(fault, func(t *testing.T) {
			db := qualGenesisAccounts(t, false)
			s, err := newProtectedState(db)
			require.NoError(t, err)
			g := qualDRWADevelopmentMinimumGenesis(t)
			switch fault {
			case "profile":
				g.profileDigest = [32]byte{}
			case "release":
				g.releaseDigest = [32]byte{}
			case "cap":
				g.maxEverTokens = 0
			case "budget":
				g.registryProofBytes = 0
			case "budget_over_int":
				g.registryProofBytes = ^uint64(0)
			}
			before, err := db.RootHash()
			require.NoError(t, err)
			require.ErrorIs(t, s.provisionMinimumGenesis(g), errInvalidGenesisState)
			after, err := db.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Zero(t, db.JournalLen())
		})
	}
}

func TestQualDRWADevelopmentMinimumGenesisMissingItem(t *testing.T) {
	for _, key := range []string{"ELRONDDRWA@plane@state", "ELRONDDRWA@profile@minimum", "ELRONDDRWA@param@maxEverRegulatedTokens", "ELRONDDRWA@param@registryProofBytes"} {
		t.Run(key, func(t *testing.T) {
			db := qualGenesisAccounts(t, false)
			s, err := newProtectedState(db)
			require.NoError(t, err)
			owner, err := NewRollbackContainment(db)
			require.NoError(t, err)
			require.NoError(t, owner.Execute(func() (*vmcommon.VMOutput, error) {
				return nil, s.provisionMinimumGenesis(qualDRWADevelopmentMinimumGenesis(t))
			}))
			_, _, err = owner.Commit()
			require.NoError(t, err)
			account, err := db.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue([]byte(key), nil))
			require.NoError(t, db.SaveAccount(account))
			_, err = db.Commit()
			require.NoError(t, err)
			_, err = s.readMinimumGenesis()
			require.Error(t, err, "missing required input cannot supply a default or enable operations")
		})
	}
}

func TestQualDRWADevelopmentMinimumGenesisSaveFailure(t *testing.T) {
	for _, key := range []string{"ELRONDDRWA@plane@state", "ELRONDDRWA@profile@minimum", "ELRONDDRWA@param@maxEverRegulatedTokens", "ELRONDDRWA@param@registryProofBytes"} {
		t.Run(key, func(t *testing.T) {
			db := qualGenesisAccounts(t, false)
			fault := errors.New("experimental genesis item write failure")
			adapter := &qualGenesisFault{AccountsAdapter: db, load: func(address []byte) (vmcommon.AccountHandler, error) { return db.LoadAccount(address) }}
			// systemAccount uses GetExistingAccount after base provisioning. The existing
			// account decorator targets exactly one late item, delegating all other saves.
			wrapped := &qualMinimumGenesisFault{AccountsAdapter: adapter, key: []byte(key), fault: fault}
			s, err := newProtectedState(wrapped)
			require.NoError(t, err)
			owner, err := NewRollbackContainment(db)
			require.NoError(t, err)
			before, err := db.RootHash()
			require.NoError(t, err)
			require.ErrorIs(t, owner.Execute(func() (*vmcommon.VMOutput, error) {
				return nil, s.provisionMinimumGenesis(qualDRWADevelopmentMinimumGenesis(t))
			}), fault)
			after, err := db.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Zero(t, db.JournalLen())
			_, err = db.GetExistingAccount(core.SystemAccountAddress)
			require.ErrorIs(t, err, state.ErrAccNotFound)
		})
	}
}

type qualMinimumGenesisFault struct {
	state.AccountsAdapter
	key   []byte
	fault error
}

func (a *qualMinimumGenesisFault) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	account, err := a.AccountsAdapter.GetExistingAccount(address)
	if err != nil {
		return nil, err
	}
	return &qualIndexItemFault{UserAccountHandler: account.(state.UserAccountHandler), key: bytes.Clone(a.key), err: a.fault}, nil
}

func TestQualDRWADevelopmentMinimumGenesisRegistryBound(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprint(auto), func(t *testing.T) {
			db := qualGenesisAccounts(t, auto)
			s, err := newProtectedState(db)
			require.NoError(t, err)
			owner, err := NewRollbackContainment(db)
			require.NoError(t, err)
			require.NoError(t, owner.Execute(func() (*vmcommon.VMOutput, error) {
				return nil, s.provisionMinimumGenesis(qualDRWADevelopmentMinimumGenesis(t))
			}))
			_, _, err = owner.Commit()
			require.NoError(t, err)
			g, err := s.readMinimumGenesis()
			require.NoError(t, err)
			// Independent count vector at the selected cap; real native proof-producing
			// store is distinct from the transport's proof cache and materialization store.
			ids := make([][]byte, 64)
			for i := range ids {
				ids[i] = []byte(fmt.Sprintf("QUAL-%06x", i))
			}
			f := qualRegistryTransport(t, auto, []byte{0, 0, 0, 0, 0, 0, 0, 64}, []byte{1}, ids...)
			tr, err := newRegistryTransport(f.reader, g.maxEverTokens, int(g.registryProofBytes))
			require.NoError(t, err)
			view, err := tr.reconstruct(f.anchor, f.count, f.members)
			require.NoError(t, err)
			require.Len(t, view.members, 64)
			// One extra member is rejected before any proof can be read, even if every
			// proof is absent. The cap comes from the manifest, not the transport fixture.
			over := append(append([]registryMemberWitness(nil), f.members...), registryMemberWitness{tokenID: []byte("EXTRA-abcdef")})
			rejected, err := tr.reconstruct(nil, AccountItemWitness{}, over)
			require.ErrorIs(t, err, errInvalidRegistryTransport)
			require.Nil(t, rejected)
		})
	}
}
