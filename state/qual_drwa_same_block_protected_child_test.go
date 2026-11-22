package state_test

import (
	"bytes"
	"errors"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func qualA19StageFromNativeState(db *state.AccountsDB, address, key, predecessor []byte,
	keys [][]byte, derive func([]core.TrieData) ([]core.TrieData, error), encode func([]byte) ([]byte, error)) ([]byte, error) {
	owner, ok := any(db).(interface {
		StageDerivedProtectedChildTrie([]byte, []byte, []byte, [][]byte,
			func([]core.TrieData) ([]core.TrieData, error), func([]byte) ([]byte, error)) ([]byte, error)
	})
	if !ok {
		// The old API needs a child root that can be opened before deriving the
		// successor. An uncommitted child is not present in this storage view.
		_, err := db.GetTrie(predecessor)
		return nil, err
	}
	return owner.StageDerivedProtectedChildTrie(address, key, predecessor, keys, derive, encode)
}

func TestQualDRWAA19SameBlockChildDerivationAndRollback(t *testing.T) {
	address := bytes.Repeat([]byte{1}, 32)
	holder := bytes.Repeat([]byte{2}, 32)
	supply := []byte(core.ProtectedKeyPrefix + "fixture/a19/nonce-root")
	position := []byte(core.ProtectedKeyPrefix + "fixture/a19/position-root")
	leafKey := []byte("synthetic touched leaf")
	decode := func(owner, key, raw []byte) ([]byte, error) {
		if !bytes.Equal(owner, address) || !(bytes.Equal(key, supply) || bytes.Equal(key, position)) || len(raw) != 32 {
			return nil, errors.New("invalid synthetic locator")
		}
		return raw, nil
	}
	encode := func(root []byte) ([]byte, error) { return root, nil }
	adb, main, _ := qualA19OpenAccounts(t, filepath.Join(t.TempDir(), "staged"), decode, nil)
	user, err := adb.LoadAccount(address)
	require.NoError(t, err)
	for _, loc := range [][]byte{supply, position} {
		require.NoError(t, user.(state.UserAccountHandler).SaveKeyValue(loc, common.EmptyTrieHash))
	}
	require.NoError(t, adb.SaveAccount(user))
	payer, err := adb.LoadAccount(holder)
	require.NoError(t, err)
	require.NoError(t, payer.(state.UserAccountHandler).AddToBalance(big.NewInt(20)))
	require.NoError(t, adb.SaveAccount(payer))
	_, err = adb.Commit()
	require.NoError(t, err)
	boundary, err := drwa.NewRollbackContainment(adb)
	require.NoError(t, err)

	const version = core.AutoBalanceEnabled
	firstValue := []byte("issued=5/live=3")
	nextValue := []byte("issued=5/live=0")
	detached, err := main.Recreate(holders.NewDefaultRootHashesHolder(common.EmptyTrieHash))
	require.NoError(t, err)
	require.NoError(t, detached.(state.DataTrie).UpdateWithVersion(leafKey, firstValue, version))
	first, err := detached.RootHash()
	require.NoError(t, err)
	require.NoError(t, adb.StageProtectedChildTrie(address, supply, common.EmptyTrieHash, first,
		[]core.TrieData{{Key: leafKey, Value: firstValue, Version: version}}))
	_, err = adb.GetTrie(first)
	require.Error(t, err, "after the first effect the exact predecessor exists only in this AccountsDB journal")

	derive := func(expected, next []byte, expectedVersion core.TrieNodeVersion) func([]core.TrieData) ([]core.TrieData, error) {
		return func(current []core.TrieData) ([]core.TrieData, error) {
			require.Equal(t, []core.TrieData{{Key: leafKey, Value: expected, Version: expectedVersion}}, current)
			// Inputs handed to the pure mutation builder are detached copies.
			if len(current[0].Value) != 0 {
				current[0].Key[0] ^= 1
				current[0].Value[0] ^= 1
			}
			return []core.TrieData{{Key: leafKey, Value: next, Version: version}}, nil
		}
	}
	stage := func(locator, predecessor []byte, edit func([]core.TrieData) ([]core.TrieData, error),
		body func([]byte) ([]byte, error)) ([]byte, error) {
		return qualA19StageFromNativeState(adb, address, locator, predecessor, [][]byte{leafKey}, edit, body)
	}
	next, err := stage(supply, first, derive(firstValue, nextValue, version), encode)
	require.NoError(t, err)
	require.NoError(t, detached.(state.DataTrie).UpdateWithVersion(leafKey, nextValue, version))
	expected, err := detached.RootHash()
	require.NoError(t, err)
	require.Equal(t, expected, next)
	_, err = adb.GetTrie(next)
	require.Error(t, err, "neither protected child update publishes before the block commit")
	_, err = stage(supply, first, derive(firstValue, nextValue, version), encode)
	require.Error(t, err, "a stale parent cannot grant a read of current staged leaves")
	require.NoError(t, adb.StageProtectedChildTrie(address, position, common.EmptyTrieHash, first,
		[]core.TrieData{{Key: leafKey, Value: firstValue, Version: version}}))

	preRoot, err := adb.RootHash()
	require.NoError(t, err)
	preJournal := adb.JournalLen()
	firstFailure := errors.New("synthetic position successor encoder failed after native child mutation")
	delta := []byte("synthetic burned position")
	apply := func() error {
		payer, e := adb.LoadAccount(holder)
		if e != nil {
			return e
		}
		if e = payer.(state.UserAccountHandler).SubFromBalance(big.NewInt(4)); e != nil {
			return e
		}
		if e = adb.SaveAccount(payer); e != nil {
			return e
		}
		if _, e = stage(supply, next, derive(nextValue, []byte("issued=6/live=1"), version), encode); e != nil {
			return e
		}
		_, e = stage(position, first, derive(firstValue, delta, version), func(root []byte) ([]byte, error) {
			require.NotEqual(t, common.EmptyTrieHash, root)
			return nil, firstFailure
		})
		return e
	}
	err = boundary.Execute(func() (*vmcommon.VMOutput, error) {
		return nil, apply()
	})
	require.ErrorIs(t, err, firstFailure)
	postRoot, err := adb.RootHash()
	require.NoError(t, err)
	require.Equal(t, preRoot, postRoot)
	require.Equal(t, preJournal, adb.JournalLen())
	payer, err = adb.GetExistingAccount(holder)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(20), payer.(state.UserAccountHandler).GetBalance())

	// A following operation can still read the second staged value/version.
	// It cannot observe the rolled-back third effect.
	recovered, err := stage(supply, next, derive(nextValue, nextValue, version), encode)
	require.NoError(t, err)
	require.Equal(t, next, recovered)
	recoveredPosition, err := stage(position, first, derive(firstValue, firstValue, version), encode)
	require.NoError(t, err)
	require.Equal(t, first, recoveredPosition)
	_, err = adb.Commit()
	require.NoError(t, err)
	opened, err := adb.GetTrie(next)
	require.NoError(t, err)
	value, _, leafVersion, err := opened.(state.DataTrie).GetWithVersion(leafKey)
	require.NoError(t, err)
	require.Equal(t, nextValue, value)
	require.Equal(t, uint32(version), leafVersion)
}
