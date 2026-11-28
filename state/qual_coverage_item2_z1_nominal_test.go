package state_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

// Two valid local checkpoints are retained and independently reconstructed.
// The existing fixture uses a disabled pruning manager, and this test also
// requests DisableDataRemoval; the retention read never deletes any node.
func TestQualCoverageItem2NominalRetainedCheckpoints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	address := bytes.Repeat([]byte{1}, 32)
	key := []byte(core.ProtectedKeyPrefix + "fixture/retained-checkpoint")
	first := []core.TrieData{
		{Key: []byte("alpha"), Value: []byte("first-a"), Version: core.NotSpecified},
		{Key: []byte("beta"), Value: []byte("first-b"), Version: core.NotSpecified},
	}
	second := []core.TrieData{
		{Key: []byte("alpha"), Value: []byte("second-a"), Version: core.NotSpecified},
		{Key: []byte("beta"), Value: []byte("second-b"), Version: core.NotSpecified},
	}
	decode := func(owner, recordKey, record []byte) ([]byte, error) {
		if !bytes.Equal(owner, address) || !bytes.Equal(recordKey, key) || len(record) != 32 {
			return nil, errors.New("unrecognized local fixture record")
		}
		return bytes.Clone(record), nil
	}
	var firstCheckpoint, secondCheckpoint, firstRoot, secondRoot []byte
	var located [][]byte
	retentionReads := 0
	retention := &state.ProtectedChildCheckpoints{
		Locate: func(checkpoint common.RootHashHolder) ([]state.ProtectedChildLocator, error) {
			root := checkpoint.GetRootHash()
			located = append(located, bytes.Clone(root))
			if bytes.Equal(root, firstCheckpoint) {
				return []state.ProtectedChildLocator{{Address: address, Key: key, Record: firstRoot}}, nil
			}
			if bytes.Equal(root, secondCheckpoint) {
				return []state.ProtectedChildLocator{{Address: address, Key: key, Record: secondRoot}}, nil
			}
			return nil, errors.New("unselected local fixture checkpoint")
		},
		Retained: func() ([]common.RootHashHolder, error) {
			retentionReads++
			return []common.RootHashHolder{
				holders.NewDefaultRootHashesHolder(firstCheckpoint),
				holders.NewDefaultRootHashesHolder(secondCheckpoint),
			}, nil
		},
		MaxLocators: 1, MaxCheckpoints: 2, MaxBytes: 8192,
	}
	adb, main, closeState := qualA19OpenAccounts(t, path, decode, nil, retention)
	account, err := adb.LoadAccount(address)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, common.EmptyTrieHash))
	require.NoError(t, adb.SaveAccount(account))
	_, err = adb.Commit()
	require.NoError(t, err)

	// Independently construct each root with the native detached trie.
	detached, err := main.Recreate(holders.NewDefaultRootHashesHolder(common.EmptyTrieHash))
	require.NoError(t, err)
	for _, leaf := range first {
		require.NoError(t, detached.Update(leaf.Key, leaf.Value))
	}
	firstRoot, err = detached.RootHash()
	require.NoError(t, err)
	require.NoError(t, adb.StageProtectedChildTrie(address, key, common.EmptyTrieHash, firstRoot, first))
	firstCheckpoint, err = adb.Commit()
	require.NoError(t, err)
	for _, leaf := range second {
		require.NoError(t, detached.Update(leaf.Key, leaf.Value))
	}
	secondRoot, err = detached.RootHash()
	require.NoError(t, err)
	got, err := adb.StageDerivedProtectedChildTrie(address, key, firstRoot, [][]byte{first[0].Key, first[1].Key},
		func(current []core.TrieData) ([]core.TrieData, error) {
			require.Equal(t, first, current)
			return second, nil
		}, func(root []byte) ([]byte, error) { return bytes.Clone(root), nil })
	require.NoError(t, err)
	require.Equal(t, secondRoot, got)
	secondCheckpoint, err = adb.Commit()
	require.NoError(t, err)
	require.NotEqual(t, firstCheckpoint, secondCheckpoint)
	require.NotEqual(t, firstRoot, secondRoot)

	check := func(db *state.AccountsDB, checkpoint, root []byte, want []core.TrieData) {
		t.Helper()
		tries, readErr := db.RecreateAllTries(checkpoint)
		require.NoError(t, readErr)
		require.Contains(t, tries, string(root))
		for _, leaf := range want {
			value, _, err := tries[string(root)].Get(leaf.Key)
			require.NoError(t, err)
			require.Equal(t, leaf.Value, value)
		}
	}
	check(adb, firstCheckpoint, firstRoot, first)
	check(adb, secondCheckpoint, secondRoot, second)
	located = nil
	adb.PruneTrie(firstCheckpoint, state.OldRoot, state.NewPruningHandler(state.DisableDataRemoval))
	require.Equal(t, 1, retentionReads)
	require.Equal(t, [][]byte{firstCheckpoint, secondCheckpoint}, located)
	require.Zero(t, adb.JournalLen())
	closeState()

	cold, _, _ := qualA19OpenAccounts(t, path, decode, nil, retention)
	require.NoError(t, cold.RecreateTrie(holders.NewDefaultRootHashesHolder(secondCheckpoint)))
	check(cold, firstCheckpoint, firstRoot, first)
	check(cold, secondCheckpoint, secondRoot, second)
	root, err := cold.RootHash()
	require.NoError(t, err)
	require.Equal(t, secondCheckpoint, root)
	require.Zero(t, cold.JournalLen())
}
