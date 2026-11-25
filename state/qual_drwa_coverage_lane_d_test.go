package state_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

func TestQualLaneDProtectedChildDerivedJournal(t *testing.T) {
	// Part A P-05 keeps every pre-rollback write owned by its original
	// snapshot. The admitted leaf update must also retain its trie version.
	address := bytes.Repeat([]byte{1}, 32)
	locator := []byte(core.ProtectedKeyPrefix + "fixture/lane-d/child")
	leafKey := []byte("fixture-leaf")
	adb, main, _, _ := qualA19AccountsOnStore(t, testscommon.NewSnapshotPruningStorerMock(),
		func(owner, key, record []byte) ([]byte, error) {
			if !bytes.Equal(owner, address) || !bytes.Equal(key, locator) || len(record) != 32 {
				return nil, errors.New("unexpected fixture locator")
			}
			return bytes.Clone(record), nil
		})

	account, err := adb.LoadAccount(address)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(locator, common.EmptyTrieHash))
	require.NoError(t, adb.SaveAccount(account))
	_, err = adb.Commit()
	require.NoError(t, err)

	const version = core.AutoBalanceEnabled
	first := core.TrieData{Key: leafKey, Value: []byte("first"), Version: version}
	second := core.TrieData{Key: leafKey, Value: []byte("second"), Version: version}
	detached, err := main.Recreate(holders.NewDefaultRootHashesHolder(common.EmptyTrieHash))
	require.NoError(t, err)
	dataTrie := detached.(state.DataTrie)
	require.NoError(t, dataTrie.UpdateWithVersion(first.Key, first.Value, first.Version))
	firstRoot, err := detached.RootHash()
	require.NoError(t, err)
	require.NoError(t, adb.StageProtectedChildTrie(address, locator, common.EmptyTrieHash, firstRoot, []core.TrieData{first}))
	checkpoint := adb.JournalLen()
	require.Greater(t, checkpoint, 0)
	require.NoError(t, dataTrie.UpdateWithVersion(second.Key, second.Value, second.Version))
	secondRoot, err := detached.RootHash()
	require.NoError(t, err)
	require.NotEqual(t, firstRoot, secondRoot)

	read := func(root []byte, want core.TrieData) {
		t.Helper()
		leaves, readErr := adb.ReadProtectedChildLeaves(address, locator, root, [][]byte{leafKey})
		require.NoError(t, readErr)
		require.Equal(t, []core.TrieData{want}, leaves)
	}
	stage := func() {
		t.Helper()
		got, stageErr := adb.StageDerivedProtectedChildTrie(address, locator, firstRoot, [][]byte{leafKey},
			func(current []core.TrieData) ([]core.TrieData, error) {
				require.Equal(t, []core.TrieData{first}, current)
				return []core.TrieData{second}, nil
			}, func(root []byte) ([]byte, error) { return root, nil })
		require.NoError(t, stageErr)
		require.Equal(t, secondRoot, got)
	}
	stage()
	read(secondRoot, second)
	require.NoError(t, adb.RevertToSnapshot(checkpoint))
	require.Equal(t, checkpoint, adb.JournalLen())
	read(firstRoot, first)
	stage()
	_, err = adb.Commit()
	require.NoError(t, err)
	reopened, err := adb.GetTrie(secondRoot)
	require.NoError(t, err)
	value, _, leafVersion, err := reopened.(state.DataTrie).GetWithVersion(leafKey)
	require.NoError(t, err)
	require.Equal(t, second.Value, value)
	require.Equal(t, uint32(version), leafVersion)
}

func TestQualLaneDProtectedCheckpointUnavailable(t *testing.T) {
	root := common.EmptyTrieHash
	unavailable := errors.New("fixture locator input unavailable")
	calls := 0
	checkpoints := &state.ProtectedChildCheckpoints{
		Locate: func(checkpoint common.RootHashHolder) ([]state.ProtectedChildLocator, error) {
			calls++
			require.Equal(t, root, checkpoint.GetRootHash())
			require.False(t, checkpoint.GetEpoch().HasValue)
			return nil, unavailable
		},
		Retained: func() ([]common.RootHashHolder, error) {
			t.Fatal("resolver must not query retention")
			return nil, unavailable
		},
		MaxLocators: 1, MaxCheckpoints: 1, MaxBytes: 4096,
	}
	adb, _, _, _ := qualA19AccountsOnStore(t, testscommon.NewSnapshotPruningStorerMock(),
		func(_, _, _ []byte) ([]byte, error) {
			t.Fatal("resolver must not decode a locator without provider evidence")
			return nil, unavailable
		}, checkpoints)
	resolve := adb.ProtectedChildResolver()
	require.NotNil(t, resolve)

	refs, err := resolve(nil)
	require.Error(t, err)
	require.Nil(t, refs)
	refs, err = resolve(holders.NewDefaultRootHashesHolder([]byte{0}))
	require.Error(t, err)
	require.Nil(t, refs)
	require.Zero(t, calls)

	refs, err = resolve(holders.NewDefaultRootHashesHolder(root))
	require.ErrorIs(t, err, unavailable)
	require.Nil(t, refs)
	require.Equal(t, 1, calls)
}

func TestQualLaneDProtectedChildDecoderReadRefusal(t *testing.T) {
	address := bytes.Repeat([]byte{1}, 32)
	locator := []byte(core.ProtectedKeyPrefix + "fixture/lane-d/child")
	predecessor := common.EmptyTrieHash
	keys := [][]byte{[]byte("fixture-leaf")}
	unavailable := errors.New("fixture decoder unavailable")

	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "decoder-unavailable", err: unavailable},
		{name: "no-root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			adb, _, _, _ := qualA19AccountsOnStore(t, testscommon.NewSnapshotPruningStorerMock(),
				func(owner, key, record []byte) ([]byte, error) {
					calls++
					require.Equal(t, address, owner)
					require.Equal(t, locator, key)
					require.Equal(t, predecessor, record)
					return nil, tc.err
				})
			before := adb.JournalLen()
			leaves, err := adb.ReadProtectedChildLeaves(address, locator, predecessor, keys)
			require.Error(t, err)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			}
			require.Nil(t, leaves)
			require.Equal(t, before, adb.JournalLen())
			require.Equal(t, 1, calls)
		})
	}
}
