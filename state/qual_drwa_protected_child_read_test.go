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

func qualA19ReadTouched(db *state.AccountsDB, address, recordKey, predecessor, root []byte, keys [][]byte) ([]core.TrieData, error) {
	owner, ok := any(db).(interface {
		ReadProtectedChildLeaves([]byte, []byte, []byte, [][]byte) ([]core.TrieData, error)
	})
	if !ok {
		// Before the read boundary existed the only read-only native option
		// was reopening the child from disk by the expected root.
		tr, err := db.GetTrie(root)
		if err != nil {
			return nil, err
		}
		out := make([]core.TrieData, len(keys))
		for i, key := range keys {
			value, _, version, err := tr.GetWithVersion(key)
			if err != nil {
				return nil, err
			}
			out[i] = core.TrieData{Key: key, Value: value, Version: core.TrieNodeVersion(version)}
		}
		return out, nil
	}
	return owner.ReadProtectedChildLeaves(address, recordKey, predecessor, keys)
}

type qualA19ProtectedReadStore struct {
	common.BaseStorer
	target, replacement []byte
}

func (s *qualA19ProtectedReadStore) Get(key []byte) ([]byte, error) {
	if bytes.Equal(key, s.target) {
		return s.replacement, nil
	}
	return s.BaseStorer.Get(key)
}

func TestQualDRWAA19ReadStagedProtectedChildWithoutWriting(t *testing.T) {
	address := bytes.Repeat([]byte{1}, 32)
	recordKey := []byte(core.ProtectedKeyPrefix + "fixture/a19/read")
	a, b := []byte("fixture/touched-a"), []byte("fixture/touched-b")
	beforeRecord := append([]byte{1}, common.EmptyTrieHash...)
	decode := func(owner, key, record []byte) ([]byte, error) {
		if !bytes.Equal(owner, address) || !bytes.Equal(key, recordKey) || len(record) != len(beforeRecord) {
			return nil, errors.New("unavailable fixture locator")
		}
		return record[1:], nil
	}
	store := &qualA19ProtectedReadStore{}
	db, main, _ := qualA19OpenAccounts(t, filepath.Join(t.TempDir(), "protected-read"), decode, func(base common.BaseStorer) common.BaseStorer {
		store.BaseStorer = base
		return store
	})
	account, err := db.LoadAccount(address)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(recordKey, beforeRecord))
	require.NoError(t, db.SaveAccount(account))
	_, err = db.Commit()
	require.NoError(t, err)

	leaf := core.TrieData{Key: a, Value: []byte("synthetic retained value"), Version: core.AutoBalanceEnabled}
	keys := [][]byte{a, b}
	detached, err := main.Recreate(holders.NewDefaultRootHashesHolder(common.EmptyTrieHash))
	require.NoError(t, err)
	require.NoError(t, detached.(state.DataTrie).UpdateWithVersion(leaf.Key, leaf.Value, leaf.Version))
	childRoot, err := detached.RootHash()
	require.NoError(t, err)
	successor := append([]byte{2}, childRoot...)
	require.NoError(t, db.StageProtectedChildTrie(address, recordKey, beforeRecord, successor, []core.TrieData{leaf}))
	_, err = db.GetTrie(childRoot)
	require.Error(t, err, "the child exists only in the owning journal")
	root, err := db.RootHash()
	require.NoError(t, err)
	journal := db.JournalLen()

	read := func(predecessor []byte, keys [][]byte) ([]core.TrieData, error) {
		return qualA19ReadTouched(db, address, recordKey, predecessor, childRoot, keys)
	}
	expected := []core.TrieData{leaf, {Key: b, Version: core.NotSpecified}}
	actual, err := read(successor, keys)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	actual[0].Key[0] ^= 1
	actual[0].Value[0] ^= 1
	actual[0].Version = core.NotSpecified

	// The synthetic position record's version byte and existing child
	// are both retained by a net-identical touched-leaf verification.
	actual, err = read(successor, keys)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	sameRootWrongVersion := append([]byte{1}, childRoot...)
	for _, wrong := range [][]byte{beforeRecord, sameRootWrongVersion} {
		actual, err = read(wrong, keys)
		require.Error(t, err)
		require.Nil(t, actual)
	}
	actual, err = qualA19ReadTouched(db, address, []byte(core.ProtectedKeyPrefix+"fixture/a19/other"), successor, childRoot, keys)
	require.Error(t, err)
	require.Nil(t, actual)
	for _, badKeys := range [][][]byte{nil, {a, a}, {nil}} {
		actual, err = read(successor, badKeys)
		require.Error(t, err)
		require.Nil(t, actual)
	}
	after, err := db.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, journal, db.JournalLen())
	account, err = db.GetExistingAccount(address)
	require.NoError(t, err)
	record, _, err := account.(state.UserAccountHandler).RetrieveValue(recordKey)
	require.NoError(t, err)
	require.Equal(t, successor, record)
	_, err = db.GetTrie(childRoot)
	require.Error(t, err, "the read did not publish the staged child")

	committed, err := db.Commit()
	require.NoError(t, err)
	actual, err = read(successor, keys)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	wrongNode, err := main.GetSerializedNode(committed)
	require.NoError(t, err)
	store.target = childRoot
	store.replacement = wrongNode
	_, err = db.GetTrie(childRoot)
	require.NoError(t, err, "the native reopener decodes a node found at the requested key")
	actual, err = read(successor, keys)
	require.Error(t, err, "reopening a different node under the requested root cannot authenticate it")
	require.Nil(t, actual)
	store.replacement = nil
	actual, err = read(successor, keys)
	require.Error(t, err, "a missing cold child is not an absent leaf")
	require.Nil(t, actual)
	require.Zero(t, db.JournalLen())
}
