package trie_test

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/dataTrieValue"
	"github.com/multiversx/mx-chain-go/state/trackableDataTrie"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/multiversx/mx-chain-go/trie"
)

func TestQualGateG16MigrationRecreation(t *testing.T) {
	store, codec, hasher, _, depth := getDefaultTrieParameters()
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.AutoBalanceDataTriesFlag, common.FixDataTrieLeafValidationFlag)
	tr, err := trie.NewTrie(store, codec, hasher, flags, depth)
	require.NoError(t, err)
	address, legacyKey, modernKey := []byte("account"), []byte("legacy-key"), []byte("modern-key")
	legacyValue, modernValue := []byte("old legacy"), []byte("old modern")
	legacy := append(append(bytes.Clone(legacyValue), legacyKey...), address...)
	require.NoError(t, tr.UpdateWithVersion(legacyKey, legacy, core.NotSpecified))
	modern, err := codec.Marshal(&dataTrieValue.TrieLeafData{Key: modernKey, Address: address, Value: modernValue})
	require.NoError(t, err)
	require.NoError(t, tr.UpdateWithVersion(hasher.Compute(string(modernKey)), modern, core.AutoBalanceEnabled))
	var current common.Trie = tr
	recreate := func() {
		root, rootErr := current.RootHash()
		require.NoError(t, rootErr)
		require.NoError(t, current.Commit())
		current, rootErr = current.Recreate(holders.NewDefaultRootHashesHolder(root))
		require.NoError(t, rootErr)
	}
	recreate()
	tracker, err := trackableDataTrie.NewTrackableDataTrie(address, hasher, codec, flags, &stateMock.StateAccessesCollectorStub{})
	require.NoError(t, err)
	tracker.SetDataTrie(current)
	for _, versions := range [][2]core.TrieNodeVersion{{99, core.AutoBalanceEnabled}, {core.NotSpecified, 99}, {core.AutoBalanceEnabled, core.NotSpecified}} {
		before, rootErr := current.RootHash()
		require.NoError(t, rootErr)
		collectCalls := 0
		err = tracker.MigrateDataTrieLeaves(vmcommon.ArgsMigrateDataTrieLeaves{
			OldVersion: versions[0], NewVersion: versions[1],
			TrieMigrator: &trieMock.DataTrieMigratorStub{GetLeavesToBeMigratedCalled: func() []core.TrieData {
				collectCalls++
				return nil
			}},
		})
		require.Error(t, err)
		require.Zero(t, collectCalls)
		after, rootErr := current.RootHash()
		require.NoError(t, rootErr)
		require.Equal(t, before, after)
	}
	legacyRead, _, err := tracker.RetrieveValue(legacyKey)
	require.NoError(t, err)
	require.Equal(t, legacyValue, legacyRead)
	modernRead, _, err := tracker.RetrieveValue(modernKey)
	require.NoError(t, err)
	require.Equal(t, modernValue, modernRead)
	err = tracker.MigrateDataTrieLeaves(vmcommon.ArgsMigrateDataTrieLeaves{
		OldVersion: core.NotSpecified, NewVersion: core.AutoBalanceEnabled,
		TrieMigrator: &trieMock.DataTrieMigratorStub{GetLeavesToBeMigratedCalled: func() []core.TrieData {
			return []core.TrieData{{Key: legacyKey, Value: legacy, Version: core.NotSpecified}}
		}},
	})
	require.NoError(t, err)
	_, _, err = tracker.SaveDirtyData(current)
	require.NoError(t, err)
	recreate()
	tracker.SetDataTrie(current)
	raw, _, _, err := current.GetWithVersion(legacyKey)
	require.NoError(t, err)
	require.Empty(t, raw)
	_, _, version, err := current.GetWithVersion(hasher.Compute(string(legacyKey)))
	require.NoError(t, err)
	require.Equal(t, uint32(core.AutoBalanceEnabled), version)
	got, _, err := tracker.RetrieveValue(legacyKey)
	require.NoError(t, err)
	require.Equal(t, legacyValue, got)
	require.NoError(t, tracker.SaveKeyValue(legacyKey, nil))
	_, _, err = tracker.SaveDirtyData(current)
	require.NoError(t, err)
	recreate()
	tracker.SetDataTrie(current)
	got, _, err = tracker.RetrieveValue(legacyKey)
	require.NoError(t, err)
	require.Empty(t, got)
	got, _, err = tracker.RetrieveValue(modernKey)
	require.NoError(t, err)
	require.Equal(t, modernValue, got)
	var _ state.DataTrie = tr
}
