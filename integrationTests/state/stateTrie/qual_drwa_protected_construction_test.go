package stateTrie

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE P20 construction, Part A 3.1/5.4 and Part B 17.2.
// This fixture framing demonstrates disjoint variable-length components under
// the EXISTING protocol-only prefix, outside VM's writable child namespace.
// It allocates no production key, width, record address or migration format.
func qualProtectedFixtureKey(parts ...[]byte) []byte {
	key := []byte(core.ProtectedKeyPrefix + "qual-drwa/")
	for _, part := range parts {
		key = binary.BigEndian.AppendUint64(key, uint64(len(part)))
		key = append(key, part...)
	}
	return key
}

func TestQualDRWAProtectedNamespaceNativePersistence(t *testing.T) {
	adb := createAccountsDBTestSetup()
	t.Cleanup(func() { require.NoError(t, adb.Close()) })
	first := bytes.Repeat([]byte{31}, 32)
	second := bytes.Repeat([]byte{32}, 32)
	key := qualProtectedFixtureKey([]byte("token-A"), []byte("final/holder"))
	require.False(t, vmcommon.IsAllowedToSaveUnderKey(key))
	require.False(t, process.IsAllowedToSaveUnderKey(key))
	for _, address := range [][]byte{first, second} {
		account, err := adb.LoadAccount(address)
		require.NoError(t, err)
		require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue([]byte("ordinary"), []byte("untouched")))
		require.NoError(t, adb.SaveAccount(account))
	}
	before, err := adb.Commit()
	require.NoError(t, err)
	account, err := adb.LoadAccount(first)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, []byte("candidate")))
	require.NoError(t, adb.SaveAccount(account))
	require.NoError(t, adb.RevertToSnapshot(0))
	afterRollback, err := adb.RootHash()
	require.NoError(t, err)
	require.Equal(t, before, afterRollback)
	account, err = adb.LoadAccount(first)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, []byte("committed")))
	require.NoError(t, adb.SaveAccount(account))
	committed, err := adb.Commit()
	require.NoError(t, err)
	require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(before)))
	require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(committed)))
	for index, address := range [][]byte{first, second} {
		readAccount, readErr := adb.GetExistingAccount(address)
		require.NoError(t, readErr)
		value, _, readErr := readAccount.(state.UserAccountHandler).RetrieveValue([]byte("ordinary"))
		require.NoError(t, readErr)
		require.Equal(t, []byte("untouched"), value)
		value, _, readErr = readAccount.(state.UserAccountHandler).RetrieveValue(key)
		if index == 0 {
			require.NoError(t, readErr)
			require.Equal(t, []byte("committed"), value)
		} else {
			require.Empty(t, value, "the same key at another holder cannot read the first holder's record")
		}
	}
}

func TestQualDRWAProtectedNamespaceFraming(t *testing.T) {
	seen := make(map[string]bool)
	for _, parts := range [][][]byte{
		{[]byte("a"), []byte("bc")}, {[]byte("ab"), []byte("c")},
		{[]byte("a/b"), []byte("c")}, {[]byte("a"), []byte("b/c")},
		{nil, []byte("a")}, {[]byte("a"), nil}, {[]byte("a")},
		{[]byte{0}, []byte("a")}, {[]byte("a"), []byte{0}},
	} {
		key := qualProtectedFixtureKey(parts...)
		require.False(t, seen[string(key)], "fixture component collision")
		seen[string(key)] = true
		require.False(t, vmcommon.IsAllowedToSaveUnderKey(key))
		require.False(t, process.IsAllowedToSaveUnderKey(key))
	}
	require.True(t, vmcommon.IsAllowedToSaveUnderKey([]byte("ordinary-user-key")))
	require.True(t, process.IsAllowedToSaveUnderKey([]byte("ordinary-user-key")))
}
