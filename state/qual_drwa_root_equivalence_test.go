package state_test

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

// The same file is executed unchanged on 06c383cf and the T04 descendant.
// Roots are compared between those executions, never used as a self-generated
// expectation for balances, data, undo or reconstruction.
func TestQualDRWARootHashRealTrieEquivalence(t *testing.T) {
	_, adb := getDefaultTrieAndAccountsDb()
	t.Cleanup(func() { require.NoError(t, adb.Close()) })
	address := []byte("ordinary equivalence account")
	account, err := adb.LoadAccount(address)
	require.NoError(t, err)
	user := account.(state.UserAccountHandler)
	require.NoError(t, user.AddToBalance(big.NewInt(20)))
	require.NoError(t, user.SaveKeyValue([]byte("record"), []byte("original")))
	user.SetCode([]byte("ordinary code"))
	require.NoError(t, adb.SaveAccount(user))
	root, err := adb.Commit()
	require.NoError(t, err)
	roots := []string{hex.EncodeToString(root)}
	for i := 0; i < 3; i++ {
		observed, rootErr := adb.RootHash()
		require.NoError(t, rootErr)
		require.Equal(t, root, observed)
	}
	account, err = adb.GetExistingAccount(address)
	require.NoError(t, err)
	user = account.(state.UserAccountHandler)
	require.Equal(t, big.NewInt(20), user.GetBalance())
	require.Equal(t, []byte("ordinary code"), adb.GetCode(user.GetCodeHash()))
	// Positive snapshot undo retains a prior mutation; full reconstruction uses
	// the committed authoritative root after further ordinary mutations.
	require.NoError(t, user.AddToBalance(big.NewInt(2)))
	require.NoError(t, adb.SaveAccount(user))
	snapshot := adb.JournalLen()
	require.NoError(t, user.AddToBalance(big.NewInt(3)))
	require.NoError(t, user.SaveKeyValue([]byte("record"), []byte("changed")))
	require.NoError(t, adb.SaveAccount(user))
	require.NoError(t, adb.RevertToSnapshot(snapshot))
	account, err = adb.GetExistingAccount(address)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(22), account.(state.UserAccountHandler).GetBalance())
	observed, err := adb.RootHash()
	require.NoError(t, err)
	roots = append(roots, hex.EncodeToString(observed))
	require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	require.NoError(t, adb.RecreateTrieIfNeeded(holders.NewDefaultRootHashesHolder(root)))
	account, err = adb.GetExistingAccount(address)
	require.NoError(t, err)
	user = account.(state.UserAccountHandler)
	require.Equal(t, big.NewInt(20), user.GetBalance())
	value, _, err := user.RetrieveValue([]byte("record"))
	require.NoError(t, err)
	require.Equal(t, []byte("original"), value)
	observed, err = adb.CommitInEpoch(1, 0)
	require.NoError(t, err)
	require.Equal(t, root, observed)
	roots = append(roots, hex.EncodeToString(observed))
	encoded, err := json.Marshal(roots)
	require.NoError(t, err)
	t.Logf("T04_REAL_TRIE_EQUIVALENCE %s", encoded)
}

// Measures the actual native AccountsDB and trie calls added by the four
// error-path probes and four cross-store commit preflights. Both warm and dirty
// roots are included; this is a microbenchmark, not a block-throughput claim.
func TestQualDRWARootHashRealTrieBenchmark(t *testing.T) {
	_, adb := getDefaultTrieAndAccountsDb()
	t.Cleanup(func() { require.NoError(t, adb.Close()) })
	for i := byte(0); i < 32; i++ {
		account, err := adb.LoadAccount([]byte{1, i})
		require.NoError(t, err)
		require.NoError(t, account.(state.UserAccountHandler).AddToBalance(big.NewInt(20)))
		require.NoError(t, adb.SaveAccount(account))
	}
	_, err := adb.Commit()
	require.NoError(t, err)
	warm := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, rootErr := adb.RootHash(); rootErr != nil {
				b.Fatal(rootErr)
			}
		}
	})
	account, err := adb.LoadAccount([]byte{1, 0})
	require.NoError(t, err)
	user := account.(state.UserAccountHandler)
	dirty := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			if saveErr := user.AddToBalance(big.NewInt(1)); saveErr != nil {
				b.Fatal(saveErr)
			}
			if saveErr := adb.SaveAccount(user); saveErr != nil {
				b.Fatal(saveErr)
			}
			b.StartTimer()
			if _, rootErr := adb.RootHash(); rootErr != nil {
				b.Fatal(rootErr)
			}
		}
	})
	t.Logf("T04_ROOT_BENCHMARK warm_ns=%d warm_allocs=%d dirty_ns=%d dirty_allocs=%d", warm.NsPerOp(), warm.AllocsPerOp(), dirty.NsPerOp(), dirty.AllocsPerOp())
}
