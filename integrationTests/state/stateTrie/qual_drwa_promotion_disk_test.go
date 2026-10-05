package stateTrie

import (
	"bytes"
	"fmt"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/integrationTests"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE Part A 6.1 AR-01 storage/rollback construction, extending the
// in-memory promotion boundary with native LevelDB close/reopen and fresh caches.
// The caller-selected roots and promotion eligibility remain TRUSTED fixtures:
// no bootstrap root selection, M/B finality, pruning, process crash, power-loss,
// gas/log/SCR journal, cross-shard or production key/profile claim is made.
// The five writes stand for an already-authorized promotion and its dependent
// account effect. They do not implement an import producer or a GAS consumer.
func TestQualDRWAPromotionDiskReopen(t *testing.T) {
	for _, balanced := range []bool{false, true} {
		for stopAfter := 0; stopAfter <= 5; stopAfter++ {
			t.Run(fmt.Sprintf("balanced_%t_after_%d", balanced, stopAfter), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "accounts")
				// Fixture resource settings follow storageunit_test.go:77-85.
				// Each opening creates a NEW persister, cache, storage manager,
				// trie, account factory and AccountsDB over the same files.
				open := func() (*state.AccountsDB, func()) {
					cache, err := storageunit.NewCache(storageunit.CacheConfig{
						Type: storageunit.LRUCache, Capacity: 100,
					})
					require.NoError(t, err)
					persister, err := storageunit.NewDB(storageunit.ArgDB{
						DBType: storageunit.LvlDBSerial, Path: path,
						BatchDelaySeconds: 5, MaxBatchSize: 10, MaxOpenFiles: 10,
					})
					require.NoError(t, err)
					store, err := storageunit.NewStorageUnit(cache, persister)
					require.NoError(t, err)
					manager, _ := integrationTests.CreateTrieStorageManager(store)
					require.NotNil(t, manager)
					flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
					if balanced {
						flags.AddActiveFlags(common.AutoBalanceDataTriesFlag)
					}
					adb, _ := integrationTests.CreateAccountsDBWithEnableEpochsHandler(integrationTests.UserAccount, manager, flags)
					require.NotNil(t, adb)
					closed := false
					closeDB := func() {
						if closed {
							return
						}
						closed = true
						accountErr := adb.Close()
						// AccountsDB.Close does NOT close its storage manager.
						// Native storage Close flushes the persister's batch.
						storageErr := manager.Close()
						require.NoError(t, accountErr)
						require.NoError(t, storageErr)
						require.True(t, manager.IsClosed())
					}
					t.Cleanup(closeDB)
					return adb, closeDB
				}
				adb, closeDB := open()
				control := bytes.Repeat([]byte{41}, 32)
				consumer := bytes.Repeat([]byte{42}, 32)
				keys := [][]byte{
					qualProtectedFixtureKey([]byte("token-A"), []byte("final/record")),
					qualProtectedFixtureKey([]byte("token-A"), []byte("pending/record")),
					qualProtectedFixtureKey([]byte("token-A"), []byte("item/origin")),
					qualProtectedFixtureKey([]byte("token-A"), []byte("ack/phase-A")),
				}
				write := func(address, key, value []byte) {
					account, err := adb.LoadAccount(address)
					require.NoError(t, err)
					require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, value))
					require.NoError(t, adb.SaveAccount(account))
				}
				read := func(address, key []byte) []byte {
					account, err := adb.GetExistingAccount(address)
					require.NoError(t, err)
					value, _, err := account.(state.UserAccountHandler).RetrieveValue(key)
					require.NoError(t, err, "storage errors cannot become absence")
					return value
				}
				write(control, keys[0], []byte("predecessor-A"))
				write(control, keys[1], []byte("candidate-B"))
				write(control, keys[2], []byte("result-S"))
				write(consumer, []byte("ordinary"), []byte("untouched"))
				account, err := adb.GetExistingAccount(consumer)
				require.NoError(t, err)
				require.NoError(t, account.(state.UserAccountHandler).AddToBalance(big.NewInt(100)))
				require.NoError(t, adb.SaveAccount(account))
				parent, err := adb.Commit()
				require.NoError(t, err)
				steps := []func(){
					func() { write(control, keys[0], []byte("candidate-B")) },
					func() { write(control, keys[1], nil) },
					func() { write(control, keys[2], nil) },
					func() { write(control, keys[3], []byte("canonical-result-S")) },
					func() {
						account, loadErr := adb.GetExistingAccount(consumer)
						require.NoError(t, loadErr)
						user := account.(state.UserAccountHandler)
						require.NoError(t, user.SaveKeyValue([]byte("dependent-effect"), []byte("consumed-B")))
						require.NoError(t, user.AddToBalance(big.NewInt(7)))
						require.NoError(t, adb.SaveAccount(account))
					},
				}
				assertState := func(promoted bool) {
					t.Helper()
					expectedFinal, expectedPending, expectedItem := []byte("predecessor-A"), []byte("candidate-B"), []byte("result-S")
					var expectedAck, expectedEffect []byte
					expectedBalance := int64(100)
					if promoted {
						expectedFinal, expectedPending, expectedItem = []byte("candidate-B"), nil, nil
						expectedAck, expectedEffect = []byte("canonical-result-S"), []byte("consumed-B")
						expectedBalance = 107
					}
					for i, expected := range [][]byte{expectedFinal, expectedPending, expectedItem, expectedAck} {
						require.Equal(t, expected, read(control, keys[i]))
					}
					require.Equal(t, expectedEffect, read(consumer, []byte("dependent-effect")))
					require.Equal(t, []byte("untouched"), read(consumer, []byte("ordinary")))
					account, getErr := adb.GetExistingAccount(consumer)
					require.NoError(t, getErr)
					require.Equal(t, big.NewInt(expectedBalance), account.(state.UserAccountHandler).GetBalance())
				}
				for i := 0; i < stopAfter; i++ {
					steps[i]()
				}
				partial, err := adb.RootHash()
				require.NoError(t, err)
				if stopAfter != 0 {
					require.NotEqual(t, parent, partial)
				}
				closeDB() // deliberately NO AccountsDB.Commit for this partial branch
				adb, closeDB = open()
				require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(parent)))
				assertState(false)
				if stopAfter != 0 {
					require.Error(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(partial)),
						"an uncommitted root cannot be reconstructed from a fresh disk store")
					require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(parent)))
					assertState(false)
				}

				// The old committed item must still produce a native witness
				// after reopening; no retained account pointer or proof is used.
				main, err := adb.GetTrie(parent)
				require.NoError(t, err)
				accountNodes, _, err := main.GetProof(control)
				require.NoError(t, err)
				account, err = adb.GetExistingAccount(control)
				require.NoError(t, err)
				data, err := adb.GetTrie(account.(state.UserAccountHandler).GetRootHash())
				require.NoError(t, err)
				storedKey := keys[2]
				flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
				if balanced {
					flags.AddActiveFlags(common.AutoBalanceDataTriesFlag)
					storedKey = integrationTests.TestHasher.Compute(string(storedKey))
				}
				dataNodes, _, err := data.GetProof(storedKey)
				require.NoError(t, err)
				budget := 0
				for _, nodes := range [][][]byte{accountNodes, dataNodes} {
					for _, node := range nodes {
						budget += len(node)
					}
				}
				item, err := qualReadAccountWitness(t, parent, control, keys[2], accountNodes, dataNodes, budget, flags)
				require.NoError(t, err)
				require.Equal(t, []byte("result-S"), item)

				for _, step := range steps {
					step()
				}
				promoted, err := adb.Commit()
				require.NoError(t, err)
				require.NotEqual(t, parent, promoted)
				closeDB()
				adb, closeDB = open()
				require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(promoted)))
				assertState(true)

				// Exercise real cache invalidation and all-account restoration
				// after reading the promoted branch. Branch selection is trusted.
				require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(parent)))
				assertState(false)
				for _, step := range steps {
					step()
				}
				replayed, err := adb.Commit()
				require.NoError(t, err)
				require.Equal(t, promoted, replayed, "restored replay cannot double the dependent balance effect")
				closeDB()
				adb, closeDB = open()
				require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(replayed)))
				assertState(true)
				closeDB()
			})
		}
	}
}
