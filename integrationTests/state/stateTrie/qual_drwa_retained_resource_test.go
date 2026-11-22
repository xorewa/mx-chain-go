package stateTrie

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE AM-014 / Part B 10.3, 11.1 storage measurements.
// Counts and payload sizes are declared SYNTHETIC experiment inputs, not
// protocol bounds, workload forecasts or availability/throughput promises.
// In-memory storage and this machine only; no disk, network, admission,
// parser execution, pruning policy, gas price or acceptance is inferred.
func TestQualDRWARetainedStateMeasurements(t *testing.T) {
	classes := []string{"intent-OPEN", "intent-CONSUMED", "intent-CANCELLED", "intent-expired-retained",
		"current-CEB", "prepared-CEB", "open-effect", "terminal-replay"}
	for _, count := range []int{8, 32} {
		for _, size := range []int{64, 4096} {
			t.Run(fmt.Sprintf("records_per_class_%d_bytes_%d", count, size), func(t *testing.T) {
				adb := createAccountsDBTestSetup()
				t.Cleanup(func() { require.NoError(t, adb.Close()) })
				address := bytes.Repeat([]byte{51}, 32)
				payload := bytes.Repeat([]byte{0x5a}, size)
				keys := make([][]byte, 0, len(classes)*count)
				started := time.Now()
				for _, class := range classes {
					for index := 0; index < count; index++ {
						key := qualProtectedFixtureKey([]byte(class), []byte(fmt.Sprint(index)))
						keys = append(keys, key)
						account, err := adb.LoadAccount(address)
						require.NoError(t, err)
						require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, payload))
						require.NoError(t, adb.SaveAccount(account))
					}
				}
				journalEntries := adb.JournalLen()
				root, err := adb.Commit()
				require.NoError(t, err)
				commitElapsed := time.Since(started)
				started = time.Now()
				require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
				account, err := adb.GetExistingAccount(address)
				require.NoError(t, err)
				for _, key := range keys {
					value, _, readErr := account.(state.UserAccountHandler).RetrieveValue(key)
					require.NoError(t, readErr)
					require.Equal(t, payload, value)
				}
				t.Logf("synthetic retained records=%d classes=%d value_bytes=%d journal_entries=%d write_commit_ns=%d recreate_read_ns=%d",
					len(keys), len(classes), len(keys)*size, journalEntries, commitElapsed.Nanoseconds(), time.Since(started).Nanoseconds())
			})
		}
	}
}

// Required three-indispensable-interpretation scenario: prove only native
// byte retention and unrelated-programme isolation here. Decoders, safe
// execution of retained meanings, authority loss and lawful NORMAL exit
// still require the D04/D08 construction and its independent review.
func TestQualDRWAThreeInterpretationRetentionStorage(t *testing.T) {
	adb := createAccountsDBTestSetup()
	t.Cleanup(func() { require.NoError(t, adb.Close()) })
	subjects := [][]byte{bytes.Repeat([]byte{61}, 32), bytes.Repeat([]byte{62}, 32)}
	keys := [][]byte{
		qualProtectedFixtureKey([]byte("interpretation-previous"), []byte("pending-effect")),
		qualProtectedFixtureKey([]byte("interpretation-current"), []byte("current-CEB")),
		qualProtectedFixtureKey([]byte("interpretation-repair"), []byte("prepared-CEB")),
	}
	values := [][]byte{[]byte("previous-meaning-required"), []byte("current-meaning-required"), []byte("repair-meaning-required")}
	put := func(subject, key, value []byte) {
		account, err := adb.LoadAccount(subject)
		require.NoError(t, err)
		require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, value))
		require.NoError(t, adb.SaveAccount(account))
	}
	for _, subject := range subjects {
		put(subject, keys[0], values[0])
	}
	oldRoot, err := adb.Commit()
	require.NoError(t, err)
	put(subjects[0], keys[1], values[1])
	put(subjects[0], keys[2], values[2])
	fullRoot, err := adb.Commit()
	require.NoError(t, err)
	require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(oldRoot)))
	require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(fullRoot)))
	for i, subject := range subjects {
		account, err := adb.GetExistingAccount(subject)
		require.NoError(t, err)
		for j, key := range keys {
			value, _, readErr := account.(state.UserAccountHandler).RetrieveValue(key)
			require.NoError(t, readErr)
			if i == 0 || j == 0 {
				require.Equal(t, values[j], value)
			} else {
				require.Empty(t, value)
			}
		}
	}
}
