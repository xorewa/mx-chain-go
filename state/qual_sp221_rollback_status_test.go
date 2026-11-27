package state_test

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-21, Part A P-05: a failed RevertToSnapshot keeps its native result and is
// carried on the store's separate status; the store refuses to commit until it
// is recreated from a committed root. Inert local fixtures only.

type qualSP221FailingEntry struct {
	err   error
	calls int
}

func (e *qualSP221FailingEntry) Revert() (vmcommon.AccountHandler, error) {
	e.calls++
	return nil, e.err
}
func (e *qualSP221FailingEntry) IsInterfaceNil() bool { return e == nil }

func qualSP221Credit(t *testing.T, adb *state.AccountsDB, address []byte, value int64) {
	t.Helper()
	account, err := adb.LoadAccount(address)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).AddToBalance(big.NewInt(value)))
	require.NoError(t, adb.SaveAccount(account))
}

func qualSP221Balance(t *testing.T, adb *state.AccountsDB, address []byte) *big.Int {
	t.Helper()
	account, err := adb.LoadAccount(address)
	require.NoError(t, err)
	return account.(state.UserAccountHandler).GetBalance()
}

func qualSP221CommittedStore(t *testing.T) (*state.AccountsDB, []byte, []byte) {
	t.Helper()
	adb := integrationtests.CreateInMemoryShardAccountsDB()
	address := bytes.Repeat([]byte{1}, 32)
	qualSP221Credit(t, adb, address, 10)
	root, err := adb.Commit()
	require.NoError(t, err)
	require.NoError(t, adb.RollbackFailure())
	return adb, address, root
}

func TestQualSP221StoreRollbackSuccessLeavesNoStatus(t *testing.T) {
	adb, address, root := qualSP221CommittedStore(t)
	qualSP221Credit(t, adb, address, 2)
	snapshot := adb.JournalLen()
	require.NotZero(t, snapshot)
	qualSP221Credit(t, adb, address, 3)
	require.NoError(t, adb.RevertToSnapshot(snapshot))
	require.NoError(t, adb.RollbackFailure())
	require.Equal(t, big.NewInt(12), qualSP221Balance(t, adb, address))
	require.NoError(t, adb.RevertToSnapshot(0))
	require.Equal(t, big.NewInt(10), qualSP221Balance(t, adb, address))
	committed, err := adb.Commit()
	require.NoError(t, err)
	require.Equal(t, root, committed)

	qualSP221Credit(t, adb, address, 5)
	require.NoError(t, adb.RevertToSnapshot(0))
	require.NoError(t, adb.RollbackFailure())
}

func TestQualSP221StoreRollbackFailureIsRetainedAndRefusesCommit(t *testing.T) {
	for _, commit := range []string{"Commit", "CommitInEpoch"} {
		for _, fault := range []string{"entry", "bounds"} {
			t.Run(commit+"/"+fault, func(t *testing.T) {
				adb, address, root := qualSP221CommittedStore(t)
				qualSP221Credit(t, adb, address, 2)
				snapshot := adb.JournalLen()
				require.NotZero(t, snapshot, "a zero snapshot would recreate the trie instead of reverting entries")
				qualSP221Credit(t, adb, address, 3)

				want := state.ErrSnapshotValueOutOfBounds
				var entry *qualSP221FailingEntry
				if fault == "entry" {
					want = errors.New("inert journal revert failure")
					entry = &qualSP221FailingEntry{err: want}
					adb.QualSP221Journalize(entry)
				} else {
					snapshot = adb.JournalLen() + 1
				}

				err := adb.RevertToSnapshot(snapshot)
				require.Same(t, want, err, "the caller receives the native error value")
				status := adb.RollbackFailure()
				require.ErrorIs(t, status, state.ErrRollbackFailed)
				require.ErrorIs(t, status, want)
				if entry != nil {
					require.Equal(t, 1, entry.calls)
				}
				// The mutation was neither kept by a commit nor undone.
				require.Equal(t, big.NewInt(15), qualSP221Balance(t, adb, address))

				// A second failure does not replace the first one.
				require.Same(t, state.ErrSnapshotValueOutOfBounds, adb.RevertToSnapshot(adb.JournalLen()+1))
				require.Same(t, status, adb.RollbackFailure())

				var committed []byte
				if commit == "Commit" {
					committed, err = adb.Commit()
				} else {
					committed, err = adb.CommitInEpoch(0, 0)
				}
				require.Same(t, status, err)
				require.Nil(t, committed)

				// Permitted recovery: recreate from the committed root.
				require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
				require.NoError(t, adb.RollbackFailure())
				require.Equal(t, big.NewInt(10), qualSP221Balance(t, adb, address))
				committed, err = adb.Commit()
				require.NoError(t, err)
				require.Equal(t, root, committed)
			})
		}
	}
}

func TestQualSP221StoreFullRevertClearsRetainedFailure(t *testing.T) {
	adb, address, root := qualSP221CommittedStore(t)
	qualSP221Credit(t, adb, address, 5)
	require.Same(t, state.ErrSnapshotValueOutOfBounds, adb.RevertToSnapshot(adb.JournalLen()+1))
	require.Error(t, adb.RollbackFailure())

	require.NoError(t, adb.RevertToSnapshot(0))
	require.NoError(t, adb.RollbackFailure())
	require.Equal(t, big.NewInt(10), qualSP221Balance(t, adb, address))
	current, err := adb.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, current)
}
