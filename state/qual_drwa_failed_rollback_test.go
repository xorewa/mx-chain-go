package state_test

import (
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/stateChange"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/testscommon"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Bind all callback-backed operations reached by the stub-trie probes. Tests
// override only the operation at which they inject a fault.
func qualFailedRollbackArgs() state.ArgsAccountsDB {
	args := createMockAccountsDBArgs()
	args.SnapshotsManager = stateDisabled.NewDisabledSnapshotsManager()
	stats := &testscommon.StateStatisticsHandlerStub{
		ProcessingStatsCalled: func() []string { return nil },
		ResetCalled:           func() {},
	}
	manager := &storageManager.StorageManagerStub{
		GetStateStatsHandlerCalled:    func() common.StateStatisticsHandler { return stats },
		SetEpochForPutOperationCalled: func(uint32) {},
	}
	tr := args.Trie.(*trieMock.TrieStub)
	tr.GetCalled = func([]byte) ([]byte, uint32, error) { return nil, 0, nil }
	tr.UpdateCalled = func([]byte, []byte) error { return nil }
	tr.RootCalled = func() ([]byte, error) { return []byte("root"), nil }
	tr.CommitCalled = func() error { return nil }
	tr.GetOldRootCalled = func() []byte { return nil }
	tr.GetStorageManagerCalled = func() common.StorageManager { return manager }
	tr.RecreateCalled = func(common.RootHashHolder) (common.Trie, error) { return tr, nil }
	args.StateAccessesCollector = &stateMock.StateAccessesCollectorStub{
		IsInterfaceNilCalled:                func() bool { return false },
		SetIndexToLatestStateAccessesCalled: func(int) error { return nil },
		RevertToIndexCalled:                 func(int) error { return nil },
		ResetCalled:                         func() {},
		CommitCollectedAccessesCalled:       func([]byte) error { return nil },
		GetAccountChangesCalled:             func(vmcommon.AccountHandler, vmcommon.AccountHandler) uint32 { return stateChange.NoChange },
		AddStateChangeCalled:                func(*stateChange.StateAccess) {},
	}
	return args
}

// Part A 5.4 P-05: a rollback error must not leave a writable/committable
// partially restored execution context. The oracle is this requirement;
// journal length alone, including zero, is deliberately insufficient.
func TestQualDRWAFailedRollbackBlocksEffects(t *testing.T) {
	for _, phase := range []string{"entry", "account_save", "collector", "zero_snapshot", "invalid_snapshot"} {
		t.Run(phase, func(t *testing.T) {
			fault := errors.New("injected rollback failure")
			args := qualFailedRollbackArgs()
			tr := args.Trie.(*trieMock.TrieStub)
			tr.RootCalled = func() ([]byte, error) { return []byte("root"), nil }
			commits, writes, undoCalls := 0, 0, 0
			tr.CommitCalled = func() error { commits++; return nil }
			tr.UpdateCalled = func([]byte, []byte) error {
				writes++
				if phase == "account_save" {
					return fault
				}
				return nil
			}
			tr.RecreateCalled = func(common.RootHashHolder) (common.Trie, error) {
				if phase == "zero_snapshot" {
					return nil, fault
				}
				return tr, nil
			}
			args.StateAccessesCollector.(*stateMock.StateAccessesCollectorStub).RevertToIndexCalled = func(int) error {
				if phase == "collector" {
					return fault
				}
				return nil
			}
			adb, err := state.NewAccountsDB(args)
			require.NoError(t, err)
			adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) { return nil, nil }})
			adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) {
				undoCalls++
				if phase == "entry" {
					return nil, fault
				}
				if phase == "account_save" {
					return stateMock.NewAccountWrapMock([]byte("account")), nil
				}
				return nil, nil
			}})
			snapshot := 1
			if phase == "zero_snapshot" {
				snapshot = 0
			}
			if phase == "invalid_snapshot" {
				snapshot = -1
				fault = state.ErrSnapshotValueOutOfBounds
			}
			require.ErrorIs(t, adb.RevertToSnapshot(snapshot), fault)
			writesAfterRollback := writes
			journalAfterRollback := adb.JournalLen()
			_, err = adb.Commit()
			require.ErrorIs(t, err, fault, "failed rollback must bar commit even when its journal was cleared")
			_, err = adb.CommitInEpoch(7, 6)
			require.ErrorIs(t, err, fault)
			account := stateMock.NewAccountWrapMock([]byte("account"))
			require.ErrorIs(t, adb.SaveAccount(account), fault)
			require.ErrorIs(t, adb.ImportAccount(account), fault)
			require.ErrorIs(t, adb.RemoveAccount(account.AddressBytes()), fault)
			_, err = adb.LoadAccount(account.AddressBytes())
			require.ErrorIs(t, err, fault)
			_, err = adb.GetExistingAccount(account.AddressBytes())
			require.ErrorIs(t, err, fault)
			_, err = adb.RootHash()
			require.ErrorIs(t, err, fault)
			_, err = adb.GetAccountFromBytes(account.AddressBytes(), []byte("account bytes"))
			require.ErrorIs(t, err, fault)
			require.Nil(t, adb.GetCode([]byte("code")))
			require.Zero(t, commits)
			require.Equal(t, writesAfterRollback, writes)
			require.Equal(t, journalAfterRollback, adb.JournalLen())
			if snapshot > 0 {
				require.ErrorIs(t, adb.RevertToSnapshot(snapshot+1), fault, "a later snapshot cannot certify the failed earlier undo")
				require.Equal(t, 1, undoCalls)
			}
		})
	}
}

// Uses a real native trie and account/data-trie journal. The injected last
// journal entry fails undo after a balance and protocol-key mutation. No node,
// VM, persistent network, DRWA admission or canonical-finality claim is made.
func TestQualDRWAFailedRollbackRealTrieRecovery(t *testing.T) {
	_, adb := getDefaultTrieAndAccountsDb()
	t.Cleanup(func() { require.NoError(t, adb.Close()) })
	address := []byte("ordinary account for rollback")
	account, err := adb.LoadAccount(address)
	require.NoError(t, err)
	user := account.(state.UserAccountHandler)
	require.NoError(t, user.AddToBalance(big.NewInt(20)))
	require.NoError(t, user.SaveKeyValue([]byte("protocol-key"), []byte("committed")))
	require.NoError(t, adb.SaveAccount(user))
	root, err := adb.Commit()
	require.NoError(t, err)
	account, err = adb.LoadAccount(address)
	require.NoError(t, err)
	user = account.(state.UserAccountHandler)
	require.NoError(t, user.AddToBalance(big.NewInt(5)))
	require.NoError(t, user.SaveKeyValue([]byte("protocol-key"), []byte("partial")))
	require.NoError(t, adb.SaveAccount(user))
	fault := errors.New("injected final entry undo failure")
	snapshot := adb.JournalLen()
	adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) { return nil, fault }})
	require.ErrorIs(t, adb.RevertToSnapshot(snapshot), fault)
	_, err = adb.Commit()
	require.ErrorIs(t, err, fault)
	_, err = adb.LoadAccount(address)
	require.ErrorIs(t, err, fault)
	require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	account, err = adb.LoadAccount(address)
	require.NoError(t, err)
	user = account.(state.UserAccountHandler)
	require.Equal(t, big.NewInt(20), user.GetBalance())
	value, _, err := user.RetrieveValue([]byte("protocol-key"))
	require.NoError(t, err)
	require.Equal(t, []byte("committed"), value)
	actualRoot, err := adb.Commit()
	require.NoError(t, err)
	require.Equal(t, root, actualRoot, "all account/data-trie effects restored at the native commit boundary")
}

func TestQualDRWAFailedRollbackFailedReconstructionRemainsBlocked(t *testing.T) {
	fault, rebuildFault := errors.New("undo failed"), errors.New("rebuild failed")
	args := qualFailedRollbackArgs()
	tr := args.Trie.(*trieMock.TrieStub)
	tr.RootCalled = func() ([]byte, error) { return []byte("same root"), nil }
	rebuilds := 0
	tr.RecreateCalled = func(common.RootHashHolder) (common.Trie, error) {
		rebuilds++
		if rebuilds <= 2 {
			return nil, rebuildFault
		}
		return tr, nil
	}
	adb, err := state.NewAccountsDB(args)
	require.NoError(t, err)
	adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) { return nil, nil }})
	adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) { return nil, fault }})
	require.ErrorIs(t, adb.RevertToSnapshot(1), fault)
	options := holders.NewDefaultRootHashesHolder([]byte("same root"))
	require.ErrorIs(t, adb.RecreateTrieIfNeeded(options), rebuildFault)
	require.Zero(t, adb.JournalLen(), "zero journal does not certify a successful reconstruction")
	_, err = adb.Commit()
	require.ErrorIs(t, err, fault)
	err = adb.RevertToSnapshot(0)
	require.ErrorIs(t, err, fault)
	require.ErrorIs(t, err, rebuildFault)
	_, err = adb.RootHash()
	require.ErrorIs(t, err, fault)
	require.NoError(t, adb.RecreateTrieIfNeeded(options))
	require.Equal(t, 3, rebuilds)
	_, err = adb.RootHash()
	require.NoError(t, err)
}

func TestQualDRWAFailedRollbackRecovery(t *testing.T) {
	for _, recovery := range []string{"retry", "earlier_snapshot", "zero_snapshot", "recreate", "equal_root_recreate"} {
		t.Run(recovery, func(t *testing.T) {
			fault := errors.New("injected entry failure")
			args := qualFailedRollbackArgs()
			tr := args.Trie.(*trieMock.TrieStub)
			root := []byte("committed root")
			tr.CommitCalled = func() error { return nil }
			tr.RootCalled = func() ([]byte, error) { return root, nil }
			recreates, completed, attempts := 0, 0, 0
			tr.RecreateCalled = func(common.RootHashHolder) (common.Trie, error) { recreates++; return tr, nil }
			adb, err := state.NewAccountsDB(args)
			require.NoError(t, err)
			adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) { return nil, nil }})
			adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) { return nil, nil }})
			adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) {
				attempts++
				if attempts == 1 {
					return nil, fault
				}
				return nil, nil
			}})
			adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) { completed++; return nil, nil }})
			require.ErrorIs(t, adb.RevertToSnapshot(2), fault)
			_, err = adb.Commit()
			require.ErrorIs(t, err, fault)
			require.Equal(t, 3, adb.JournalLen())
			switch recovery {
			case "retry":
				require.NoError(t, adb.RevertToSnapshot(2))
				require.Equal(t, 2, adb.JournalLen())
			case "earlier_snapshot":
				require.NoError(t, adb.RevertToSnapshot(1))
				require.Equal(t, 1, adb.JournalLen())
			case "zero_snapshot":
				require.NoError(t, adb.RevertToSnapshot(0))
				require.Zero(t, adb.JournalLen())
			case "recreate":
				require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
				require.Zero(t, adb.JournalLen())
			case "equal_root_recreate":
				require.NoError(t, adb.RecreateTrieIfNeeded(holders.NewDefaultRootHashesHolder(root)))
				require.Zero(t, adb.JournalLen())
			}
			require.Equal(t, 1, completed, "completed native undo is never repeated")
			if recovery == "retry" || recovery == "earlier_snapshot" {
				require.Equal(t, 2, attempts)
				require.Zero(t, recreates)
			} else {
				require.Equal(t, 1, attempts)
				require.Equal(t, 1, recreates)
			}
			_, err = adb.RootHash()
			require.NoError(t, err)
			_, err = adb.Commit()
			require.NoError(t, err)
		})
	}
}

func TestQualDRWAFailedRollbackConcurrentCommit(t *testing.T) {
	args := qualFailedRollbackArgs()
	tr := args.Trie.(*trieMock.TrieStub)
	tr.RootCalled = func() ([]byte, error) { return []byte("root"), nil }
	entered, release := make(chan struct{}), make(chan struct{})
	fault := errors.New("blocked undo failed")
	commits := 0
	tr.CommitCalled = func() error { commits++; return nil }
	adb, err := state.NewAccountsDB(args)
	require.NoError(t, err)
	adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) { return nil, nil }})
	adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) { close(entered); <-release; return nil, fault }})
	var wg sync.WaitGroup
	wg.Add(2)
	revertResult, commitResult := make(chan error, 1), make(chan error, 1)
	go func() { defer wg.Done(); revertResult <- adb.RevertToSnapshot(1) }()
	<-entered
	go func() { defer wg.Done(); _, e := adb.Commit(); commitResult <- e }()
	close(release)
	wg.Wait()
	require.ErrorIs(t, <-revertResult, fault)
	require.ErrorIs(t, <-commitResult, fault)
	require.Zero(t, commits)
}

// T04-SR-01: after a failed retry towards an earlier boundary, the old later
// boundary cannot certify restoration. Both undo failures must remain visible.
func TestQualDRWAFailedRollbackEarlierRetryCannotClearLatch(t *testing.T) {
	first, earlier := errors.New("first undo failed"), errors.New("earlier undo failed")
	adb, err := state.NewAccountsDB(qualFailedRollbackArgs())
	require.NoError(t, err)
	adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) { return nil, nil }})
	earlierAttempts, laterAttempts := 0, 0
	adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) {
		earlierAttempts++
		if earlierAttempts == 1 {
			return nil, earlier
		}
		return nil, nil
	}})
	adb.Journalize(&journalEntryStub{revertCalled: func() (vmcommon.AccountHandler, error) {
		laterAttempts++
		if laterAttempts == 1 {
			return nil, first
		}
		return nil, nil
	}})
	require.ErrorIs(t, adb.RevertToSnapshot(2), first)
	err = adb.RevertToSnapshot(1)
	require.ErrorIs(t, err, first)
	require.ErrorIs(t, err, earlier)
	err = adb.RevertToSnapshot(2)
	require.ErrorIs(t, err, first, "the old boundary must not clear the failed earlier retry")
	require.ErrorIs(t, err, earlier)
	_, err = adb.Commit()
	require.ErrorIs(t, err, first)
	require.ErrorIs(t, err, earlier)
	require.Equal(t, 1, earlierAttempts)
	require.Equal(t, 2, laterAttempts)
	require.NoError(t, adb.RevertToSnapshot(1))
	_, err = adb.Commit()
	require.NoError(t, err)
	require.Equal(t, 2, earlierAttempts)
	require.Equal(t, 2, laterAttempts)
}
