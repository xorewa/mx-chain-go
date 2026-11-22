package block

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	coreblock "github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// G12 EXPERIMENTAL native-boundary fixtures only. These tests enter the real
// block-owned persistence/reset routines with native AccountsDB and data tries.
// They do not install an S1 route, choose a protected record namespace, establish
// canonicality, retain physical roots, or qualify gas/output/cache recovery.
var qualS1NativeAddress = bytes.Repeat([]byte{0x61}, 32)
var qualS1NativeKey = []byte("fixture/s1/native-joint")

type qualS1NativeStore struct {
	state.AccountsAdapter
	commits, epochCommits int
	epochs                [2]uint32
	afterCommit           error
}

func (s *qualS1NativeStore) Commit() ([]byte, error) {
	s.commits++
	root, err := s.AccountsAdapter.Commit()
	if err == nil {
		err = s.afterCommit
	}
	return root, err
}

func (s *qualS1NativeStore) CommitInEpoch(current, target uint32) ([]byte, error) {
	s.epochCommits++
	s.epochs = [2]uint32{current, target}
	root, err := s.AccountsAdapter.CommitInEpoch(current, target)
	if err == nil {
		err = s.afterCommit
	}
	return root, err
}

func qualS1NativeWrite(t *testing.T, db state.AccountsAdapter, balance int64, value string) {
	t.Helper()
	a, err := db.LoadAccount(qualS1NativeAddress)
	require.NoError(t, err)
	u := a.(state.UserAccountHandler)
	require.NoError(t, u.AddToBalance(new(big.Int).Sub(big.NewInt(balance), u.GetBalance())))
	require.NoError(t, u.SaveKeyValue(bytes.Clone(qualS1NativeKey), []byte(value)))
	require.NoError(t, db.SaveAccount(u))
}

func qualS1NativeRead(t *testing.T, db state.AccountsAdapter, balance int64, value string) {
	t.Helper()
	a, err := db.GetExistingAccount(qualS1NativeAddress)
	require.NoError(t, err)
	u := a.(state.UserAccountHandler)
	require.Equal(t, big.NewInt(balance), u.GetBalance())
	got, _, err := u.RetrieveValue(qualS1NativeKey)
	require.NoError(t, err)
	require.Equal(t, []byte(value), got)
}

func qualS1NativeFixture(t *testing.T, auto bool) (*baseProcessor, *qualS1NativeStore, *testscommon.MemDbMock, []byte) {
	t.Helper()
	db := testscommon.NewMemDbMock()
	accounts, _ := qualAccountDB(t, db, auto)
	qualS1NativeWrite(t, accounts, 100, "predecessor") // G12 EXPERIMENTAL literals.
	root, err := accounts.Commit()
	require.NoError(t, err)
	store := &qualS1NativeStore{AccountsAdapter: accounts}
	bp := getDefaultBaseProcessor()
	bp.accountsDB = map[state.AccountsDbIdentifier]state.AccountsAdapter{state.UserAccountsState: store}
	bp.blockChain = &testscommon.ChainHandlerStub{GetCurrentBlockHeaderCalled: func() data.HeaderHandler {
		return &coreblock.HeaderV3{}
	}}
	return bp, store, db, bytes.Clone(root)
}

func qualS1NativeHeader(epochStart bool) data.HeaderHandler {
	// G12 EXPERIMENTAL epoch3 gives an independently known previous epoch2.
	return &testscommon.HeaderHandlerStub{EpochField: 3, IsStartOfEpochBlockCalled: func() bool { return epochStart }}
}

func TestQualDRWAS1NativeCommitStateJointWrites(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, epochStart := range []bool{false, true} {
			t.Run(fmt.Sprintf("auto_%t/epoch_start_%t", auto, epochStart), func(t *testing.T) {
				bp, store, db, oldRoot := qualS1NativeFixture(t, auto)
				qualS1NativeWrite(t, store, 90, "successor")
				require.Positive(t, store.JournalLen())
				// Independent ordinary native reference: the pinned block routine
				// delegates to Commit, or CommitInEpoch(current,current-1).
				_, refStore, _, refOldRoot := qualS1NativeFixture(t, auto)
				require.Equal(t, oldRoot, refOldRoot)
				qualS1NativeWrite(t, refStore, 90, "successor")
				var expectedRoot []byte
				var err error
				if epochStart {
					expectedRoot, err = refStore.AccountsAdapter.CommitInEpoch(3, 2)
				} else {
					expectedRoot, err = refStore.AccountsAdapter.Commit()
				}
				require.NoError(t, err)
				require.NoError(t, bp.commitState(qualS1NativeHeader(epochStart)))
				require.Zero(t, store.JournalLen())
				root, err := store.RootHash()
				require.NoError(t, err)
				require.Equal(t, expectedRoot, root)
				require.NotEqual(t, oldRoot, root)
				if epochStart {
					require.Equal(t, 1, store.epochCommits)
					require.Zero(t, store.commits)
					require.Equal(t, [2]uint32{3, 2}, store.epochs)
				} else {
					require.Equal(t, 1, store.commits)
					require.Zero(t, store.epochCommits)
				}
				for _, view := range []struct {
					root    []byte
					balance int64
					value   string
				}{{oldRoot, 100, "predecessor"}, {root, 90, "successor"}} {
					fresh, _ := qualAccountDB(t, db, auto)
					require.NoError(t, fresh.RecreateTrie(holders.NewDefaultRootHashesHolder(view.root)))
					qualS1NativeRead(t, fresh, view.balance, view.value)
				}
			})
		}
	}
}

func TestQualDRWAS1NativeBlockResetJointWrites(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprintf("auto_%t", auto), func(t *testing.T) {
			bp, store, db, oldRoot := qualS1NativeFixture(t, auto)
			qualS1NativeWrite(t, store, 90, "successor")
			dirtyRoot, err := store.RootHash()
			require.NoError(t, err)
			require.NotEqual(t, oldRoot, dirtyRoot)
			require.Positive(t, store.JournalLen())
			bp.RevertCurrentBlock()
			require.Zero(t, store.JournalLen())
			require.Zero(t, store.commits)
			require.Zero(t, store.epochCommits)
			root, err := store.RootHash()
			require.NoError(t, err)
			require.Equal(t, oldRoot, root)
			qualS1NativeRead(t, store, 100, "predecessor")
			fresh, _ := qualAccountDB(t, db, auto)
			require.NoError(t, fresh.RecreateTrie(holders.NewDefaultRootHashesHolder(oldRoot)))
			qualS1NativeRead(t, fresh, 100, "predecessor")
		})
	}
}

func TestQualDRWAS1NativePostCommitErrorNeedsRetainedRoot(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, epochStart := range []bool{false, true} {
			t.Run(fmt.Sprintf("auto_%t/epoch_start_%t", auto, epochStart), func(t *testing.T) {
				bp, store, db, oldRoot := qualS1NativeFixture(t, auto)
				qualS1NativeWrite(t, store, 90, "successor")
				original := errors.New("G12 EXPERIMENTAL after-native-persistence")
				store.afterCommit = original
				require.Same(t, original, bp.commitState(qualS1NativeHeader(epochStart)))
				require.Zero(t, store.JournalLen())
				persisted, err := store.RootHash()
				require.NoError(t, err)
				require.NotEqual(t, oldRoot, persisted)
				fresh, _ := qualAccountDB(t, db, auto)
				require.NoError(t, fresh.RecreateTrie(holders.NewDefaultRootHashesHolder(persisted)))
				qualS1NativeRead(t, fresh, 90, "successor")
				// Native journal reset targets its latest committed root. This
				// observation does not assert S1 containment or authorize retry.
				bp.RevertCurrentBlock()
				after, err := store.RootHash()
				require.NoError(t, err)
				require.Equal(t, persisted, after)
				qualS1NativeRead(t, store, 90, "successor")
				require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(oldRoot)))
				qualS1NativeRead(t, store, 100, "predecessor")
				after, err = store.RootHash()
				require.NoError(t, err)
				require.Equal(t, oldRoot, after)
				require.Equal(t, 1, store.commits+store.epochCommits)
			})
		}
	}
}
