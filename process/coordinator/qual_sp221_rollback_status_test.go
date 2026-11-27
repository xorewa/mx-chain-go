package coordinator

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/block/processedMb"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	commonMock "github.com/multiversx/mx-chain-go/testscommon/common"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	"github.com/multiversx/mx-chain-go/testscommon/preprocMocks"
)

// qualSP221Store is the real account store. With failRevert set, the store's
// own RevertToSnapshot fails (snapshot out of bounds). Inert local fixture.
type qualSP221Store struct {
	*state.AccountsDB
	failRevert bool
	reverts    int
}

func (s *qualSP221Store) RevertToSnapshot(snapshot int) error {
	s.reverts++
	if s.failRevert {
		return s.AccountsDB.RevertToSnapshot(s.AccountsDB.JournalLen() + 1)
	}
	return s.AccountsDB.RevertToSnapshot(snapshot)
}

func (s *qualSP221Store) credit(t *testing.T, address []byte, value int64) {
	t.Helper()
	account, err := s.AccountsDB.LoadAccount(address)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).AddToBalance(big.NewInt(value)))
	require.NoError(t, s.AccountsDB.SaveAccount(account))
}

func (s *qualSP221Store) balance(t *testing.T, address []byte) int64 {
	t.Helper()
	account, err := s.AccountsDB.LoadAccount(address)
	require.NoError(t, err)
	return account.(state.UserAccountHandler).GetBalance().Int64()
}

// SP2-21, Part A P-05, INV-0: the coordinator's miniblock cleanup returns the
// native error value when its rollback fails; the failure is on the status.
func TestQualSP221CoordinatorRollbackStatus(t *testing.T) {
	holder, marker := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{3}, 32)
	for _, rollbackFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("rollback_fails_%t", rollbackFails), func(t *testing.T) {
			failure := errors.New("inert processing failure")
			store := &qualSP221Store{AccountsDB: integrationtests.CreateInMemoryShardAccountsDB(), failRevert: rollbackFails}
			store.credit(t, holder, 10)
			root, err := store.Commit()
			require.NoError(t, err)

			hash, txHash := []byte("mb"), []byte("tx")
			c := &transactionCoordinator{
				accounts:                store,
				gasHandler:              &testscommon.GasHandlerStub{},
				feeHandler:              &mock.FeeAccumulatorStub{},
				txExecutionOrderHandler: &commonMock.TxExecutionOrderHandlerStub{},
			}
			mb := &block.MiniBlock{TxHashes: [][]byte{txHash}}
			pp := &preprocMocks.PreProcessorMock{ProcessMiniBlockCalled: func(*block.MiniBlock, func() bool, func() bool, bool, bool, int, process.PreProcessorExecutionInfoHandler) ([][]byte, int, bool, error) {
				store.credit(t, marker, 5)
				return [][]byte{txHash}, 0, true, failure
			}}
			info := &processedMb.ProcessedMiniBlockInfo{IndexOfLastTxProcessed: -1}
			err = c.processCompleteMiniBlock(pp, mb, hash, func() bool { return true }, func() bool { return false }, false, true, info, []byte("header"), process.GasProcessingPolicy{})
			require.Same(t, failure, err, "the native error value is returned unchanged")
			require.False(t, info.FullyProcessed)
			require.Equal(t, int32(-1), info.IndexOfLastTxProcessed)
			require.Equal(t, 1, store.reverts)

			if !rollbackFails {
				require.NoError(t, store.RollbackFailure())
				require.Zero(t, store.balance(t, marker))
				committed, commitErr := store.Commit()
				require.NoError(t, commitErr)
				require.Equal(t, root, committed)
				return
			}
			status := store.RollbackFailure()
			require.ErrorIs(t, status, state.ErrRollbackFailed)
			require.ErrorIs(t, status, state.ErrSnapshotValueOutOfBounds)
			require.EqualValues(t, 5, store.balance(t, marker), "the mutation was not undone")
			committed, commitErr := store.Commit()
			require.Same(t, status, commitErr, "the partially reverted store does not commit")
			require.Nil(t, committed)
			require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
			require.NoError(t, store.RollbackFailure())
			require.Zero(t, store.balance(t, marker))
			require.EqualValues(t, 10, store.balance(t, holder))
		})
	}
}
