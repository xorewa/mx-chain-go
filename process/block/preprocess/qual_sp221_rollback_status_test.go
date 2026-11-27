package preprocess

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/rewardTx"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/cache"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	"github.com/multiversx/mx-chain-go/txcache"
)

// qualSP221Store is the real account store. With failRevert set, the store's
// own RevertToSnapshot fails (snapshot out of bounds). Inert local fixture.
type qualSP221Store struct {
	*state.AccountsDB
	failRevert bool
	reverts    int
	root       []byte
}

var qualSP221Holder, qualSP221Marker = bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{3}, 32)

func qualSP221NewStore(t *testing.T, failRevert bool) *qualSP221Store {
	t.Helper()
	s := &qualSP221Store{AccountsDB: integrationtests.CreateInMemoryShardAccountsDB(), failRevert: failRevert}
	s.credit(t, qualSP221Holder, 10)
	root, err := s.Commit()
	require.NoError(t, err)
	s.root = root
	return s
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

// requireOutcome checks the separate status after one site ran its rollback.
func (s *qualSP221Store) requireOutcome(t *testing.T) {
	t.Helper()
	require.Equal(t, 1, s.reverts)
	if !s.failRevert {
		require.NoError(t, s.RollbackFailure())
		require.Zero(t, s.balance(t, qualSP221Marker))
		committed, err := s.Commit()
		require.NoError(t, err)
		require.Equal(t, s.root, committed)
		return
	}
	status := s.RollbackFailure()
	require.ErrorIs(t, status, state.ErrRollbackFailed)
	require.ErrorIs(t, status, state.ErrSnapshotValueOutOfBounds)
	require.EqualValues(t, 5, s.balance(t, qualSP221Marker), "the mutation was not undone")
	committed, err := s.Commit()
	require.Same(t, status, err, "the partially reverted store does not commit")
	require.Nil(t, committed)
	require.NoError(t, s.RecreateTrie(holders.NewDefaultRootHashesHolder(s.root)))
	require.NoError(t, s.RollbackFailure())
	require.Zero(t, s.balance(t, qualSP221Marker))
	require.EqualValues(t, 10, s.balance(t, qualSP221Holder))
}

// SP2-21, Part A P-05, INV-0: incoming miniblock processing returns the native
// values when the per-transaction rollback fails; the failure is on the status.
func TestQualSP221IncomingRollbackStatus(t *testing.T) {
	for _, kind := range []string{"transaction", "SCR", "reward"} {
		for _, rollbackFails := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/rollback_fails_%t", kind, rollbackFails), func(t *testing.T) {
				failure := errors.New("inert processing failure")
				store := qualSP221NewStore(t, rollbackFails)
				calls := 0
				execute := func() (vmcommon.ReturnCode, error) {
					calls++
					store.credit(t, qualSP221Marker, 5)
					return vmcommon.UserError, failure
				}
				info := &testscommon.PreProcessorExecutionInfoHandlerMock{GetNumOfCrossInterMbsAndTxsCalled: getNumOfCrossInterMbsAndTxsZero}
				var receiver process.PreProcessor
				var mb *block.MiniBlock
				var err error
				switch kind {
				case "SCR":
					var args SmartContractResultsArgs
					args, mb, _ = qualDRWASCRReceiverArgs(t)
					args.Accounts = store
					args.ScrProcessor = &testscommon.TxProcessorMock{ProcessSmartContractResultCalled: func(*smartContractResult.SmartContractResult) (vmcommon.ReturnCode, error) { return execute() }}
					receiver, err = NewSmartContractResultPreprocessor(args)
				case "transaction":
					var entries map[string]interface{}
					_, mb, entries = qualDRWASCRReceiverArgs(t)
					mb.Type = block.TxBlock
					mb.SenderShardID = 0
					for _, hash := range mb.TxHashes {
						entries[string(hash)] = &transaction.Transaction{Value: big.NewInt(0)}
					}
					ta := createDefaultTransactionsProcessorArgs()
					ta.Accounts = store
					ta.DataPool = &testscommon.ShardedDataStub{ShardDataStoreCalled: func(string) storage.Cacher {
						return &cache.CacherStub{PeekCalled: func(hash []byte) (interface{}, bool) { v, ok := entries[string(hash)]; return v, ok }}
					}}
					ta.TxProcessor = &testscommon.TxProcessorMock{ProcessTransactionCalled: func(*transaction.Transaction) (vmcommon.ReturnCode, error) { return execute() }}
					receiver, err = NewTransactionPreprocessor(ta)
				case "reward":
					args := createDefaultRewardsProcessorArgs(initDataPool())
					args.Accounts = store
					args.DataPool = &testscommon.ShardedDataStub{ShardDataStoreCalled: func(string) storage.Cacher {
						return &cache.CacherStub{PeekCalled: func([]byte) (interface{}, bool) { return &rewardTx.RewardTx{Value: big.NewInt(0)}, true }}
					}}
					args.RewardProcessor = &testscommon.RewardTxProcessorMock{ProcessRewardTransactionCalled: func(*rewardTx.RewardTx) error { _, e := execute(); return e }}
					var rtp *rewardTxPreprocessor
					rtp, err = NewRewardTxPreprocessor(args)
					require.NoError(t, err)
					mb = &block.MiniBlock{TxHashes: [][]byte{[]byte("reward")}, ReceiverShardID: 1, SenderShardID: core.MetachainShardId, Type: block.RewardsBlock}
					receiver = rtp
				}
				require.NoError(t, err)

				_, last, revert, err := receiver.ProcessMiniBlock(mb, haveTimeTrue, haveAdditionalTimeFalse, false, false, -1, info, process.GasProcessingPolicy{})
				require.Same(t, failure, err, "the native error value is returned unchanged")
				require.Equal(t, 1, calls)
				require.Equal(t, -1, last)
				require.True(t, revert)
				store.requireOutcome(t)
			})
		}
	}
}

// The two outgoing sites: the miniblock builder's bad-transaction cleanup and
// the V2 per-transaction cleanup.
func TestQualSP221OutgoingRollbackStatus(t *testing.T) {
	for _, route := range []string{"builderV1", "transactionV2"} {
		for _, rollbackFails := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/rollback_fails_%t", route, rollbackFails), func(t *testing.T) {
				failure := errors.New("inert processing failure")
				store := qualSP221NewStore(t, rollbackFails)
				p := createTransactionPreprocessor()
				p.balanceComputation = &testscommon.BalanceComputationStub{}
				p.accounts = store
				p.txProcessor = &testscommon.TxProcessorMock{ProcessTransactionCalled: func(*transaction.Transaction) (vmcommon.ReturnCode, error) {
					store.credit(t, qualSP221Marker, 5)
					return vmcommon.UserError, failure
				}}
				p.txTypeHandler = &testscommon.TxTypeHandlerMock{ComputeTransactionTypeCalled: func(data.TransactionHandler) (process.TransactionType, process.TransactionType, bool) {
					return process.MoveBalance, process.MoveBalance, false
				}}
				wrapped := &txcache.WrappedTransaction{Tx: &transaction.Transaction{SndAddr: []byte("inert sender"), Value: big.NewInt(0)}, TxHash: []byte("inert hash")}
				tx := wrapped.Tx.(*transaction.Transaction)
				var err error
				if route == "builderV1" {
					mb := &miniBlocksBuilder{accounts: p.accounts, gasTracker: p.gasTracker, gasConsumedInReceiverShard: make(map[uint32]uint64), blockSizeComputation: p.blockSizeComputation, enableEpochsHandler: p.enableEpochsHandler, enableRoundsHandler: p.enableRoundsHandler}
					err = p.processMiniBlockBuilderTx(mb, wrapped, tx)
					require.EqualValues(t, 1, mb.stats.numTxsBad)
				} else {
					var added bool
					info := p.initCreateAndProcessMiniBlocks()
					added, err = p.processTransaction(tx, wrapped.TxHash, 0, 0, info)
					require.False(t, added)
					require.EqualValues(t, 1, info.processingInfo.numBadTxs)
				}
				require.Same(t, failure, err, "the native error value is returned unchanged")
				store.requireOutcome(t)
			})
		}
	}
}
