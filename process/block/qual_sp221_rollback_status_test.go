package block_test

import (
	"bytes"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/endProcess"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/process"
	processBlock "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	"github.com/multiversx/mx-chain-go/vm"
)

// qualSP221BlockStore is the real account store. failNext makes the store's own
// RevertToSnapshot fail that many times (snapshot out of bounds); a negative
// value makes every revert fail, including the block-level restoration.
type qualSP221BlockStore struct {
	*state.AccountsDB
	failNext int
	root     []byte
}

var qualSP221BlockHolder, qualSP221BlockMarker = bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{3}, 32)

func qualSP221NewBlockStore(t *testing.T) *qualSP221BlockStore {
	t.Helper()
	s := &qualSP221BlockStore{AccountsDB: integrationtests.CreateInMemoryShardAccountsDB()}
	s.credit(t, qualSP221BlockHolder, 10)
	root, err := s.Commit()
	require.NoError(t, err)
	s.root = root
	return s
}

func (s *qualSP221BlockStore) RevertToSnapshot(snapshot int) error {
	if s.failNext != 0 {
		if s.failNext > 0 {
			s.failNext--
		}
		return s.AccountsDB.RevertToSnapshot(s.AccountsDB.JournalLen() + 1)
	}
	return s.AccountsDB.RevertToSnapshot(snapshot)
}

func (s *qualSP221BlockStore) credit(t *testing.T, address []byte, value int64) {
	t.Helper()
	account, err := s.AccountsDB.LoadAccount(address)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).AddToBalance(big.NewInt(value)))
	require.NoError(t, s.AccountsDB.SaveAccount(account))
}

func (s *qualSP221BlockStore) balance(t *testing.T, address []byte) int64 {
	t.Helper()
	account, err := s.AccountsDB.LoadAccount(address)
	require.NoError(t, err)
	return account.(state.UserAccountHandler).GetBalance().Int64()
}

// failTransactionRollback stands for one failed per-transaction rollback
// inside block execution: a mutation is applied and its revert fails.
func (s *qualSP221BlockStore) failTransactionRollback(t *testing.T) {
	t.Helper()
	s.credit(t, qualSP221BlockMarker, 5)
	previous := s.failNext
	s.failNext = 1
	require.Same(t, state.ErrSnapshotValueOutOfBounds, s.RevertToSnapshot(1))
	s.failNext = previous
	require.Error(t, s.RollbackFailure())
}

func (s *qualSP221BlockStore) requireCommittedState(t *testing.T) {
	t.Helper()
	require.NoError(t, s.RollbackFailure())
	require.Zero(t, s.balance(t, qualSP221BlockMarker), "the partial mutation is gone")
	require.EqualValues(t, 10, s.balance(t, qualSP221BlockHolder))
	root, err := s.RootHash()
	require.NoError(t, err)
	require.Equal(t, s.root, root)
}

type qualSP221Finisher interface {
	process.BlockProcessor
	QualSP221FinishBlockFailure(processingErr, original error) error
}

func qualSP221Processor(t *testing.T, chain string, user, peer *qualSP221BlockStore, coordinator process.TransactionCoordinator,
	stop chan endProcess.ArgEndProcess, reads *atomic.Int64) qualSP221Finisher {
	t.Helper()
	if chain == "meta" {
		args := createMockMetaArguments(createMockComponentHolders())
		args.AccountsDB[state.UserAccountsState], args.AccountsDB[state.PeerAccountsState] = user, peer
		if coordinator != nil {
			args.TxCoordinator = coordinator
		}
		qualDRWAObserveStop(&args.ArgBaseProcessor, stop, reads)
		processor, err := processBlock.NewMetaProcessor(args)
		require.NoError(t, err)
		return processor
	}
	args := CreateMockArgumentsMultiShard(createMockComponentHolders())
	args.AccountsDB[state.UserAccountsState], args.AccountsDB[state.PeerAccountsState] = user, peer
	if coordinator != nil {
		args.TxCoordinator = coordinator
	}
	qualDRWAObserveStop(&args.ArgBaseProcessor, stop, reads)
	processor, err := processBlock.NewShardProcessor(args)
	require.NoError(t, err)
	return processor
}

var qualSP221Entries = []struct {
	name string
	call func(process.BlockProcessor) error
}{
	{"process", func(p process.BlockProcessor) error {
		return p.ProcessBlock(nil, nil, func() time.Duration { return time.Second })
	}},
	{"create", func(p process.BlockProcessor) error {
		_, _, err := p.CreateBlock(nil, func() bool { return true })
		return err
	}},
	{"commit", func(p process.BlockProcessor) error { return p.CommitBlock(nil, nil) }},
	{"process_proposal", func(p process.BlockProcessor) error { _, err := p.ProcessBlockProposal(nil, nil, nil); return err }},
	{"create_proposal", func(p process.BlockProcessor) error {
		_, _, err := p.CreateBlockProposal(nil, func() bool { return true })
		return err
	}},
	{"commit_proposal", func(p process.BlockProcessor) error { return p.CommitBlockProposalState(nil, nil) }},
	{"scheduled", func(p process.BlockProcessor) error {
		return p.ProcessScheduledBlock(nil, nil, func() time.Duration { return time.Second })
	}},
}

// SP2-21, Part A P-05: the block owner reads the stores' rollback status at
// every entry. A store with a failed revert is not processed further or
// committed; it is restored to the committed root and the entry is refused.
func TestQualSP221BlockEntriesContainRollbackFailure(t *testing.T) {
	for _, chain := range []string{"shard", "meta"} {
		for _, dirty := range []string{"user", "peer"} {
			for _, entry := range qualSP221Entries {
				t.Run(chain+"/"+dirty+"/"+entry.name, func(t *testing.T) {
					user, peer := qualSP221NewBlockStore(t), qualSP221NewBlockStore(t)
					stop := make(chan endProcess.ArgEndProcess, 1)
					var reads atomic.Int64
					processor := qualSP221Processor(t, chain, user, peer, nil, stop, &reads)

					// No failed revert: the native entry result.
					require.ErrorIs(t, entry.call(processor), process.ErrNilBlockHeader)

					if dirty == "user" {
						user.failTransactionRollback(t)
					} else {
						peer.failTransactionRollback(t)
					}
					err := entry.call(processor)
					require.ErrorIs(t, err, vm.ErrDRWAExecution)
					require.ErrorIs(t, err, state.ErrRollbackFailed)
					require.ErrorIs(t, err, state.ErrSnapshotValueOutOfBounds, "the rollback error stays available")
					require.NotErrorIs(t, err, process.ErrNilBlockHeader, "the entry did not run")
					user.requireCommittedState(t)
					peer.requireCommittedState(t)
					qualDRWAAssertStop(t, stop, false)

					// Restored to committed state: the next entry runs natively.
					require.ErrorIs(t, entry.call(processor), process.ErrNilBlockHeader)
				})
			}
		}
	}
}

// When the restoration to the committed root fails too, the owner keeps
// refusing every entry and requests node stop.
func TestQualSP221BlockEntriesStopWhenRestorationFails(t *testing.T) {
	for _, chain := range []string{"shard", "meta"} {
		for _, entry := range qualSP221Entries {
			t.Run(chain+"/"+entry.name, func(t *testing.T) {
				user, peer := qualSP221NewBlockStore(t), qualSP221NewBlockStore(t)
				stop := make(chan endProcess.ArgEndProcess, 1)
				var reads atomic.Int64
				processor := qualSP221Processor(t, chain, user, peer, nil, stop, &reads)
				user.failTransactionRollback(t)
				user.failNext = -1

				err := entry.call(processor)
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.ErrorIs(t, err, state.ErrRollbackFailed)
				qualDRWAAssertStop(t, stop, true)
				require.Error(t, user.RollbackFailure())
				_, commitErr := user.Commit()
				require.ErrorIs(t, commitErr, state.ErrRollbackFailed, "nothing is committed")

				user.failNext = 0
				require.ErrorIs(t, entry.call(processor), vm.ErrDRWAExecution, "the failed restoration is retained")
			})
		}
	}
}

// The end of block execution: a block during which a rollback failed does not
// succeed, whatever the native result was, and its state is discarded.
func TestQualSP221FinishBlockFailureContainsRollbackFailure(t *testing.T) {
	native := errors.New("inert native block failure")
	for _, chain := range []string{"shard", "meta"} {
		for _, tc := range []struct {
			name                    string
			processingErr, original error
			dirty                   bool
		}{
			{"clean_success", nil, nil, false},
			{"clean_native_failure", native, native, false},
			{"dirty_native_success", nil, nil, true},
			{"dirty_native_failure", native, native, true},
		} {
			t.Run(chain+"/"+tc.name, func(t *testing.T) {
				user, peer := qualSP221NewBlockStore(t), qualSP221NewBlockStore(t)
				stop := make(chan endProcess.ArgEndProcess, 1)
				var reads atomic.Int64
				processor := qualSP221Processor(t, chain, user, peer, nil, stop, &reads)
				if tc.dirty {
					user.failTransactionRollback(t)
				}
				err := processor.QualSP221FinishBlockFailure(tc.processingErr, tc.original)
				if !tc.dirty {
					if tc.original == nil {
						require.NoError(t, err)
					} else {
						require.Same(t, tc.original, err, "the native block error is returned unchanged")
					}
					qualDRWAAssertStop(t, stop, false)
					return
				}
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.ErrorIs(t, err, state.ErrRollbackFailed)
				require.ErrorIs(t, err, state.ErrSnapshotValueOutOfBounds)
				if tc.original != nil {
					require.ErrorIs(t, err, tc.original, "the original error stays available")
				}
				user.requireCommittedState(t)
				peer.requireCommittedState(t)
				qualDRWAAssertStop(t, stop, false)
			})
		}
	}
}

// Block creation and scheduled execution: a rollback that fails while the
// coordinator executes transactions fails the operation.
func TestQualSP221CreateBlockContainsRollbackFailure(t *testing.T) {
	for _, chain := range []string{"shard", "meta"} {
		for _, dirty := range []bool{false, true} {
			if chain == "meta" && !dirty {
				// The inherited meta mock arguments cannot apply a body to a header;
				// the meta entries without a failed revert are covered above.
				continue
			}
			t.Run(chain+"/dirty_"+map[bool]string{false: "false", true: "true"}[dirty], func(t *testing.T) {
				user, peer := qualSP221NewBlockStore(t), qualSP221NewBlockStore(t)
				executed := 0
				coordinator := &testscommon.TransactionCoordinatorMock{
					CreateMbsAndProcessTransactionsFromMeCalled: func(func() bool) block.MiniBlockSlice {
						executed++
						if dirty {
							user.failTransactionRollback(t)
						}
						return nil
					},
				}
				stop := make(chan endProcess.ArgEndProcess, 1)
				var reads atomic.Int64
				processor := qualSP221Processor(t, chain, user, peer, coordinator, stop, &reads)
				var header data.HeaderHandler = &block.Header{Nonce: 37, Round: 38, Epoch: 1}
				if chain == "meta" {
					header = &block.MetaBlock{Nonce: 37, Round: 38, Epoch: 1, AccumulatedFeesInEpoch: big.NewInt(0), DevFeesInEpoch: big.NewInt(0)}
				}
				created, body, err := processor.CreateBlock(header, func() bool { return true })
				require.Equal(t, 1, executed)
				if !dirty {
					require.NoError(t, err)
					require.NotNil(t, created)
					require.NotNil(t, body)
					return
				}
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.ErrorIs(t, err, state.ErrRollbackFailed)
				require.Nil(t, created)
				require.Nil(t, body)
				user.requireCommittedState(t)
				peer.requireCommittedState(t)
				qualDRWAAssertStop(t, stop, false)
			})
		}
	}
}

// Scheduled execution: a rollback that fails while scheduled transactions run
// fails the scheduled block, and the native cleanup restores committed state.
func TestQualSP221ScheduledBlockContainsRollbackFailure(t *testing.T) {
	for _, dirty := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "dirty"}[dirty], func(t *testing.T) {
			user, peer := qualSP221NewBlockStore(t), qualSP221NewBlockStore(t)
			executed, rootSet := 0, 0
			args := CreateMockArgumentsMultiShard(createMockComponentHolders())
			args.AccountsDB[state.UserAccountsState], args.AccountsDB[state.PeerAccountsState] = user, peer
			args.ScheduledTxsExecutionHandler = &testscommon.ScheduledTxsExecutionStub{
				ExecuteAllCalled: func(func() time.Duration) error {
					executed++
					if dirty {
						user.failTransactionRollback(t)
					}
					return nil
				},
				SetScheduledRootHashCalled: func([]byte) { rootSet++ },
			}
			processor, err := processBlock.NewShardProcessor(args)
			require.NoError(t, err)

			err = processor.ProcessScheduledBlock(&block.HeaderV2{}, &block.Body{}, func() time.Duration { return time.Second })
			require.Equal(t, 1, executed)
			if !dirty {
				require.NoError(t, err)
				require.Equal(t, 1, rootSet)
				return
			}
			require.ErrorIs(t, err, vm.ErrDRWAExecution)
			require.ErrorIs(t, err, state.ErrRollbackFailed)
			require.Zero(t, rootSet, "no scheduled root is recorded from a partially reverted store")
			user.requireCommittedState(t)
			peer.requireCommittedState(t)
		})
	}
}
