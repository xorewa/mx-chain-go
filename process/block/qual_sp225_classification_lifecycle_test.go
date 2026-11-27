package block_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/process"
	processBlock "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
)

// SP2-25, Part A 5.1 rule 5: the block processor calls the classifier owner
// before the first native effect of every execution entry, with a committed
// journal, and tells it about every successful native commit. Inert stubs.

type qualSP225Lifecycle struct {
	events   *[]string
	beginErr error
	commit   error
}

func (l *qualSP225Lifecycle) BeginExecution() error {
	*l.events = append(*l.events, "begin")
	return l.beginErr
}
func (l *qualSP225Lifecycle) Committed() error {
	*l.events = append(*l.events, "committed")
	return l.commit
}
func (l *qualSP225Lifecycle) IsInterfaceNil() bool { return l == nil }

type qualSP225Executor interface {
	process.BlockProcessor
	QualSP225CommitState(header data.HeaderHandler) error
}

func qualSP225Processor(t *testing.T, chain string, journal int, lifecycle *qualSP225Lifecycle, events *[]string, commitErr error) qualSP225Executor {
	t.Helper()
	store := func(name string) *stateMock.AccountsStub {
		return &stateMock.AccountsStub{
			JournalLenCalled:       func() int { return journal },
			RevertToSnapshotCalled: func(int) error { return nil },
			RootHashCalled:         func() ([]byte, error) { return []byte("root"), nil },
			CommitCalled: func() ([]byte, error) {
				*events = append(*events, "commit:"+name)
				return []byte("root"), commitErr
			},
			CommitInEpochCalled: func(uint32, uint32) ([]byte, error) {
				*events = append(*events, "commitInEpoch:"+name)
				return []byte("root"), commitErr
			},
		}
	}
	coordinator := &testscommon.TransactionCoordinatorMock{
		ProcessBlockTransactionCalled: func(data.HeaderHandler, *block.Body, func() time.Duration) error {
			*events = append(*events, "execute")
			return errors.New("inert stop after the first native effect")
		},
		CreateMbsAndProcessTransactionsFromMeCalled: func(func() bool) block.MiniBlockSlice {
			*events = append(*events, "execute")
			return nil
		},
	}
	var handler process.DRWAClassificationHandler
	if lifecycle != nil {
		lifecycle.events = events
		handler = lifecycle
	}
	if chain == "meta" {
		args := createMockMetaArguments(createMockComponentHolders())
		args.AccountsDB[state.UserAccountsState], args.AccountsDB[state.PeerAccountsState] = store("user"), store("peer")
		args.TxCoordinator, args.DRWAClassification = coordinator, handler
		processor, err := processBlock.NewMetaProcessor(args)
		require.NoError(t, err)
		return processor
	}
	args := CreateMockArgumentsMultiShard(createMockComponentHolders())
	args.AccountsDB[state.UserAccountsState], args.AccountsDB[state.PeerAccountsState] = store("user"), store("peer")
	args.TxCoordinator, args.DRWAClassification = coordinator, handler
	processor, err := processBlock.NewShardProcessor(args)
	require.NoError(t, err)
	return processor
}

func qualSP225Entries(chain string) map[string]func(process.BlockProcessor) error {
	var header, proposal data.HeaderHandler = &block.Header{Nonce: 1, PubKeysBitmap: []byte("0100101"), PrevHash: []byte(""), Signature: []byte("signature"), RootHash: []byte("roothash")}, &block.HeaderV3{}
	if chain == "meta" {
		header, proposal = &block.MetaBlock{Nonce: 1, PubKeysBitmap: []byte("0100101"), PrevHash: []byte(""), Signature: []byte("signature"), RootHash: []byte("roothash")}, &block.MetaBlockV3{}
	}
	entries := map[string]func(process.BlockProcessor) error{
		"process": func(p process.BlockProcessor) error {
			return p.ProcessBlock(header, &block.Body{}, func() time.Duration { return time.Second })
		},
		"process_proposal": func(p process.BlockProcessor) error {
			_, err := p.ProcessBlockProposal(proposal, []byte("hash"), &block.Body{})
			return err
		},
	}
	if chain == "meta" {
		entries["create"] = func(p process.BlockProcessor) error {
			_, _, err := p.CreateBlock(&block.MetaBlock{Nonce: 37, Round: 38, Epoch: 1}, func() bool { return true })
			return err
		}
	}
	return entries
}

func TestQualSP225ExecutionEntriesBeginClassificationFirst(t *testing.T) {
	refusal := fmt.Errorf("%w: inert unresolved projection", vm.ErrDRWAExecution)
	for _, chain := range []string{"meta", "shard"} {
		for name, call := range qualSP225Entries(chain) {
			t.Run(chain+"/"+name+"/refused", func(t *testing.T) {
				var events []string
				processor := qualSP225Processor(t, chain, 0, &qualSP225Lifecycle{beginErr: refusal}, &events, nil)
				err := call(processor)
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.Equal(t, []string{"begin"}, events, "no native effect follows a refused classification")
			})
			t.Run(chain+"/"+name+"/dirty_journal", func(t *testing.T) {
				var events []string
				processor := qualSP225Processor(t, chain, 3, &qualSP225Lifecycle{}, &events, nil)
				err := call(processor)
				require.ErrorIs(t, err, process.ErrAccountStateDirty)
				require.Empty(t, events, "the owner is called only with a committed journal")
			})
			if name == "create" {
				// The inherited meta mock arguments cannot apply a created body
				// to a header, so the admitted creation path is not run here.
				continue
			}
			t.Run(chain+"/"+name+"/admitted_precedes_execution", func(t *testing.T) {
				var events []string
				processor := qualSP225Processor(t, chain, 0, &qualSP225Lifecycle{}, &events, nil)
				_ = call(processor)
				require.NotEmpty(t, events)
				require.Equal(t, "begin", events[0])
				for _, event := range events[1:] {
					require.NotEqual(t, "begin", event, "one begin per execution")
				}
			})
			t.Run(chain+"/"+name+"/no_owner_is_native", func(t *testing.T) {
				var with, without []string
				errWith := call(qualSP225Processor(t, chain, 0, &qualSP225Lifecycle{}, &with, nil))
				errWithout := call(qualSP225Processor(t, chain, 0, nil, &without, nil))
				require.Equal(t, fmt.Sprint(errWithout), fmt.Sprint(errWith))
				require.Equal(t, append([]string{"begin"}, without...), with, "the owner adds nothing but its own call")
			})
		}
	}
}

func TestQualSP225NativeCommitNotifiesClassification(t *testing.T) {
	inert := errors.New("inert native commit failure")
	for _, chain := range []string{"meta", "shard"} {
		for _, tc := range []struct {
			name      string
			header    data.HeaderHandler
			commitErr error
			ownerErr  error
		}{
			{"commit", &block.Header{Nonce: 1}, nil, nil},
			{"commit_in_epoch", &block.MetaBlock{Nonce: 1, Epoch: 2, EpochStart: block.EpochStart{LastFinalizedHeaders: []block.EpochStartShardData{{}}}}, nil, nil},
			{"native_commit_fails", &block.Header{Nonce: 1}, inert, nil},
			{"owner_error_does_not_undo_the_commit", &block.Header{Nonce: 1}, nil, fmt.Errorf("%w: inert", vm.ErrDRWAExecution)},
		} {
			t.Run(chain+"/"+tc.name, func(t *testing.T) {
				var events []string
				processor := qualSP225Processor(t, chain, 0, &qualSP225Lifecycle{commit: tc.ownerErr}, &events, tc.commitErr)
				err := processor.QualSP225CommitState(tc.header)
				if tc.commitErr != nil {
					require.Same(t, tc.commitErr, err)
					require.NotContains(t, events, "committed", "a failed native commit is not reported as committed")
					return
				}
				require.NoError(t, err)
				require.Len(t, events, 3)
				require.Equal(t, "committed", events[2], "after every store")
				expected := "commit:"
				if tc.header.IsStartOfEpochBlock() {
					expected = "commitInEpoch:"
				}
				require.ElementsMatch(t, []string{expected + "user", expected + "peer"}, events[:2])

				var native []string
				require.NoError(t, qualSP225Processor(t, chain, 0, nil, &native, nil).QualSP225CommitState(tc.header))
				require.ElementsMatch(t, native, events[:2])
			})
		}
	}
}
