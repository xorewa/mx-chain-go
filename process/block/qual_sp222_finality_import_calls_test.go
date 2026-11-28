package block_test

import (
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	processBlock "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
)

// SP2-22, Part A 6.1: the finalized-result import runs at the deterministic
// start of a V3 block execution, after the stores are positioned at the
// parent's executed root and before the first transaction, and its execution
// is closed by the native commit or by the native revert. Inert stubs.

type qualSP222Import struct {
	events   *[]string
	beginErr error
}

func (i *qualSP222Import) BeginBlock(header data.HeaderHandler, headerHash []byte) error {
	*i.events = append(*i.events, fmt.Sprintf("begin:%d:%s", header.GetNonce(), headerHash))
	return i.beginErr
}
func (i *qualSP222Import) EndBlock(committed bool) {
	*i.events = append(*i.events, fmt.Sprintf("end:%t", committed))
}
func (i *qualSP222Import) IsInterfaceNil() bool { return i == nil }

func qualSP222Processor(t *testing.T, chain string, owner *qualSP222Import, events *[]string, commitErr error) process.BlockProcessor {
	t.Helper()
	store := func(name string) *stateMock.AccountsStub {
		// The store starts away from the parent's executed root (nil in these
		// mocks), so the native positioning is visible as an event.
		positioned := false
		return &stateMock.AccountsStub{
			RecreateTrieCalled: func(common.RootHashHolder) error {
				*events = append(*events, "position:"+name)
				positioned = true
				return nil
			},
			RevertToSnapshotCalled: func(int) error {
				*events = append(*events, "revert:"+name)
				return nil
			},
			RootHashCalled: func() ([]byte, error) {
				if positioned {
					return nil, nil
				}
				return []byte("another root"), nil
			},
			CommitCalled: func() ([]byte, error) {
				*events = append(*events, "commit:"+name)
				return []byte("root"), commitErr
			},
		}
	}
	coordinator := &testscommon.TransactionCoordinatorMock{
		ProcessBlockTransactionCalled: func(data.HeaderHandler, *block.Body, func() time.Duration) error {
			*events = append(*events, "execute")
			return nil
		},
		CreateReceiptsHashCalled: func() ([]byte, error) { return []byte("receipts"), nil },
	}
	var handler process.DRWAFinalityImportHandler
	if owner != nil {
		owner.events = events
		handler = owner
	}
	if chain == "meta" {
		coreComponents, dataComponents, bootstrapComponents, statusComponents := createMockComponentHolders()
		dataComponents.BlockChain = &testscommon.ChainHandlerStub{
			GetLastExecutionResultCalled: func() data.BaseExecutionResultHandler {
				return &block.MetaExecutionResult{ExecutionResult: &block.BaseMetaExecutionResult{
					AccumulatedFeesInEpoch: big.NewInt(10), DevFeesInEpoch: big.NewInt(10)}}
			},
			GetLastExecutedBlockHeaderCalled: func() data.HeaderHandler { return &block.MetaBlockV3{} },
		}
		args := createMockMetaArguments(coreComponents, dataComponents, bootstrapComponents, statusComponents)
		args.AccountsDB[state.UserAccountsState], args.AccountsDB[state.PeerAccountsState] = store("user"), store("peer")
		args.TxCoordinator, args.DRWAFinalityImport = coordinator, handler
		processor, err := processBlock.NewMetaProcessor(args)
		require.NoError(t, err)
		return processor
	}
	args := CreateMockArguments(createComponentHolderMocks())
	args.AccountsDB[state.UserAccountsState] = store("user")
	args.TxCoordinator, args.DRWAFinalityImport = coordinator, handler
	processor, err := processBlock.NewShardProcessor(args)
	require.NoError(t, err)
	return processor
}

func qualSP222Proposal(chain string) data.HeaderHandler {
	if chain == "meta" {
		return &block.MetaBlockV3{Nonce: 1}
	}
	return &block.HeaderV3{Nonce: 1}
}

func qualSP222Index(events []string, prefix string) int {
	for i, event := range events {
		if len(event) >= len(prefix) && event[:len(prefix)] == prefix {
			return i
		}
	}
	return -1
}

func TestQualSP222ImportPhasePrecedesTheFirstTransaction(t *testing.T) {
	for _, chain := range []string{"shard", "meta"} {
		t.Run(chain+"/order", func(t *testing.T) {
			var events []string
			processor := qualSP222Processor(t, chain, &qualSP222Import{}, &events, nil)
			_, err := processor.ProcessBlockProposal(qualSP222Proposal(chain), []byte("hash-of-B"), &block.Body{})
			begin, execute := qualSP222Index(events, "begin:1:hash-of-B"), qualSP222Index(events, "execute")
			require.NotEqual(t, -1, begin, "events %v, err %v", events, err)
			require.NotEqual(t, -1, execute, "events %v, err %v", events, err)
			require.Less(t, begin, execute)
			require.Less(t, qualSP222Index(events, "position:user"), begin, "the stores are positioned first")
			count := 0
			for _, event := range events {
				if len(event) > 5 && event[:6] == "begin:" {
					count++
				}
			}
			require.Equal(t, 1, count, "one import phase per execution")
		})
		t.Run(chain+"/refused import refuses the block and reverts", func(t *testing.T) {
			var events []string
			refusal := errors.New("inert: evidence not held")
			processor := qualSP222Processor(t, chain, &qualSP222Import{beginErr: refusal}, &events, nil)
			result, err := processor.ProcessBlockProposal(qualSP222Proposal(chain), []byte("hash-of-B"), &block.Body{})
			require.ErrorIs(t, err, refusal)
			require.Nil(t, result)
			require.Equal(t, -1, qualSP222Index(events, "execute"), "no transaction follows a refused import")
			revert, end := qualSP222Index(events, "revert:user"), qualSP222Index(events, "end:false")
			require.NotEqual(t, -1, revert)
			require.NotEqual(t, -1, end)
		})
		t.Run(chain+"/without an owner the processor is native", func(t *testing.T) {
			var with, without []string
			resultWith, errWith := qualSP222Processor(t, chain, &qualSP222Import{}, &with, nil).
				ProcessBlockProposal(qualSP222Proposal(chain), []byte("hash-of-B"), &block.Body{})
			resultWithout, errWithout := qualSP222Processor(t, chain, nil, &without, nil).
				ProcessBlockProposal(qualSP222Proposal(chain), []byte("hash-of-B"), &block.Body{})
			require.Equal(t, fmt.Sprint(errWithout), fmt.Sprint(errWith))
			require.Equal(t, resultWithout, resultWith)
			var native []string
			for _, event := range with {
				if qualSP222Index([]string{event}, "begin:") == -1 && qualSP222Index([]string{event}, "end:") == -1 {
					native = append(native, event)
				}
			}
			require.Equal(t, without, native, "the owner adds nothing but its own calls")
		})
		t.Run(chain+"/commit and revert close the execution", func(t *testing.T) {
			var events []string
			processor := qualSP222Processor(t, chain, &qualSP222Import{}, &events, nil)
			require.NoError(t, processor.CommitBlockProposalState(qualSP222Proposal(chain), []byte("hash-of-B")))
			commit, end := qualSP222Index(events, "commit:user"), qualSP222Index(events, "end:true")
			require.NotEqual(t, -1, commit)
			require.Less(t, commit, end, "closed as committed only after the native commit")

			events = nil
			failure := errors.New("inert native commit failure")
			processor = qualSP222Processor(t, chain, &qualSP222Import{}, &events, failure)
			require.ErrorIs(t, processor.CommitBlockProposalState(qualSP222Proposal(chain), []byte("hash-of-B")), failure)
			require.Equal(t, -1, qualSP222Index(events, "end:true"), "a failed commit is not reported as committed")

			events = nil
			processor = qualSP222Processor(t, chain, &qualSP222Import{}, &events, nil)
			processor.RevertCurrentBlock()
			require.Equal(t, 0, qualSP222Index(events, "end:false"), "closed before the stores are reverted")
		})
	}
}
