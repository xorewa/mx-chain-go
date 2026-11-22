package asyncExecution

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/process/asyncExecution/cache"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/processMocks"
)

// Exercises the real executor's ordered calls with native stubs. It does not
// execute a block processor, prove trie restoration on retry or establish finality.
func TestQualDRWAAsyncCommitTrackingBoundary(t *testing.T) {
	for _, kind := range []string{"commit_error", "tracker_error", "tracker_rejection", "success"} {
		t.Run(kind, func(t *testing.T) {
			nativeErr := errors.New("injected execution boundary error")
			hash, previous, root := []byte("proposal"), []byte("previous"), []byte("result root")
			header := &block.Header{Nonce: 1, PrevHash: previous}
			result := &block.BaseExecutionResult{HeaderNonce: 1, HeaderHash: hash, RootHash: root}
			var order []string
			signal := make(chan uint64, 1)
			args := createMockArgs()
			args.SignalProcessCompletionChan = signal
			args.BlockProcessor = &processMocks.BlockProcessorStub{
				ProcessBlockProposalCalled: func(h data.HeaderHandler, hh []byte, body data.BodyHandler) (data.BaseExecutionResultHandler, error) {
					require.Same(t, header, h)
					require.Equal(t, hash, hh)
					require.IsType(t, &block.Body{}, body)
					order = append(order, "process")
					return result, nil
				},
				CommitBlockProposalStateCalled: func(h data.HeaderHandler, hh []byte) error {
					require.Same(t, header, h)
					require.Equal(t, hash, hh)
					order = append(order, "commit")
					if kind == "commit_error" {
						return nativeErr
					}
					return nil
				},
				RevertBlockProposalStateCalled: func() { order = append(order, "revert") },
				DiscardStateAccessesCalled:     func(hh []byte) { require.Equal(t, hash, hh); order = append(order, "discard") },
				PruneTrieAsyncHeaderCalled:     func() { order = append(order, "prune") },
			}
			args.ExecutionTracker = &processMocks.ExecutionTrackerStub{AddExecutionResultCalled: func(r data.BaseExecutionResultHandler) (bool, error) {
				require.Same(t, result, r)
				order = append(order, "track")
				if kind == "tracker_error" {
					return false, nativeErr
				}
				return kind != "tracker_rejection", nil
			}}
			args.BlockChain = &testscommon.ChainHandlerStub{
				GetLastExecutionResultCalled: func() data.BaseExecutionResultHandler { return &block.BaseExecutionResult{HeaderHash: previous} },
				SetLastExecutionInfoCalled: func(h data.HeaderHandler, r data.BaseExecutionResultHandler) {
					require.Zero(t, len(signal), "completion must not precede publication")
					require.Same(t, header, h)
					require.Same(t, result, r)
					order = append(order, "publish")
				},
			}
			executor, err := NewHeadersExecutor(args)
			require.NoError(t, err)
			err = executor.Process(cache.HeaderBodyPair{Header: header, HeaderHash: hash, Body: &block.Body{}})
			if kind == "commit_error" || kind == "tracker_error" {
				require.ErrorIs(t, err, nativeErr)
			} else {
				require.NoError(t, err)
			}
			switch kind {
			case "commit_error":
				require.Equal(t, []string{"process", "commit", "revert"}, order)
			case "tracker_error", "tracker_rejection":
				require.Equal(t, []string{"process", "commit", "track", "discard"}, order)
			case "success":
				require.Equal(t, []string{"process", "commit", "track", "prune", "publish"}, order)
			}
			if kind == "success" {
				select {
				case nonce := <-signal:
					require.Equal(t, uint64(1), nonce)
				default:
					t.Fatal("successful processing must signal completion")
				}
			}
			select {
			case <-signal:
				t.Fatal("unexpected or duplicate completion signal")
			default:
			}
		})
	}
}

func TestQualDRWAAsyncPreCommitExitBoundaries(t *testing.T) {
	for _, kind := range []string{"initial_context", "process_error", "nil_result", "changed_context", "committed_hash_conflict", "last_result_changed"} {
		t.Run(kind, func(t *testing.T) {
			nativeErr := errors.New("injected process error")
			hash, previous := []byte("proposal"), []byte("previous")
			header := &block.Header{Nonce: 1, PrevHash: previous}
			result := &block.BaseExecutionResult{HeaderNonce: 1, HeaderHash: hash}
			var order []string
			reads := 0
			signal := make(chan uint64, 1)
			args := createMockArgs()
			args.SignalProcessCompletionChan = signal
			args.BlockProcessor = &processMocks.BlockProcessorStub{
				ProcessBlockProposalCalled: func(h data.HeaderHandler, hh []byte, body data.BodyHandler) (data.BaseExecutionResultHandler, error) {
					require.Same(t, header, h)
					require.Equal(t, hash, hh)
					require.IsType(t, &block.Body{}, body)
					order = append(order, "process")
					if kind == "process_error" {
						return nil, nativeErr
					}
					if kind == "nil_result" {
						return nil, nil
					}
					return result, nil
				},
				CommitBlockProposalStateCalled: func(data.HeaderHandler, []byte) error { t.Fatal("pre-commit exit must not commit"); return nil },
				RevertBlockProposalStateCalled: func() { order = append(order, "revert") },
				DiscardStateAccessesCalled:     func([]byte) { t.Fatal("no committed result to discard here") },
				PruneTrieAsyncHeaderCalled:     func() { t.Fatal("pre-commit exit must not prune") },
			}
			args.ExecutionTracker = &processMocks.ExecutionTrackerStub{AddExecutionResultCalled: func(data.BaseExecutionResultHandler) (bool, error) {
				t.Fatal("pre-commit exit must not track")
				return false, nil
			}}
			args.BlockChain = &testscommon.ChainHandlerStub{
				GetLastExecutionResultCalled: func() data.BaseExecutionResultHandler {
					reads++
					if kind == "initial_context" || (kind == "changed_context" && reads == 2) || (kind == "last_result_changed" && reads == 3) {
						return &block.BaseExecutionResult{HeaderNonce: 0, HeaderHash: []byte("different predecessor")}
					}
					return &block.BaseExecutionResult{HeaderNonce: 0, HeaderHash: previous}
				},
				GetCurrentBlockHeaderAndHashCalled: func() (data.HeaderHandler, []byte) {
					if kind == "committed_hash_conflict" {
						return &block.Header{Nonce: 1}, []byte("other committed hash")
					}
					return nil, nil
				},
				SetLastExecutionInfoCalled: func(data.HeaderHandler, data.BaseExecutionResultHandler) { t.Fatal("pre-commit exit must not publish") },
			}
			executor, err := NewHeadersExecutor(args)
			require.NoError(t, err)
			err = executor.Process(cache.HeaderBodyPair{Header: header, HeaderHash: hash, Body: &block.Body{}})
			switch kind {
			case "initial_context":
				require.ErrorIs(t, err, ErrContextMismatch)
				require.Empty(t, order)
			case "process_error":
				require.ErrorIs(t, err, nativeErr)
				require.Equal(t, []string{"process"}, order)
			case "nil_result":
				require.ErrorIs(t, err, ErrNilExecutionResult)
				require.Equal(t, []string{"process", "revert"}, order)
			default:
				require.NoError(t, err)
				require.Equal(t, []string{"process", "revert"}, order)
			}
			require.Equal(t, map[string]int{"initial_context": 1, "process_error": 1, "nil_result": 1, "changed_context": 2, "committed_hash_conflict": 2, "last_result_changed": 3}[kind], reads)
			require.Empty(t, signal)
		})
	}
}
