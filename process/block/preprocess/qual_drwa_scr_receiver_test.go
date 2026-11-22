package preprocess

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/cache"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// W04 / Part A 5.1: native receiver ordering is a prerequisite observation,
// not a DRWA transport, authenticated registry anchor or persistent rollback proof.
// The real preprocessor runs with upstream dependency stubs. No native VM,
// block consensus or durable account database runs in these tests.
func qualDRWASCRReceiverArgs(t *testing.T) (SmartContractResultsArgs, *block.MiniBlock, map[string]interface{}) {
	t.Helper()
	mb := &block.MiniBlock{Type: block.SmartContractResultBlock, SenderShardID: core.MetachainShardId, ReceiverShardID: 0,
		TxHashes: [][]byte{[]byte("z-first"), []byte("a-second"), []byte("m-third")}}
	entries := make(map[string]interface{})
	for i, hash := range mb.TxHashes {
		entries[string(hash)] = &smartContractResult.SmartContractResult{Nonce: uint64(i), Value: big.NewInt(0), RcvAddr: []byte("receiver"), Data: hash}
	}
	args := createDefaultSmartContractProcessorArgs(initDataPool())
	args.DataPool = &testscommon.ShardedDataStub{ShardDataStoreCalled: func(id string) storage.Cacher {
		require.Equal(t, process.ShardCacherIdentifier(mb.SenderShardID, mb.ReceiverShardID), id)
		return &cache.CacherStub{PeekCalled: func(key []byte) (interface{}, bool) { v, ok := entries[string(key)]; return v, ok }}
	}}
	return args, mb, entries
}

func TestQualDRWASCRReceiverErrorBoundary(t *testing.T) {
	for _, partial := range []bool{false, true} {
		for _, tc := range []struct {
			name   string
			code   vmcommon.ReturnCode
			failAt int
		}{
			{"ok", vmcommon.Ok, -1}, {"user_error_is_processed", vmcommon.UserError, -1},
			{"go_error_first", vmcommon.UserError, 0}, {"go_error_second", vmcommon.UserError, 1},
		} {
			t.Run(fmt.Sprintf("partial_%t/%s", partial, tc.name), func(t *testing.T) {
				args, mb, _ := qualDRWASCRReceiverArgs(t)
				calls, gas, reverted := [][]byte{}, [][]byte{}, [][]byte{}
				failure := errors.New("receiver prerequisite unavailable")
				args.ScrProcessor = &testscommon.TxProcessorMock{ProcessSmartContractResultCalled: func(result *smartContractResult.SmartContractResult) (vmcommon.ReturnCode, error) {
					calls = append(calls, result.Data)
					if int(result.Nonce) == tc.failAt {
						return tc.code, failure
					}
					return tc.code, nil
				}}
				snapshots := 0
				args.Accounts = &stateMock.AccountsStub{JournalLenCalled: func() int { return 7 }, RevertToSnapshotCalled: func(index int) error {
					require.Equal(t, 7, index)
					snapshots++
					return nil
				}}
				args.GasHandler = &testscommon.GasHandlerStub{SetGasProvidedCalled: func(_ uint64, hash []byte) { gas = append(gas, hash) }}
				info := &testscommon.PreProcessorExecutionInfoHandlerMock{RevertProcessedTxsResultsCalled: func(hashes [][]byte, key []byte) {
					require.Equal(t, [][]byte{key}, hashes)
					reverted = append(reverted, key)
				}}
				receiver, err := NewSmartContractResultPreprocessor(args)
				require.NoError(t, err)
				toRevert, last, shouldRevert, err := receiver.ProcessMiniBlock(mb, haveTimeTrue, haveAdditionalTimeFalse, false, partial, -1, info, process.GasProcessingPolicy{})
				if tc.failAt < 0 {
					require.NoError(t, err)
					require.Equal(t, mb.TxHashes, calls, "miniblock hash order is preserved, regardless of return code")
					require.Equal(t, mb.TxHashes, gas)
					require.Equal(t, 2, last)
					require.False(t, shouldRevert)
					require.Nil(t, toRevert)
					require.Empty(t, reverted)
					require.Zero(t, snapshots)
				} else {
					require.Same(t, failure, err)
					require.Equal(t, mb.TxHashes[:tc.failAt+1], calls, "no execution after a Go error")
					require.Equal(t, mb.TxHashes[:tc.failAt], gas, "failed SCR is not accounted as processed")
					require.Equal(t, tc.failAt-1, last)
					require.Equal(t, !partial, shouldRevert)
					require.Equal(t, [][]byte{mb.TxHashes[tc.failAt]}, reverted)
					require.Equal(t, 1, snapshots)
					if partial {
						require.Nil(t, toRevert)
					} else {
						require.Equal(t, mb.TxHashes[:tc.failAt], toRevert, "caller must undo processed prefix in full mode")
					}
				}
				// Cached availability is not execution success: partial mode caches even
				// the failed/unattempted suffix. Progress is reported separately by last.
				if tc.failAt >= 0 && !partial {
					require.Empty(t, receiver.GetAllCurrentUsedTxs())
				} else {
					require.Len(t, receiver.GetAllCurrentUsedTxs(), 3)
				}
			})
		}
	}
}

func TestQualDRWASCRReceiverResumeAndPoolBoundary(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		last                     int
		missing, wrong, fallback bool
		expected                 error
	}{
		{name: "resume", last: 0},
		{name: "missing_suffix_before_execution", last: -1, missing: true, expected: process.ErrNilSmartContractResult},
		{name: "wrong_type_before_execution", last: -1, wrong: true, expected: process.ErrWrongTypeAssertion},
		{name: "resume_still_requires_prefix_data", last: 0, missing: true, expected: process.ErrNilSmartContractResult},
		{name: "fallback_pool_lookup", last: -1, missing: true, fallback: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, mb, entries := qualDRWASCRReceiverArgs(t)
			target := mb.TxHashes[2]
			if tc.last == 0 {
				target = mb.TxHashes[0]
			}
			saved := entries[string(target)]
			if tc.missing {
				delete(entries, string(target))
			}
			if tc.wrong {
				entries[string(target)] = "not an SCR"
			}
			lookups := 0
			args.DataPool.(*testscommon.ShardedDataStub).SearchFirstDataCalled = func(hash []byte) (interface{}, bool) {
				require.Equal(t, target, hash)
				lookups++
				if tc.fallback {
					return saved, true
				}
				return nil, false
			}
			calls := [][]byte{}
			args.ScrProcessor = &testscommon.TxProcessorMock{ProcessSmartContractResultCalled: func(result *smartContractResult.SmartContractResult) (vmcommon.ReturnCode, error) {
				calls = append(calls, result.Data)
				return vmcommon.Ok, nil
			}}
			receiver, err := NewSmartContractResultPreprocessor(args)
			require.NoError(t, err)
			undo, last, revert, err := receiver.ProcessMiniBlock(mb, haveTimeTrue, haveAdditionalTimeFalse, false, true, tc.last, &testscommon.PreProcessorExecutionInfoHandlerMock{}, process.GasProcessingPolicy{})
			require.False(t, revert)
			require.Nil(t, undo)
			if tc.expected != nil {
				require.ErrorIs(t, err, tc.expected)
				require.Equal(t, tc.last, last)
				require.Empty(t, calls)
				require.Empty(t, receiver.GetAllCurrentUsedTxs())
			} else {
				require.NoError(t, err)
				require.Equal(t, 2, last)
				require.Equal(t, mb.TxHashes[tc.last+1:], calls, "caller-supplied progress skips a prefix; it is not authenticated here")
			}
			if tc.missing {
				require.Equal(t, 1, lookups)
			} else {
				require.Zero(t, lookups)
			}
		})
	}
}

func TestQualDRWASCRBlockReceiverErrorBoundary(t *testing.T) {
	for _, async := range []bool{false, true} {
		for _, tc := range []struct {
			name   string
			code   vmcommon.ReturnCode
			failAt int
		}{
			{"ok", vmcommon.Ok, -1}, {"user_error_is_processed", vmcommon.UserError, -1},
			{"go_error_first", vmcommon.UserError, 0}, {"go_error_second", vmcommon.UserError, 1},
		} {
			t.Run(fmt.Sprintf("async_%t/%s", async, tc.name), func(t *testing.T) {
				args, mb, entries := qualDRWASCRReceiverArgs(t)
				if async {
					args.EnableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.SupernovaFlag)
					args.EnableRoundsHandler = &testscommon.EnableRoundsHandlerStub{IsFlagEnabledCalled: func(flag common.EnableRoundFlag) bool { return flag == common.SupernovaRoundFlag }}
				}
				calls := [][]byte{}
				failure := errors.New("receiver prerequisite unavailable")
				args.ScrProcessor = &testscommon.TxProcessorMock{ProcessSmartContractResultCalled: func(result *smartContractResult.SmartContractResult) (vmcommon.ReturnCode, error) {
					calls = append(calls, result.Data)
					if int(result.Nonce) == tc.failAt {
						return tc.code, failure
					}
					return tc.code, nil
				}}
				receiver, err := NewSmartContractResultPreprocessor(args)
				require.NoError(t, err)
				for _, hash := range mb.TxHashes {
					receiver.scrForBlock.AddTransaction(hash, entries[string(hash)].(*smartContractResult.SmartContractResult), mb.SenderShardID, mb.ReceiverShardID)
				}
				hash, err := core.CalculateHash(args.Marshalizer, args.Hasher, mb)
				require.NoError(t, err)
				var header data.HeaderHandler = &block.Header{MiniBlockHeaders: []block.MiniBlockHeader{{Hash: hash, TxCount: 3}}}
				if async {
					header = &block.HeaderV3{}
				}
				err = receiver.ProcessBlockTransactions(header, &block.Body{MiniBlocks: []*block.MiniBlock{mb}}, haveTimeTrue)
				if tc.failAt < 0 {
					require.NoError(t, err)
					require.Equal(t, mb.TxHashes, calls)
				} else {
					require.Same(t, failure, err)
					require.Equal(t, mb.TxHashes[:tc.failAt+1], calls)
				}
			})
		}
	}
}
