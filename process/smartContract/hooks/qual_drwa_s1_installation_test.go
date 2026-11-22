package hooks_test

import "github.com/multiversx/mx-chain-go/testscommon/marshallerMock"

import (
	"errors"
	"fmt"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	ht "github.com/multiversx/mx-chain-go/process/drwa/headertime"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/testscommon"
	epochs "github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/stretchr/testify/require"
	"testing"
)

func qualS1CandidateHook(t *testing.T, enabled func(uint32, uint64) bool) (*hooks.BlockChainHookImpl, *testscommon.EpochStartTriggerStub) {
	t.Helper()
	args := createMockBlockChainHookArgs()
	args.Hasher = blake2b.NewBlake2b()
	args.Marshalizer = &marshal.GogoProtoMarshalizer{}
	args.DRWAHeaderTimeEnabledAt = enabled
	flags := epochs.NewEnableEpochsHandlerStub()
	flags.IsFlagEnabledInEpochCalled = func(flag core.EnableEpochFlag, epoch uint32) bool { return flag != common.SupernovaFlag || epoch >= 10 }
	args.EnableEpochsHandler = flags
	trigger := &testscommon.EpochStartTriggerStub{}
	args.EpochStartTrigger = trigger
	hook, err := hooks.NewBlockChainHookImpl(args)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, hook.Close()); require.NoError(t, args.DataPool.Close()) })
	require.NoError(t, hook.SetEpochStartHeader(&block.HeaderV3{Epoch: 10}))
	return hook, trigger
}

func TestQualS1CandidateTimeFirstActivation(t *testing.T) {
	for _, tc := range []struct {
		epoch  uint32
		round  uint64
		active bool
	}{{9, 22, false}, {10, 21, false}, {10, 22, true}, {11, 22, true}} {
		t.Run(fmt.Sprintf("epoch_%d_round_%d", tc.epoch, tc.round), func(t *testing.T) {
			hook, _ := qualS1CandidateHook(t, func(e uint32, r uint64) bool { return e >= 10 && r >= 22 })
			require.NoError(t, hook.SetEpochStartHeader(&block.HeaderV3{Epoch: tc.epoch}))
			// Previous installed header remains pre-activation at begin.
			require.NoError(t, hook.SetCurrentHeader(&block.HeaderV3{Epoch: tc.epoch, Round: 1, TimestampMs: 1}))
			header := &block.HeaderV3{Epoch: tc.epoch, Round: tc.round, TimestampMs: 1234567}
			install, end, err := hook.BeginDRWAHeaderEvaluationForHeader(header)
			require.NoError(t, err)
			defer end()
			require.NoError(t, install(header))
			require.Equal(t, tc.round, hook.CurrentRound())
			ctx, err := hook.EvaluatedHeaderTimeContext()
			if !tc.active {
				require.Error(t, err)
				require.Nil(t, ctx)
				return
			}
			require.NoError(t, err)
			milliseconds, err := ctx.Milliseconds()
			require.NoError(t, err)
			require.Equal(t, ht.HeaderMilliseconds(1234567), milliseconds)
			identity, shard := ctx.HeaderIdentity()
			require.Equal(t, header.GetShardID(), shard)
			expected, err := core.CalculateHash(&marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), header)
			require.NoError(t, err)
			require.Equal(t, expected, identity)
			end()
			end()
			_, err = ctx.Milliseconds()
			require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
		})
	}
}

func TestQualS1CandidateTimeIdentityAndInvalidation(t *testing.T) {
	for _, mode := range []string{"replacement", "mutated_candidate", "raw_ABA", "ended", "activation_lost", "lease", "nil_install", "native_error"} {
		t.Run(mode, func(t *testing.T) {
			active := true
			hook, trigger := qualS1CandidateHook(t, func(uint32, uint64) bool { return active })
			header := &block.HeaderV3{Epoch: 10, Round: 22, TimestampMs: 111}
			install, end, err := hook.BeginDRWAHeaderEvaluationForHeader(header)
			require.NoError(t, err)
			defer end()
			if mode == "replacement" {
				require.NoError(t, install(&block.HeaderV3{Epoch: 10, Round: 23, TimestampMs: 111}))
				_, err = hook.EvaluatedHeaderTimeContext()
				require.Error(t, err)
				require.Equal(t, uint64(23), hook.CurrentRound())
				return
			}
			if mode == "mutated_candidate" {
				header.TimestampMs++
				require.NoError(t, install(header))
				_, err = hook.EvaluatedHeaderTimeContext()
				require.Error(t, err)
				return
			}
			require.NoError(t, install(header))
			ctx, err := hook.EvaluatedHeaderTimeContext()
			require.NoError(t, err)
			switch mode {
			case "raw_ABA":
				require.NoError(t, hook.SetCurrentHeader(&block.HeaderV3{Epoch: 10, Round: 23}))
				require.NoError(t, hook.SetCurrentHeader(header))
			case "ended":
				end()
				require.NoError(t, install(header))
			case "activation_lost":
				active = false
			case "lease":
				_, _, release, e := ctx.Lease()
				require.NoError(t, e)
				defer release()
				require.NoError(t, install(header))
			case "nil_install":
				require.ErrorIs(t, install(nil), hooks.ErrNilCurrentHeader)
			case "native_error":
				selected := errors.New("native epoch error")
				trigger.LastCommitedEpochStartHdrCalled = func() (data.HeaderHandler, error) { return nil, selected }
				require.ErrorIs(t, install(&block.HeaderV3{Epoch: 11}), selected)
			}
			_, err = ctx.Milliseconds()
			require.Error(t, err)
		})
	}
}

func TestQualS1CandidateTimeOrdinaryDifferential(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, failed := range []bool{false, true} {
			hook, trigger := qualS1CandidateHook(t, func(uint32, uint64) bool { return enabled })
			previous := &block.HeaderV3{Epoch: 10, Round: 21, TimestampMs: 111}
			candidate := &block.HeaderV3{Epoch: 10, Round: 22, TimestampMs: 222}
			selected := errors.New("ordinary native epoch error")
			if failed {
				candidate.Epoch = 11
				trigger.LastCommitedEpochStartHdrCalled = func() (data.HeaderHandler, error) { return nil, selected }
			}
			require.NoError(t, hook.SetCurrentHeader(previous))
			oldErr := hook.SetCurrentHeader(candidate)
			oldRound, oldNonce, oldEpoch, oldTimestamp := hook.CurrentRound(), hook.CurrentNonce(), hook.CurrentEpoch(), hook.CurrentTimeStamp()
			require.NoError(t, hook.SetCurrentHeader(previous))
			install, end, err := hook.BeginDRWAHeaderEvaluationForHeader(candidate)
			require.NoError(t, err)
			newErr := install(candidate)
			end()
			require.Equal(t, oldErr, newErr)
			require.Equal(t, oldRound, hook.CurrentRound())
			require.Equal(t, oldNonce, hook.CurrentNonce())
			require.Equal(t, oldEpoch, hook.CurrentEpoch())
			require.Equal(t, oldTimestamp, hook.CurrentTimeStamp())
		}
	}
}

// M-2: only the initial candidate hash fails. Native installation and the
// later context hash succeed, isolating the retained candidateError check.
func TestQualS1CandidateHashFailureWithholdsTypedView(t *testing.T) {
	args := createMockBlockChainHookArgs()
	selected := errors.New("candidate identity marshal failure")
	nativeMarshalizer := &marshal.GogoProtoMarshalizer{}
	calls := 0
	args.Marshalizer = &marshallerMock.MarshalizerStub{MarshalCalled: func(value interface{}) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, selected
		}
		return nativeMarshalizer.Marshal(value)
	}}
	args.Hasher = blake2b.NewBlake2b()
	args.DRWAHeaderTimeEnabledAt = func(uint32, uint64) bool { return true }
	flags := epochs.NewEnableEpochsHandlerStub()
	flags.IsFlagEnabledInEpochCalled = func(flag core.EnableEpochFlag, epoch uint32) bool { return flag != common.SupernovaFlag || epoch >= 10 }
	args.EnableEpochsHandler = flags
	hook, err := hooks.NewBlockChainHookImpl(args)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, hook.Close()); require.NoError(t, args.DataPool.Close()) })
	require.NoError(t, hook.SetEpochStartHeader(&block.HeaderV3{Epoch: 10}))
	candidate := &block.HeaderV3{Epoch: 10, Round: 22, Nonce: 7, TimestampMs: 111}
	install, end, err := hook.BeginDRWAHeaderEvaluationForHeader(candidate)
	require.NoError(t, err)
	defer end()
	require.Equal(t, 1, calls)
	require.NoError(t, install(candidate), "typed identity failure must not replace the native result")
	require.Greater(t, calls, 1, "the subsequent context hash must succeed")
	require.Equal(t, uint64(22), hook.CurrentRound())
	require.Equal(t, uint64(7), hook.CurrentNonce())
	ctx, err := hook.EvaluatedHeaderTimeContext()
	require.ErrorIs(t, err, selected)
	require.Nil(t, ctx)
}

// L-1: defensive API branch; the actual proposal rejects nil before begin.
func TestQualS1NilCandidateInvalidatesActiveTypedView(t *testing.T) {
	hook, _ := qualS1CandidateHook(t, func(uint32, uint64) bool { return true })
	candidate := &block.HeaderV3{Epoch: 10, Round: 22, TimestampMs: 111}
	install, end, err := hook.BeginDRWAHeaderEvaluationForHeader(candidate)
	require.NoError(t, err)
	defer end()
	require.NoError(t, install(candidate))
	ctx, err := hook.EvaluatedHeaderTimeContext()
	require.NoError(t, err)
	raw, exit, err := hook.BeginDRWAHeaderEvaluationForHeader(nil)
	require.NoError(t, err)
	defer exit()
	_, err = ctx.Milliseconds()
	require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
	require.ErrorIs(t, raw(nil), hooks.ErrNilCurrentHeader)
	require.Equal(t, uint64(22), hook.CurrentRound())
}
