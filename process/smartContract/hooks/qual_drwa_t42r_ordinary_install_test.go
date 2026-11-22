package hooks_test

import (
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-go/common"
	drwatime "github.com/multiversx/mx-chain-go/process/drwa/headertime"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/stretchr/testify/require"
	"sync/atomic"
	"testing"
)

// T42R-1: use the production constructor, with the actual native hasher present
// but no DRWA consumer. An invalidated typed view cannot fail native install.
func TestQualDRWAT42RNativeInterleavedInstall(t *testing.T) {
	for _, hasher := range []bool{false, true} {
		name := "no_hasher"
		if hasher {
			name = "production_hasher"
		}
		t.Run(name, func(t *testing.T) {
			args := createMockBlockChainHookArgs()
			t.Cleanup(func() { require.NoError(t, args.DataPool.Close()) })
			if hasher {
				args.Hasher = blake2b.NewBlake2b()
			}
			hook, err := hooks.NewBlockChainHookImpl(args)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, hook.Close()) })
			install, end, err := hook.BeginDRWAHeaderEvaluation()
			require.NoError(t, err)
			defer end()
			require.NoError(t, hook.SetCurrentHeader(&block.HeaderV3{Round: 22}))
			require.NoError(t, install(&block.HeaderV3{Round: 21}))
			require.Equal(t, uint64(21), hook.CurrentRound())
			_, err = hook.EvaluatedHeaderTimeContext()
			if hasher {
				require.ErrorIs(t, err, drwatime.ErrInactiveHeaderTime)
			} else {
				require.ErrorIs(t, err, drwatime.ErrUnavailableHeaderTime)
			}
		})
	}
}

// Explicit fixture activation models a native-owner dependency, not a profile
// admission or a requester-controlled flag. Epoch/time/round values are R7
// experimental coordinates reused from the existing T42 qualifiers.
type qualT42RHasher struct {
	hashing.Hasher
	calls atomic.Int64
}

func (h *qualT42RHasher) Compute(s string) []byte { h.calls.Add(1); return h.Hasher.Compute(s) }
func qualT42RHook(t *testing.T, present bool, enabled func() bool) (*hooks.BlockChainHookImpl, *qualT42RHasher, *testscommon.EpochStartTriggerStub) {
	t.Helper()
	args := createMockBlockChainHookArgs()
	t.Cleanup(func() { require.NoError(t, args.DataPool.Close()) })
	hash := &qualT42RHasher{Hasher: blake2b.NewBlake2b()}
	if present {
		args.Hasher = hash
	}
	args.DRWAHeaderTimeEnabled = enabled
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	flags.IsFlagEnabledInEpochCalled = func(flag core.EnableEpochFlag, epoch uint32) bool {
		if flag == common.SupernovaFlag {
			return epoch >= 10
		}
		return true
	}
	args.EnableEpochsHandler = flags
	trigger := &testscommon.EpochStartTriggerStub{}
	args.EpochStartTrigger = trigger
	hook, err := hooks.NewBlockChainHookImpl(args)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, hook.Close()) })
	require.NoError(t, hook.SetEpochStartHeader(&block.HeaderV3{Epoch: 10}))
	return hook, hash, trigger
}
func TestQualDRWAT42RNativeResults(t *testing.T) {
	for _, mode := range []string{"no_hasher", "ordinary_hasher", "active"} {
		for _, kind := range []string{"interleaved", "ended", "nil", "epoch_failure", "closed", "lease_raw", "lease_owned"} {
			t.Run(mode+"/"+kind, func(t *testing.T) {
				var enabled func() bool
				if mode == "active" {
					enabled = func() bool { return true }
				}
				hook, _, trigger := qualT42RHook(t, mode != "no_hasher", enabled)
				first := &block.HeaderV3{Epoch: 10, Round: 21, TimestampMs: 111}
				second := &block.HeaderV3{Epoch: 10, Round: 22, TimestampMs: 222}
				install, end, err := hook.BeginDRWAHeaderEvaluation()
				require.NoError(t, err)
				defer end()
				require.NoError(t, install(first))
				var old *drwatime.HeaderTimeContext
				if mode == "active" {
					old, err = hook.EvaluatedHeaderTimeContext()
					require.NoError(t, err)
				}
				var release func()
				if (kind == "lease_raw" || kind == "lease_owned") && mode == "active" {
					_, _, release, err = old.Lease()
					require.NoError(t, err)
					defer release()
				}
				switch kind {
				case "interleaved":
					require.NoError(t, hook.SetCurrentHeader(second))
					require.NoError(t, install(first))
					require.Equal(t, uint64(21), hook.CurrentRound())
				case "ended":
					end()
					require.NoError(t, install(second))
					require.Equal(t, uint64(22), hook.CurrentRound())
				case "nil":
					require.ErrorIs(t, install(nil), hooks.ErrNilCurrentHeader)
					require.ErrorIs(t, hook.SetCurrentHeader(nil), hooks.ErrNilCurrentHeader)
					require.Equal(t, uint64(21), hook.CurrentRound())
				case "epoch_failure":
					failure := errors.New("T42R native epoch failure")
					trigger.LastCommitedEpochStartHdrCalled = func() (data.HeaderHandler, error) { return nil, failure }
					require.ErrorIs(t, install(&block.HeaderV3{Epoch: 11}), failure)
					require.ErrorIs(t, hook.SetCurrentHeader(&block.HeaderV3{Epoch: 11}), failure)
					require.Equal(t, uint64(21), hook.CurrentRound())
				case "closed":
					require.NoError(t, hook.Close())
					require.NoError(t, install(second))
					require.Equal(t, uint64(22), hook.CurrentRound())
				case "lease_raw":
					require.NoError(t, hook.SetCurrentHeader(second))
					require.Equal(t, uint64(22), hook.CurrentRound())
				case "lease_owned":
					require.NoError(t, install(second))
					require.Equal(t, uint64(22), hook.CurrentRound())
				}
				if mode == "active" && release == nil || mode == "active" && kind == "lease_raw" || mode == "active" && kind == "lease_owned" {
					_, err = old.Milliseconds()
					require.ErrorIs(t, err, drwatime.ErrInactiveHeaderTime)
				}
			})
		}
	}
}
func TestQualDRWAT42ROrdinaryCostAndActivation(t *testing.T) {
	var active atomic.Bool
	for _, mode := range []string{"omitted", "disabled", "toggle"} {
		t.Run(mode, func(t *testing.T) {
			active.Store(false)
			var enabled func() bool
			if mode != "omitted" {
				enabled = active.Load
			}
			hook, hash, _ := qualT42RHook(t, true, enabled)
			header := &block.HeaderV3{Epoch: 10, Round: 21, TimestampMs: 111}
			for i := 0; i < 3; i++ {
				install, end, err := hook.BeginDRWAHeaderEvaluation()
				require.NoError(t, err)
				require.NoError(t, install(header))
				require.NoError(t, hook.SetCurrentHeader(header))
				end()
			}
			require.Zero(t, hash.calls.Load(), "ordinary native proposals must perform no DRWA header hashes")
			if mode != "toggle" {
				return
			}
			active.Store(true)
			install, end, err := hook.BeginDRWAHeaderEvaluation()
			require.NoError(t, err)
			require.NoError(t, install(header))
			ctx, err := hook.EvaluatedHeaderTimeContext()
			require.NoError(t, err)
			_, err = ctx.Milliseconds()
			require.NoError(t, err)
			require.Positive(t, hash.calls.Load())
			active.Store(false)
			_, err = ctx.Milliseconds()
			require.ErrorIs(t, err, drwatime.ErrInactiveHeaderTime)
			count := hash.calls.Load()
			require.NoError(t, hook.SetCurrentHeader(header))
			end()
			native, exit, err := hook.BeginDRWAHeaderEvaluation()
			require.NoError(t, err)
			require.NoError(t, native(header))
			exit()
			require.Equal(t, count, hash.calls.Load())
			active.Store(true)
			_, err = ctx.Milliseconds()
			require.ErrorIs(t, err, drwatime.ErrInactiveHeaderTime)
			next, done, err := hook.BeginDRWAHeaderEvaluation()
			require.NoError(t, err)
			defer done()
			require.NoError(t, next(header))
			_, err = hook.EvaluatedHeaderTimeContext()
			require.NoError(t, err)
		})
	}
}
