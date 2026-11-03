package hooks_test

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-go/common"
	drwaTime "github.com/multiversx/mx-chain-go/process/drwa/headertime"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// Join the native round-duration reader to the retained evaluated-header owner.
// Epoch, round and timestamp coordinates are synthetic, not an admitted profile.
func TestQualPartialsG25HeaderConsumerComposition(t *testing.T) {
	args := createMockBlockChainHookArgs()
	t.Cleanup(func() { require.NoError(t, args.DataPool.Close()) })
	args.Hasher = blake2b.NewBlake2b()
	args.DRWAHeaderTimeEnabled = func() bool { return true }
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	flags.IsFlagEnabledInEpochCalled = func(f core.EnableEpochFlag, e uint32) bool { return f == common.SupernovaFlag && e >= 10 }
	args.EnableEpochsHandler = flags
	rounds := []uint64{}
	args.RoundHandler = &testscommon.RoundHandlerMock{TimeDurationForRoundCalled: func(r uint64) time.Duration {
		rounds = append(rounds, r)
		return time.Duration(100+r) * time.Millisecond
	}}
	hook, err := hooks.NewBlockChainHookImpl(args)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, hook.Close()) })
	require.NoError(t, hook.SetEpochStartHeader(&block.HeaderV3{Epoch: 10}))
	install, end, err := hook.BeginDRWAHeaderEvaluation()
	require.NoError(t, err)
	defer end()
	require.NoError(t, install(&block.HeaderV3{Epoch: 10, Round: 21, TimestampMs: 111}))
	ctx, err := hook.EvaluatedHeaderTimeContext()
	require.NoError(t, err)
	ms, err := ctx.Milliseconds()
	require.NoError(t, err)
	require.Equal(t, drwaTime.HeaderMilliseconds(111), ms)
	require.Equal(t, uint64(111), hook.CurrentTimeStampMs())
	require.Equal(t, uint64(121), hook.RoundTime())
	require.NoError(t, hook.SetCurrentHeader(&block.HeaderV3{Epoch: 10, Round: 22, TimestampMs: 222}))
	_, err = ctx.Milliseconds()
	require.ErrorIs(t, err, drwaTime.ErrInactiveHeaderTime)
	require.Equal(t, uint64(222), hook.CurrentTimeStampMs())
	require.Equal(t, uint64(122), hook.RoundTime())
	require.Equal(t, []uint64{21, 22}, rounds)
	end()
	require.NoError(t, hook.Close())
	_, _, err = hook.BeginDRWAHeaderEvaluation()
	require.ErrorIs(t, err, drwaTime.ErrInactiveHeaderTime)
}
func TestQualPartialsG25IdentifierConsumers(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, length := range []int{0, 1, 32, 33} {
			t.Run(fmt.Sprintf("enabled_%t/length_%d", enabled, length), func(t *testing.T) {
				args := createMockBlockChainHookArgs()
				t.Cleanup(func() { require.NoError(t, args.DataPool.Close()) })
				flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
				if enabled {
					flags.AddActiveFlags(common.FixCorrectSmallIntAndGasLimitsFlag)
				}
				args.EnableEpochsHandler = flags
				reads, pauses, limited := 0, 0, 0
				sentinel := errors.New("synthetic account read failure")
				args.Accounts = &stateMock.AccountsStub{GetExistingAccountCalled: func([]byte) (vmcommon.AccountHandler, error) { reads++; return nil, sentinel }}
				args.GlobalSettingsHandler = &testscommon.ESDTGlobalSettingsHandlerStub{IsPausedCalled: func([]byte) bool { pauses++; return true }, IsLimitedTransferCalled: func([]byte) bool { limited++; return true }}
				hook, err := hooks.NewBlockChainHookImpl(args)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, hook.Close()) })
				id := bytes.Repeat([]byte{'a'}, length)
				out, err := hook.GetESDTToken(bytes.Repeat([]byte{1}, 32), id, 0)
				require.Nil(t, out)
				rejected := enabled && (length == 0 || length > 32)
				if rejected {
					require.ErrorIs(t, err, hooks.ErrInvalidTokenIdentifier)
				} else {
					require.Same(t, sentinel, err)
				}
				require.Equal(t, !rejected, hook.IsPaused(id))
				require.Equal(t, !rejected, hook.IsLimitedTransfer(id))
				want := 1
				if rejected {
					want = 0
				}
				require.Equal(t, want, reads)
				require.Equal(t, want, pauses)
				require.Equal(t, want, limited)
			})
		}
	}
}
