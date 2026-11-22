package hooks_test

import (
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	"github.com/stretchr/testify/require"
)

// W02, Part A 2.3 N-02/M-04 and Part B 3.2/11.3: observe the selected
// evaluated-header candidate with the real epoch handler. These are hook-level
// experiments, not evidence of consensus, scheduling, restart or DRWA admission.
func TestQualDRWAEvaluatedHeaderTime(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		header                data.HeaderHandler
		seconds, milliseconds uint64
	}{
		{"shard_legacy", &block.Header{Epoch: 9, Round: 99, Nonce: 7, TimeStamp: 1234}, 1234, 1234000},
		{"meta_legacy", &block.MetaBlock{Epoch: 9, Round: 99, Nonce: 7, TimeStamp: 1234}, 1234, 1234000},
		{"shard_v3", &block.HeaderV3{Epoch: 10, Round: 100, Nonce: 8, TimestampMs: 1234567}, 1234, 1234567},
		{"meta_v3", &block.MetaBlockV3{Epoch: 10, Round: 100, Nonce: 8, TimestampMs: 1234567}, 1234, 1234567},
	} {
		for _, notification := range []uint32{0, math.MaxUint32} {
			t.Run(fmt.Sprintf("%s/notified_epoch_%d", tc.name, notification), func(t *testing.T) {
				args := createMockBlockChainHookArgs()
				flags, err := enablers.NewEnableEpochsHandler(config.EnableEpochs{SupernovaEnableEpoch: 10}, &epochNotifier.EpochNotifierStub{})
				require.NoError(t, err)
				flags.EpochConfirmed(notification, 0)
				args.EnableEpochsHandler = flags
				// The committed and current-chain headers deliberately disagree
				// with the header explicitly installed for evaluation.
				args.BlockChain = &testscommon.ChainHandlerStub{
					GetLastExecutedBlockHeaderCalled: func() data.HeaderHandler { return &block.Header{Epoch: 1, Nonce: 3, Round: 4, TimeStamp: 77} },
					GetCurrentBlockHeaderCalled:      func() data.HeaderHandler { return &block.Header{Epoch: 2, Nonce: 5, Round: 6, TimeStamp: 88} },
				}
				hook, err := hooks.NewBlockChainHookImpl(args)
				require.NoError(t, err)
				require.NoError(t, hook.SetEpochStartHeader(tc.header))
				require.NoError(t, hook.SetCurrentHeader(tc.header))
				require.Equal(t, tc.seconds, hook.CurrentTimeStamp())
				require.Equal(t, tc.milliseconds, hook.CurrentTimeStampMs())
				require.Equal(t, tc.header.GetRound(), hook.CurrentRound())
				require.Equal(t, tc.header.GetNonce(), hook.CurrentNonce())
				require.Equal(t, tc.header.GetEpoch(), hook.CurrentEpoch())
				require.Equal(t, uint64(77000), hook.LastTimeStampMs())
				// Nil input is rejected before header-state processing. Non-nil
				// trigger/storage failures are exercised separately below.
				require.ErrorIs(t, hook.SetCurrentHeader(nil), hooks.ErrNilCurrentHeader)
				require.Equal(t, tc.milliseconds, hook.CurrentTimeStampMs())
			})
		}
	}
}

func TestQualDRWAHeaderInstallationFailureKeepsPreviousContext(t *testing.T) {
	expected := errors.New("epoch-start header unavailable")
	for _, tc := range []struct {
		name                             string
		lastNil                          bool
		lastErr, storageErr, expectedErr error
		storageCalls                     int
	}{
		{"trigger_error", false, expected, nil, expected, 0},
		{"trigger_nil", true, nil, nil, hooks.ErrNilLastCommitedEpochStartHdr, 0},
		{"storage_error", false, nil, expected, expected, 1},
		{"storage_nil", false, nil, nil, hooks.ErrNilLastCommitedEpochStartHdr, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := createMockBlockChainHookArgs()
			flags, err := enablers.NewEnableEpochsHandler(config.EnableEpochs{SupernovaEnableEpoch: 10}, &epochNotifier.EpochNotifierStub{})
			require.NoError(t, err)
			args.EnableEpochsHandler = flags
			previous := &block.Header{Epoch: 9, Round: 91, Nonce: 5, TimeStamp: 1234}
			lastCalls, storageCalls := 0, 0
			args.EpochStartTrigger = &testscommon.EpochStartTriggerStub{
				LastCommitedEpochStartHdrCalled: func() (data.HeaderHandler, error) {
					lastCalls++
					if tc.lastNil || tc.lastErr != nil {
						return nil, tc.lastErr
					}
					return previous, nil
				},
				GetEpochStartHdrFromStorageCalled: func(epoch uint32) (data.HeaderHandler, error) {
					storageCalls++
					require.Equal(t, uint32(10), epoch)
					return nil, tc.storageErr
				},
			}
			hook, err := hooks.NewBlockChainHookImpl(args)
			require.NoError(t, err)
			require.NoError(t, hook.SetEpochStartHeader(previous))
			require.NoError(t, hook.SetCurrentHeader(previous))
			attempted := &block.HeaderV3{Epoch: 10, Round: 100, Nonce: 6, TimestampMs: 2345678}
			require.ErrorIs(t, hook.SetCurrentHeader(attempted), tc.expectedErr)
			require.Equal(t, 1, lastCalls)
			require.Equal(t, tc.storageCalls, storageCalls)
			require.Equal(t, uint64(1234000), hook.CurrentTimeStampMs())
			require.Equal(t, uint32(9), hook.CurrentEpoch())
			require.Equal(t, uint64(91), hook.CurrentRound())
			require.Equal(t, uint64(5), hook.CurrentNonce())
			require.Equal(t, uint64(1234000), hook.EpochStartBlockTimeStampMs())
			require.Equal(t, uint64(91), hook.EpochStartBlockRound())
			require.Equal(t, uint64(5), hook.EpochStartBlockNonce())
		})
	}
}

func TestQualDRWATimeConversionUsesHeaderEpochAndBounds(t *testing.T) {
	flags, err := enablers.NewEnableEpochsHandler(config.EnableEpochs{SupernovaEnableEpoch: 10}, &epochNotifier.EpochNotifierStub{})
	require.NoError(t, err)
	for _, tc := range []struct {
		name                              string
		epoch                             uint32
		round, raw, seconds, milliseconds uint64
	}{
		{"before_epoch_early_round", 9, 0, 1234, 1234, 1234000},
		{"before_epoch_late_round", 9, math.MaxUint64, 1234, 1234, 1234000},
		{"at_epoch_early_round", 10, 0, 1234567, 1234, 1234567},
		{"at_epoch_late_round", 10, math.MaxUint64, 1234567, 1234, 1234567},
		{"largest_exact_seconds", 9, 0, math.MaxUint64 / 1000, math.MaxUint64 / 1000, 18446744073709551000},
		// Synthetic helper input outside a sane header range: this demonstrates
		// unchecked arithmetic, not that block validation admits this header.
		{"seconds_overflow_wraps", 9, 0, math.MaxUint64/1000 + 1, math.MaxUint64/1000 + 1, 384},
		{"largest_milliseconds", 10, 0, math.MaxUint64, math.MaxUint64 / 1000, math.MaxUint64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seconds, milliseconds, err := common.GetHeaderTimestamps(&block.Header{Epoch: tc.epoch, Round: tc.round, TimeStamp: tc.raw}, flags)
			require.NoError(t, err)
			require.Equal(t, tc.seconds, seconds)
			require.Equal(t, tc.milliseconds, milliseconds)
		})
	}
}

func TestQualDRWAProposedMetaEpochIsNotRawHeaderEpoch(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		header                  data.HeaderHandler
		fixEpoch, expectedEpoch uint32
	}{
		{"fix_enabled_at_next_epoch", &block.MetaBlockV3{Epoch: 10, Round: 100, TimestampMs: 1234567, EpochChangeProposed: true}, 11, 11},
		{"fix_disabled_at_next_epoch", &block.MetaBlockV3{Epoch: 10, Round: 100, TimestampMs: 1234567, EpochChangeProposed: true}, 12, 10},
		{"not_proposed", &block.MetaBlockV3{Epoch: 10, Round: 100, TimestampMs: 1234567}, 11, 10},
		{"legacy_meta", &block.MetaBlock{Epoch: 10, Round: 100, TimeStamp: 1234567}, 11, 10},
		{"shard_v3", &block.HeaderV3{Epoch: 10, Round: 100, TimestampMs: 1234567}, 11, 10},
	} {
		for _, notification := range []uint32{0, math.MaxUint32} {
			t.Run(fmt.Sprintf("%s/notified_epoch_%d", tc.name, notification), func(t *testing.T) {
				args := createMockBlockChainHookArgs()
				flags, err := enablers.NewEnableEpochsHandler(config.EnableEpochs{SupernovaEnableEpoch: 10, FixEpochChangeProposedCurrentEpochEnableEpoch: tc.fixEpoch}, &epochNotifier.EpochNotifierStub{})
				require.NoError(t, err)
				flags.EpochConfirmed(notification, 0)
				args.EnableEpochsHandler = flags
				hook, err := hooks.NewBlockChainHookImpl(args)
				require.NoError(t, err)
				require.NoError(t, hook.SetEpochStartHeader(tc.header))
				require.NoError(t, hook.SetCurrentHeader(tc.header))
				require.Equal(t, uint32(10), tc.header.GetEpoch())
				require.Equal(t, tc.expectedEpoch, hook.CurrentEpoch())
				require.Equal(t, uint64(1234567), hook.CurrentTimeStampMs())
			})
		}
	}
}
