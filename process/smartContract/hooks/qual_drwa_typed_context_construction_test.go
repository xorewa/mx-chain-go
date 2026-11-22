package hooks_test

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE N-02/M-04 seam candidate. This fixture-owned installer uses
// the real native hook. Only successful, activated header installation issues
// a typed value. Failure invalidates the earlier capability even though the
// native hook correctly retains its earlier header. No new clock, production
// interface, activation default, or DRWA consumer is installed by this test.
// Production requires exclusive lifecycle ownership at every real installer.
type qualConsensusMilliseconds uint64
type qualTimeContext struct {
	hook       *hooks.BlockChainHookImpl
	flags      common.EnableEpochsHandler
	valid      bool
	generation uint64
	value      qualConsensusMilliseconds
}

var errQualTimeContext = errors.New("non-normative time context unavailable")

func (c *qualTimeContext) install(header data.HeaderHandler, enforced bool) error {
	c.valid = false
	c.generation++
	if check.IfNil(header) || check.IfNil(c.flags) || c.hook == nil || !enforced ||
		!c.flags.IsFlagEnabledInEpoch(common.SupernovaFlag, header.GetEpoch()) {
		return errQualTimeContext
	}
	_, expected, err := common.GetHeaderTimestamps(header, c.flags)
	if err != nil {
		return err
	}
	if err = c.hook.SetCurrentHeader(header); err != nil {
		return err
	}
	actual := c.hook.CurrentTimeStampMs()
	if actual != expected {
		return errQualTimeContext
	}
	c.value, c.valid = qualConsensusMilliseconds(actual), true
	return nil
}

func (c *qualTimeContext) milliseconds(generation uint64) (qualConsensusMilliseconds, error) {
	if !c.valid || generation != c.generation {
		return 0, errQualTimeContext
	}
	return c.value, nil
}

func TestQualDRWATypedTimeConstruction(t *testing.T) {
	flags, err := enablers.NewEnableEpochsHandler(config.EnableEpochs{SupernovaEnableEpoch: 10}, &epochNotifier.EpochNotifierStub{})
	require.NoError(t, err)
	for _, header := range []data.HeaderHandler{
		&block.HeaderV3{Epoch: 10, Round: 100, TimestampMs: 1234567},
		&block.MetaBlockV3{Epoch: 10, Round: 100, TimestampMs: 1234567},
	} {
		args := createMockBlockChainHookArgs()
		args.EnableEpochsHandler = flags
		hook, createErr := hooks.NewBlockChainHookImpl(args)
		require.NoError(t, createErr)
		require.NoError(t, hook.SetEpochStartHeader(header))
		context := &qualTimeContext{hook: hook, flags: flags}
		require.NoError(t, context.install(header, true))
		generation := context.generation
		value, readErr := context.milliseconds(generation)
		require.NoError(t, readErr)
		require.Equal(t, qualConsensusMilliseconds(1234567), value)
		// F06 expected source-time boundary is independent of implementation.
		for _, expiry := range []uint64{1234566, 1234567, 1234568} {
			require.Equal(t, expiry == 1234568, uint64(value) < expiry)
		}
		require.ErrorIs(t, context.install(nil, true), errQualTimeContext)
		_, readErr = context.milliseconds(generation)
		require.ErrorIs(t, readErr, errQualTimeContext)
		require.Equal(t, uint64(1234567), hook.CurrentTimeStampMs(), "native prior context is not authority for the failed next installation")
		require.ErrorIs(t, context.install(header, false), errQualTimeContext, "fixture represents any unmet epoch/round/prerequisite predicate")
		legacy := &block.Header{Epoch: 9, TimeStamp: 1234}
		require.ErrorIs(t, context.install(legacy, true), errQualTimeContext, "no pre-Supernova DRWA mode")
		require.NoError(t, context.install(header, true))
		_, readErr = context.milliseconds(generation)
		require.ErrorIs(t, readErr, errQualTimeContext, "re-installation does not revive an old capability")
		_, readErr = context.milliseconds(context.generation)
		require.NoError(t, readErr)
	}
}

func TestQualDRWATypedTimeDirectInstallerBypass(t *testing.T) {
	// Negative control: standalone wrapping is insufficient if another native
	// installer bypasses the owner. This is a construction LIMIT, not a fix.
	flags, err := enablers.NewEnableEpochsHandler(config.EnableEpochs{SupernovaEnableEpoch: 10}, &epochNotifier.EpochNotifierStub{})
	require.NoError(t, err)
	args := createMockBlockChainHookArgs()
	args.EnableEpochsHandler = flags
	hook, err := hooks.NewBlockChainHookImpl(args)
	require.NoError(t, err)
	first := &block.HeaderV3{Epoch: 10, TimestampMs: 1234567}
	require.NoError(t, hook.SetEpochStartHeader(first))
	context := &qualTimeContext{hook: hook, flags: flags}
	require.NoError(t, context.install(first, true))
	require.NoError(t, hook.SetCurrentHeader(&block.HeaderV3{Epoch: 10, TimestampMs: 7654321}))
	stale, err := context.milliseconds(context.generation)
	require.NoError(t, err)
	require.Equal(t, qualConsensusMilliseconds(1234567), stale)
	require.Equal(t, uint64(7654321), hook.CurrentTimeStampMs())
}
