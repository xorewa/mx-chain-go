package hooks_test

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	ht "github.com/multiversx/mx-chain-go/process/drwa/headertime"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CEvaluatedHeaderTimeAcrossSupernova(t *testing.T) {
	hook, _ := qualS1CandidateHook(t, func(uint32, uint64) bool { return true })

	legacy := &block.Header{Epoch: 9, Round: 21, TimeStamp: 1234}
	require.NoError(t, hook.SetEpochStartHeader(&block.Header{Epoch: legacy.Epoch}))
	installLegacy, endLegacy, err := hook.BeginDRWAHeaderEvaluationForHeader(legacy)
	require.NoError(t, err)
	defer endLegacy()

	require.NoError(t, installLegacy(legacy))
	require.Equal(t, uint64(1234), hook.CurrentTimeStamp())
	require.Equal(t, uint64(1234000), hook.CurrentTimeStampMs())
	context, err := hook.EvaluatedHeaderTimeContext()
	require.ErrorIs(t, err, ht.ErrUnavailableHeaderTime)
	require.Nil(t, context)
	endLegacy()

	evaluated := &block.HeaderV3{Epoch: 10, Round: 22, TimestampMs: 1234567}
	require.NoError(t, hook.SetEpochStartHeader(&block.HeaderV3{Epoch: evaluated.Epoch}))
	installEvaluated, endEvaluated, err := hook.BeginDRWAHeaderEvaluationForHeader(evaluated)
	require.NoError(t, err)
	defer endEvaluated()

	context, err = hook.EvaluatedHeaderTimeContext()
	require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
	require.Nil(t, context)
	require.Equal(t, uint64(1234000), hook.CurrentTimeStampMs())

	require.NoError(t, installEvaluated(evaluated))
	require.Equal(t, uint64(1234), hook.CurrentTimeStamp())
	require.Equal(t, uint64(1234567), hook.CurrentTimeStampMs())
	context, err = hook.EvaluatedHeaderTimeContext()
	require.NoError(t, err)
	milliseconds, err := context.Milliseconds()
	require.NoError(t, err)
	require.Equal(t, ht.HeaderMilliseconds(1234567), milliseconds)

	endEvaluated()
	_, err = context.Milliseconds()
	require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
	context, err = hook.EvaluatedHeaderTimeContext()
	require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
	require.Nil(t, context)
	require.Equal(t, uint64(1234567), hook.CurrentTimeStampMs())
}
