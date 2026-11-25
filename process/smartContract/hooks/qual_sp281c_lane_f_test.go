package hooks_test

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	ht "github.com/multiversx/mx-chain-go/process/drwa/headertime"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CLaneFCandidateWithoutCoordinateConfiguration(t *testing.T) {
	var missing *hooks.BlockChainHookImpl
	install, end, err := missing.BeginDRWAHeaderEvaluationForHeader(nil)
	require.ErrorIs(t, err, ht.ErrUnavailableHeaderTime)
	require.Nil(t, install)
	require.Nil(t, end)

	hook, _ := qualS1CandidateHook(t, nil)
	header := &block.HeaderV3{Epoch: 10, Round: 27}
	install, end, err = hook.BeginDRWAHeaderEvaluationForHeader(header)
	require.NoError(t, err)
	defer end()
	require.NoError(t, install(header))
	require.Equal(t, uint64(27), hook.CurrentRound())
	context, err := hook.EvaluatedHeaderTimeContext()
	require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
	require.Nil(t, context)
}
