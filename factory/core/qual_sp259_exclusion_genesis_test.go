package core

import (
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
)

func TestQualSP259OriginalGenesisExclusionHistory(t *testing.T) {
	proposed := &config.Config{HardforkRoundExclusions: []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 20}}}
	require.NoError(t, CheckDRWAExclusionHistory(nil, proposed, DRWAExclusionHistoryOriginalGenesis))
	require.Error(t, CheckDRWAExclusionHistory(nil, proposed), "absence alone is not an admitted no-predecessor case")
	require.Error(t, CheckDRWAExclusionHistory(proposed, proposed, DRWAExclusionHistoryOriginalGenesis))
	require.Error(t, CheckDRWAExclusionHistory(nil, nil, DRWAExclusionHistoryOriginalGenesis))
	require.Error(t, CheckDRWAExclusionHistory(nil, proposed, 0))
	require.Error(t, CheckDRWAExclusionHistory(nil, proposed, DRWAExclusionHistoryOriginalGenesis, DRWAExclusionHistoryOriginalGenesis))
	invalid := &config.Config{HardforkRoundExclusions: []config.HardforkRoundExclusionConfig{{StartRound: 20, EndRound: 10}}}
	require.ErrorIs(t, CheckDRWAExclusionHistory(nil, invalid, DRWAExclusionHistoryOriginalGenesis), common.ErrInvalidHardforkRoundExclusion)
}
