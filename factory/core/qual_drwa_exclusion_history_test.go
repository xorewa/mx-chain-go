package core

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nativeCore "github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
)

// Synthetic interval/commitment literals are not approved deployment history.
// Copies of the full proposed T09 files ensure a native startup error cannot
// masquerade as rejection of history omission. No node/recovery is launched.
func qualDRWAHistoryFiles(t *testing.T) (config.ConfigurationPathsHolder, string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"config.toml", "enableEpochs.toml", "enableRounds.toml", "economics.toml", "ratings.toml", "drwa.toml"} {
		body, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "evidence", "sp1_t09_configuration_candidate_02", name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), body, 0600))
	}
	return config.ConfigurationPathsHolder{MainConfig: filepath.Join(dir, "config.toml"),
		Epoch: filepath.Join(dir, "enableEpochs.toml"), RoundActivation: filepath.Join(dir, "enableRounds.toml"),
		Economics: filepath.Join(dir, "economics.toml"), Ratings: filepath.Join(dir, "ratings.toml")}, filepath.Join(dir, "drwa.toml")
}

func qualDRWAHistoryLoadIntervals(t *testing.T, intervals []config.HardforkRoundExclusionConfig) *config.Config {
	t.Helper()
	paths, overlay := qualDRWAHistoryFiles(t)
	cfg, err := common.LoadMainConfig(paths.MainConfig)
	require.NoError(t, err)
	cfg.HardforkRoundExclusions = intervals
	qualDRWAEncodeLoaded(t, paths.MainConfig, cfg)
	loaded, err := common.LoadMainConfig(paths.MainConfig)
	require.NoError(t, err)
	require.Equal(t, intervals, loaded.HardforkRoundExclusions)
	candidate, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true})
	require.NoError(t, err, "otherwise valid full loaded configuration")
	require.NoError(t, candidate.CheckEnforcedBlock(3, 440))
	return loaded
}

func TestQualDRWAHistoryNativeOmissionWitness(t *testing.T) {
	predecessor := qualDRWAHistoryLoadIntervals(t, []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 20}, {StartRound: 30, EndRound: 40}})
	proposed := qualDRWAHistoryLoadIntervals(t, []config.HardforkRoundExclusionConfig{{StartRound: 30, EndRound: 40}})
	native, err := common.NewConfiguredRoundExclusionHandler(proposed)
	require.NoError(t, err)
	require.False(t, native.IsRoundExcluded(10), "native supplied-list validation retrieves no predecessor history")
	require.True(t, native.IsRoundExcluded(30))
	err = CheckDRWAExclusionHistory(predecessor, proposed)
	require.EqualError(t, err, "DRWA missing predecessor exclusion [10,20]")
}

func TestQualDRWAHistoryExactLoadedRetention(t *testing.T) {
	prior := []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 20}, {StartRound: 30, EndRound: 40}}
	for _, tc := range []struct {
		name      string
		intervals []config.HardforkRoundExclusionConfig
		missing   string
	}{
		{"identical", []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 20}, {StartRound: 30, EndRound: 40}}, ""},
		{"reordered", []config.HardforkRoundExclusionConfig{{StartRound: 30, EndRound: 40}, {StartRound: 10, EndRound: 20}}, ""},
		{"additional_is_not_approval", []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 20}, {StartRound: 30, EndRound: 40}, {StartRound: 50, EndRound: 60}}, ""},
		{"omit_first", []config.HardforkRoundExclusionConfig{{StartRound: 30, EndRound: 40}}, "[10,20]"},
		{"omit_second", []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 20}}, "[30,40]"},
		{"empty_proposed", nil, "[10,20]"},
		{"changed_start", []config.HardforkRoundExclusionConfig{{StartRound: 11, EndRound: 20}, {StartRound: 30, EndRound: 40}}, "[10,20]"},
		{"changed_end", []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 19}, {StartRound: 30, EndRound: 40}}, "[10,20]"},
		{"split_record", []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 14}, {StartRound: 15, EndRound: 20}, {StartRound: 30, EndRound: 40}}, "[10,20]"},
		{"widen_record", []config.HardforkRoundExclusionConfig{{StartRound: 9, EndRound: 21}, {StartRound: 30, EndRound: 40}}, "[10,20]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			predecessor := qualDRWAHistoryLoadIntervals(t, prior)
			proposed := qualDRWAHistoryLoadIntervals(t, tc.intervals)
			beforePrior := append([]config.HardforkRoundExclusionConfig(nil), predecessor.HardforkRoundExclusions...)
			beforeProposed := append([]config.HardforkRoundExclusionConfig(nil), proposed.HardforkRoundExclusions...)
			err := CheckDRWAExclusionHistory(predecessor, proposed)
			if tc.missing == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, "DRWA missing predecessor exclusion "+tc.missing)
			}
			require.Equal(t, beforePrior, predecessor.HardforkRoundExclusions)
			require.Equal(t, beforeProposed, proposed.HardforkRoundExclusions)
		})
	}
	t.Run("merge_record_is_not_silent_approval_transfer", func(t *testing.T) {
		predecessor := qualDRWAHistoryLoadIntervals(t, []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 14}, {StartRound: 15, EndRound: 20}})
		proposed := qualDRWAHistoryLoadIntervals(t, []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 20}})
		require.EqualError(t, CheckDRWAExclusionHistory(predecessor, proposed), "DRWA missing predecessor exclusion [10,14]")
	})
	t.Run("explicit_empty_is_not_deployment_acceptance", func(t *testing.T) {
		predecessor := qualDRWAHistoryLoadIntervals(t, nil)
		proposed := qualDRWAHistoryLoadIntervals(t, nil)
		require.NoError(t, CheckDRWAExclusionHistory(predecessor, proposed))
	})
	t.Run("reload_configuration_only", func(t *testing.T) {
		predecessor := qualDRWAHistoryLoadIntervals(t, prior)
		proposed := qualDRWAHistoryLoadIntervals(t, prior)
		require.NoError(t, CheckDRWAExclusionHistory(predecessor, proposed))
		freshPredecessor := qualDRWAHistoryLoadIntervals(t, prior)
		freshProposed := qualDRWAHistoryLoadIntervals(t, prior)
		require.NoError(t, CheckDRWAExclusionHistory(freshPredecessor, freshProposed))
		require.Equal(t, predecessor.HardforkRoundExclusions, freshPredecessor.HardforkRoundExclusions)
		require.Equal(t, proposed.HardforkRoundExclusions, freshProposed.HardforkRoundExclusions)
	})
}

func TestQualDRWAHistoryMissingAndNativeInvalidInputs(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		predecessor, proposed *config.Config
	}{
		{"both_nil", nil, nil}, {"nil_predecessor", nil, &config.Config{}}, {"nil_proposed", &config.Config{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Error(t, CheckDRWAExclusionHistory(tc.predecessor, tc.proposed))
		})
	}
	for _, side := range []string{"predecessor", "proposed"} {
		for _, tc := range []struct {
			name      string
			intervals []config.HardforkRoundExclusionConfig
			err       error
		}{
			{"reversed", []config.HardforkRoundExclusionConfig{{StartRound: 20, EndRound: 10}}, common.ErrInvalidHardforkRoundExclusion},
			{"overlap", []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 20}, {StartRound: 20, EndRound: 30}}, common.ErrOverlappingHardforkRoundExclusions},
			{"duplicate", []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 20}, {StartRound: 10, EndRound: 20}}, common.ErrOverlappingHardforkRoundExclusions},
		} {
			t.Run(side+"_"+tc.name, func(t *testing.T) {
				predecessor, proposed := &config.Config{}, &config.Config{}
				if side == "predecessor" {
					predecessor.HardforkRoundExclusions = tc.intervals
				} else {
					proposed.HardforkRoundExclusions = tc.intervals
				}
				require.ErrorIs(t, CheckDRWAExclusionHistory(predecessor, proposed), tc.err)
			})
		}
		t.Run(side+"_invalid_checkpoint", func(t *testing.T) {
			predecessor, proposed := &config.Config{}, &config.Config{}
			bad := config.HardforkRecoveryCheckpointConfig{Enabled: true, Round: 99}
			if side == "predecessor" {
				predecessor.HardforkRecoveryCheckpoint = bad
			} else {
				proposed.HardforkRecoveryCheckpoint = bad
			}
			require.ErrorIs(t, CheckDRWAExclusionHistory(predecessor, proposed), common.ErrInvalidRecoveryCheckpoint)
		})
	}
}

func TestQualDRWAHistoryNativeInclusiveBoundaries(t *testing.T) {
	intervals := []config.HardforkRoundExclusionConfig{{StartRound: 0, EndRound: 0}, {StartRound: 4294967295, EndRound: 18446744073709551615}}
	predecessor := qualDRWAHistoryLoadIntervals(t, intervals)
	proposed := qualDRWAHistoryLoadIntervals(t, intervals)
	require.NoError(t, CheckDRWAExclusionHistory(predecessor, proposed))
	handler, err := common.NewConfiguredRoundExclusionHandler(proposed)
	require.NoError(t, err)
	for _, tc := range []struct {
		round    uint64
		excluded bool
	}{{0, true}, {1, false}, {4294967294, false}, {4294967295, true}, {18446744073709551615, true}} {
		require.Equal(t, tc.excluded, handler.IsRoundExcluded(tc.round))
	}
}

func TestQualDRWAHistoryNativeCheckpointIsNotAuthority(t *testing.T) {
	cfg := &config.Config{HardforkRoundExclusions: []config.HardforkRoundExclusionConfig{{StartRound: 100, EndRound: 199}},
		HardforkRecoveryCheckpoint: config.HardforkRecoveryCheckpointConfig{Enabled: true, Round: 99,
			Headers: []config.HardforkRecoveryHeaderConfig{{ShardID: 0, Hash: strings.Repeat("aa", 32)}, {ShardID: nativeCore.MetachainShardId, Hash: strings.Repeat("bb", 32)}}}}
	handler, err := common.NewConfiguredRoundExclusionHandler(cfg)
	require.NoError(t, err)
	checkpoint, err := common.NewRecoveryCheckpoint(cfg)
	require.NoError(t, err)
	require.True(t, checkpoint.HasAllShards(1), "synthetic meta+one shard only")
	require.False(t, checkpoint.HasAllShards(3), "not actual required topology support")
	for _, tc := range []struct {
		name     string
		round    uint64
		shard    uint32
		hash     []byte
		excluded bool
	}{
		{"bound_shard", 99, 0, bytes.Repeat([]byte{0xaa}, 32), false},
		{"bound_meta", 99, nativeCore.MetachainShardId, bytes.Repeat([]byte{0xbb}, 32), false},
		{"wrong_hash", 99, 0, bytes.Repeat([]byte{0xbb}, 32), true},
		{"missing_shard", 99, 1, bytes.Repeat([]byte{0xaa}, 32), true},
		{"excluded_start", 100, 0, nil, true}, {"excluded_end", 199, 0, nil, true}, {"after", 200, 0, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.excluded, common.IsHeaderExcluded(handler, tc.round, tc.shard, tc.hash))
		})
	}
	hash, ok := checkpoint.HeaderHash(0)
	require.True(t, ok)
	hash[0] = 0
	again, ok := checkpoint.HeaderHash(0)
	require.True(t, ok)
	require.Equal(t, bytes.Repeat([]byte{0xaa}, 32), again, "native returned commitment is a copy")
}
