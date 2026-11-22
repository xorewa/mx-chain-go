package core

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	commonConfigs "github.com/multiversx/mx-chain-go/common/configs"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/common/graceperiod"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/stretchr/testify/require"
)

// T09-M23: independently malformed startup inputs, including entries after the
// enforcement coordinate. These cases never call core Create or start NTP.
func TestQualDRWALoadedStartupKernelNativeDenials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*config.Config)
		want   error
		text   string
	}{
		{"grace_missing_base", func(c *config.Config) {
			c.GeneralSettings.EpochChangeGracePeriodByEpoch = c.GeneralSettings.EpochChangeGracePeriodByEpoch[1:]
		}, nil, "missing configuration for epoch 0"},
		{"grace_duplicate", func(c *config.Config) {
			c.GeneralSettings.EpochChangeGracePeriodByEpoch = append(c.GeneralSettings.EpochChangeGracePeriodByEpoch, c.GeneralSettings.EpochChangeGracePeriodByEpoch[0])
		}, nil, "duplicated epoch config"},
		{"epoch_start_missing_base", func(c *config.Config) {
			c.GeneralSettings.EpochStartConfigsByEpoch = c.GeneralSettings.EpochStartConfigsByEpoch[1:]
		}, commonConfigs.ErrMissingEpochZeroConfig, ""},
		{"epoch_start_duplicate", func(c *config.Config) {
			c.GeneralSettings.EpochStartConfigsByEpoch = append(c.GeneralSettings.EpochStartConfigsByEpoch, c.GeneralSettings.EpochStartConfigsByEpoch[0])
		}, commonConfigs.ErrDuplicatedEpochConfig, ""},
		{"epoch_start_round_missing_base", func(c *config.Config) {
			c.GeneralSettings.EpochStartConfigsByRound = c.GeneralSettings.EpochStartConfigsByRound[1:]
		}, commonConfigs.ErrMissingRoundZeroConfig, ""},
		{"epoch_start_round_duplicate", func(c *config.Config) {
			c.GeneralSettings.EpochStartConfigsByRound = append(c.GeneralSettings.EpochStartConfigsByRound, c.GeneralSettings.EpochStartConfigsByRound[0])
		}, commonConfigs.ErrDuplicatedRoundConfig, ""},
		{"consensus_epoch_missing_base", func(c *config.Config) {
			c.GeneralSettings.ConsensusConfigsByEpoch = c.GeneralSettings.ConsensusConfigsByEpoch[1:]
		}, commonConfigs.ErrMissingEpochZeroConfig, ""},
		{"consensus_epoch_duplicate", func(c *config.Config) {
			c.GeneralSettings.ConsensusConfigsByEpoch = append(c.GeneralSettings.ConsensusConfigsByEpoch, c.GeneralSettings.ConsensusConfigsByEpoch[0])
		}, commonConfigs.ErrDuplicatedEpochConfig, ""},
		{"consensus_round_missing_base", func(c *config.Config) {
			c.GeneralSettings.ConsensusConfigsByRound = c.GeneralSettings.ConsensusConfigsByRound[1:]
		}, commonConfigs.ErrMissingRoundZeroConfig, ""},
		{"consensus_round_duplicate", func(c *config.Config) {
			c.GeneralSettings.ConsensusConfigsByRound = append(c.GeneralSettings.ConsensusConfigsByRound, c.GeneralSettings.ConsensusConfigsByRound[0])
		}, commonConfigs.ErrDuplicatedRoundConfig, ""},
		{"consensus_future_count", func(c *config.Config) {
			p := c.GeneralSettings.ConsensusConfigsByRound[0]
			p.EnableRound = 1000
			p.SubroundsTiming = p.SubroundsTiming[:3]
			c.GeneralSettings.ConsensusConfigsByRound = append(c.GeneralSettings.ConsensusConfigsByRound, p)
		}, commonConfigs.ErrInvalidSubroundsTimingCount, ""},
		{"consensus_negative_time", func(c *config.Config) { c.GeneralSettings.ConsensusConfigsByRound[0].SubroundsTiming[0].StartTime = -1 }, commonConfigs.ErrNegativeSubroundTiming, ""},
		{"consensus_empty_range", func(c *config.Config) {
			p := &c.GeneralSettings.ConsensusConfigsByRound[0].SubroundsTiming[0]
			p.EndTime = p.StartTime
		}, commonConfigs.ErrInvalidSubroundTimingRange, ""},
		{"consensus_gap", func(c *config.Config) {
			c.GeneralSettings.ConsensusConfigsByRound[0].SubroundsTiming[1].StartTime = 0.06
		}, commonConfigs.ErrOverlappingSubroundTiming, ""},
		{"consensus_exceeds_round", func(c *config.Config) { c.GeneralSettings.ConsensusConfigsByRound[0].SubroundsTiming[3].EndTime = 1 }, commonConfigs.ErrSubroundTimingExceedsRound, ""},
		{"consensus_zero_threshold", func(c *config.Config) { c.GeneralSettings.ConsensusConfigsByRound[0].ProcessingThresholdPercent = 0 }, commonConfigs.ErrInvalidProcessingThreshold, ""},
		{"consensus_future_threshold", func(c *config.Config) {
			p := c.GeneralSettings.ConsensusConfigsByRound[0]
			p.EnableRound = 1000
			p.ProcessingThresholdPercent = 101
			c.GeneralSettings.ConsensusConfigsByRound = append(c.GeneralSettings.ConsensusConfigsByRound, p)
		}, commonConfigs.ErrInvalidProcessingThreshold, ""},
		{"process_epoch_missing_base", func(c *config.Config) {
			c.GeneralSettings.ProcessConfigsByEpoch = c.GeneralSettings.ProcessConfigsByEpoch[1:]
		}, commonConfigs.ErrMissingEpochZeroConfig, ""},
		{"process_epoch_duplicate", func(c *config.Config) {
			c.GeneralSettings.ProcessConfigsByEpoch = append(c.GeneralSettings.ProcessConfigsByEpoch, c.GeneralSettings.ProcessConfigsByEpoch[0])
		}, commonConfigs.ErrDuplicatedEpochConfig, ""},
		{"process_round_missing_base", func(c *config.Config) {
			c.GeneralSettings.ProcessConfigsByRound = c.GeneralSettings.ProcessConfigsByRound[1:]
		}, commonConfigs.ErrMissingRoundZeroConfig, ""},
		{"process_round_duplicate", func(c *config.Config) {
			c.GeneralSettings.ProcessConfigsByRound = append(c.GeneralSettings.ProcessConfigsByRound, c.GeneralSettings.ProcessConfigsByRound[0])
		}, commonConfigs.ErrDuplicatedRoundConfig, ""},
		{"process_zero_tx_retention", func(c *config.Config) {
			c.GeneralSettings.ProcessConfigsByRound[0].MaxRoundsToKeepUnprocessedTransactions = 0
		}, process.ErrInvalidValue, ""},
		{"process_zero_mb_retention", func(c *config.Config) {
			c.GeneralSettings.ProcessConfigsByRound[0].MaxRoundsToKeepUnprocessedMiniBlocks = 0
		}, process.ErrInvalidValue, ""},
		{"process_zero_rating_rounds", func(c *config.Config) {
			c.GeneralSettings.ProcessConfigsByRound[0].MaxConsecutiveRoundsOfRatingDecrease = 0
		}, process.ErrZeroMaxConsecutiveRoundsOfRatingDecrease, ""},
		{"process_future_zero_processing", func(c *config.Config) {
			p := c.GeneralSettings.ProcessConfigsByRound[0]
			p.EnableRound = 1000
			p.MaxBlockProcessingTimeMs = 0
			c.GeneralSettings.ProcessConfigsByRound = append(c.GeneralSettings.ProcessConfigsByRound, p)
		}, process.ErrInvalidValue, ""},
		{"process_zero_modulus", func(c *config.Config) {
			c.GeneralSettings.ProcessConfigsByRound[0].RoundModulusTriggerWhenSyncIsStuck = 0
		}, process.ErrInvalidValue, ""},
		{"process_zero_request_delay", func(c *config.Config) { c.GeneralSettings.ProcessConfigsByRound[0].ExtraDelayForRequestBlockInfoMs = 0 }, process.ErrInvalidValue, ""},
		{"process_request_before_broadcast", func(c *config.Config) { c.GeneralSettings.ProcessConfigsByRound[0].ExtraDelayForRequestBlockInfoMs = 1 }, process.ErrInvalidValue, ""},
		{"antiflood_missing_base", func(c *config.Config) { c.Antiflood.ConfigsByRound = c.Antiflood.ConfigsByRound[1:] }, commonConfigs.ErrMissingRoundZeroConfig, ""},
		{"antiflood_duplicate", func(c *config.Config) {
			c.Antiflood.ConfigsByRound = append(c.Antiflood.ConfigsByRound, c.Antiflood.ConfigsByRound[0])
		}, commonConfigs.ErrDuplicatedRoundConfig, ""},
		{"antiflood_future_zero_messages", func(c *config.Config) {
			p := c.Antiflood.ConfigsByRound[0]
			p.Round = 1000
			p.FastReacting.PeerMaxInput.BaseMessagesPerInterval = 0
			c.Antiflood.ConfigsByRound = append(c.Antiflood.ConfigsByRound, p)
		}, process.ErrInvalidValue, ""},
		{"antiflood_negative_factor", func(c *config.Config) {
			c.Antiflood.ConfigsByRound[0].FastReacting.PeerMaxInput.IncreaseFactor.Factor = -1
		}, process.ErrInvalidValue, ""},
		{"antiflood_reserved_too_high", func(c *config.Config) { c.Antiflood.ConfigsByRound[0].SlowReacting.ReservedPercent = 91 }, process.ErrInvalidValue, ""},
		{"antiflood_reserved_negative", func(c *config.Config) { c.Antiflood.ConfigsByRound[0].OutOfSpecs.ReservedPercent = -1 }, process.ErrInvalidValue, ""},
		{"antiflood_zero_ban_duration", func(c *config.Config) {
			c.Antiflood.ConfigsByRound[0].FastReacting.BlackList.PeerBanDurationInSeconds = 0
		}, process.ErrInvalidValue, ""},
		{"antiflood_zero_blacklist_count", func(c *config.Config) {
			c.Antiflood.ConfigsByRound[0].FastReacting.BlackList.ThresholdNumMessagesPerInterval = 0
		}, process.ErrInvalidValue, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths, overlay := qualDRWALoadedFiles(t)
			cfg, err := common.LoadMainConfig(paths.MainConfig)
			require.NoError(t, err)
			tc.mutate(cfg)
			qualDRWAEncodeLoaded(t, paths.MainConfig, cfg)
			candidate, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true})
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
			} else {
				require.ErrorContains(t, err, tc.text)
			}
			require.Nil(t, candidate)
		})
	}
}

func TestQualDRWALoadedStartupKernelNativeControls(t *testing.T) {
	for _, generated := range []bool{false, true} {
		t.Run(fmt.Sprintf("generated_%t", generated), func(t *testing.T) {
			paths, overlay := qualDRWALoadedFiles(t)
			if generated {
				for _, name := range []string{"config.toml", "enableEpochs.toml", "enableRounds.toml", "economics.toml", "ratings.toml", "drwa.toml"} {
					body, err := os.ReadFile(qualDRWACandidateGenesisPath(t, name))
					require.NoError(t, err)
					require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(overlay), name), body, 0600))
				}
			}
			before, err := os.ReadFile(paths.MainConfig)
			require.NoError(t, err)
			candidate, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true})
			require.NoError(t, err)
			require.NoError(t, candidate.CheckEnforcedBlock(3, 440))
			after, err := os.ReadFile(paths.MainConfig)
			require.NoError(t, err)
			require.Equal(t, before, after)
			cfg, err := common.LoadMainConfig(paths.MainConfig)
			require.NoError(t, err)
			gs := cfg.GeneralSettings
			rounds := forking.NewGenericRoundNotifier()
			processConfig, err := commonConfigs.NewProcessConfigsHandler(gs.ProcessConfigsByEpoch, gs.ProcessConfigsByRound, rounds)
			require.NoError(t, err)
			consensus, err := commonConfigs.NewCommonConfigsHandler(gs.EpochStartConfigsByEpoch, gs.EpochStartConfigsByRound, gs.ConsensusConfigsByEpoch, gs.ConsensusConfigsByRound, false)
			require.NoError(t, err)
			antiflood, err := commonConfigs.NewAntifloodConfigsHandler(cfg.Antiflood, rounds)
			require.NoError(t, err)
			grace, err := graceperiod.NewEpochChangeGracePeriod(gs.EpochChangeGracePeriodByEpoch)
			require.NoError(t, err)
			// Literal native template and unchanged candidate03 values: source
			// getters are checked around their actual epoch/round boundaries.
			for _, tc := range []struct{ epoch, want uint32 }{{0, 5}, {1, 10}, {2, 100}, {3, 100}} {
				got, err := grace.GetGracePeriodForEpoch(tc.epoch)
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			}
			require.Equal(t, uint32(25), consensus.GetGracePeriodRoundsByEpoch(1))
			require.Equal(t, uint32(250), consensus.GetGracePeriodRoundsByEpoch(2))
			for _, round := range []uint64{439, 440, 441} {
				rounds.CheckRound(&block.Header{Round: round})
				wantCommitted := uint32(10)
				wantStart := uint32(50)
				wantBoundary := uint64(0)
				if round >= 440 {
					wantCommitted, wantStart, wantBoundary = 100, 500, 440
				}
				require.Equal(t, wantCommitted, processConfig.GetMaxRoundsWithoutCommittedBlock(round))
				require.Equal(t, wantStart, consensus.GetMaxRoundsWithoutCommittedStartInEpochBlockInRound(round))
				require.Equal(t, wantBoundary, consensus.GetActiveTimingBoundaryRound(round))
				require.Equal(t, wantBoundary, antiflood.GetCurrentConfig().Round)
			}
		})
	}
}
