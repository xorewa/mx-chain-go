package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/config/overridableConfig"
	nodeErrors "github.com/multiversx/mx-chain-go/errors"
	"github.com/stretchr/testify/require"
)

// T09-M41: reuse the hash-bound in-repository public candidate fixture. These
// five actual native objects are the consumed validation subset, not the whole
// node startup, admitted profile or evidence that CLI overrides have finished.
func qualDRWAEffectiveConfigs(t *testing.T) (*config.Configs, config.ConfigurationPathsHolder, string) {
	t.Helper()
	dir := qualDRWACandidateFixtureDir(t)
	paths := config.ConfigurationPathsHolder{MainConfig: filepath.Join(dir, "config.toml"),
		Epoch: filepath.Join(dir, "enableEpochs.toml"), RoundActivation: filepath.Join(dir, "enableRounds.toml"),
		Economics: filepath.Join(dir, "economics.toml"), Ratings: filepath.Join(dir, "ratings.toml")}
	cfgs := &config.Configs{}
	var err error
	cfgs.GeneralConfig, err = common.LoadMainConfig(paths.MainConfig)
	require.NoError(t, err)
	cfgs.EpochConfig, err = common.LoadEpochConfig(paths.Epoch)
	require.NoError(t, err)
	cfgs.RoundConfig, err = common.LoadRoundConfig(paths.RoundActivation)
	require.NoError(t, err)
	cfgs.EconomicsConfig, err = common.LoadEconomicsConfig(paths.Economics)
	require.NoError(t, err)
	cfgs.RatingsConfig, err = common.LoadRatingsConfig(paths.Ratings)
	require.NoError(t, err)
	return cfgs, paths, filepath.Join(dir, "drwa.toml")
}

// The file snapshot and a later overridden native configuration are distinct.
// A passing file-loader candidate supplies no acceptance of the latter.
func TestQualDRWAEffectiveConfigurationFileWitness(t *testing.T) {
	cfgs, paths, overlay := qualDRWAEffectiveConfigs(t)
	fileCandidate, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true})
	require.NoError(t, err)
	require.NoError(t, fileCandidate.CheckEnforcedBlock(3, 440))
	require.NoError(t, overridableConfig.OverrideConfigValues([]config.OverridableConfig{
		{File: "enableEpochs.toml", Path: "EnableEpochs.GlobalMintBurnDisableEpoch", Value: uint32(4)},
	}, cfgs))
	require.Equal(t, uint32(4), cfgs.EpochConfig.EnableEpochs.GlobalMintBurnDisableEpoch)
	native, err := enablers.NewEnableEpochsHandler(cfgs.EpochConfig.EnableEpochs, forking.NewGenericEpochNotifier())
	require.NoError(t, err)
	require.True(t, native.IsFlagEnabledInEpoch(common.GlobalMintBurnFlag, 3))
	require.False(t, fileCandidate.epochs.IsFlagEnabledInEpoch(common.GlobalMintBurnFlag, 3))
}

func TestQualDRWAEffectiveConfigurationMatchesLoaded(t *testing.T) {
	cfgs, paths, overlay := qualDRWAEffectiveConfigs(t)
	before, err := json.Marshal(cfgs)
	require.NoError(t, err)
	loaded, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true})
	require.NoError(t, err)
	effective, err := NewDRWAConfigurationCandidate(cfgs, 3, DRWAConfigurationSupport{RelayedV3: true})
	require.NoError(t, err)
	le, lr := loaded.ActivationInventory()
	ee, er := effective.ActivationInventory()
	require.Equal(t, le, ee)
	require.Equal(t, lr, er)
	for _, point := range []struct {
		epoch uint32
		round uint64
	}{{1, 439}, {1, 440}, {2, 439}, {2, 440}, {3, 439}, {3, 440}, {4, 441}} {
		require.Equal(t, loaded.Enabled(point.epoch, point.round), effective.Enabled(point.epoch, point.round))
	}
	after, err := json.Marshal(cfgs)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestQualDRWAEffectiveConfigurationOverridePrerequisites(t *testing.T) {
	for _, field := range []string{"GlobalMintBurnDisableEpoch", "ESDTEnableEpoch"} {
		t.Run(field, func(t *testing.T) {
			cfgs, paths, _ := qualDRWAEffectiveConfigs(t)
			fileBefore, err := os.ReadFile(paths.Epoch)
			require.NoError(t, err)
			require.NoError(t, overridableConfig.OverrideConfigValues([]config.OverridableConfig{
				{File: "enableEpochs.toml", Path: "EnableEpochs." + field, Value: uint32(4)},
			}, cfgs))
			native, err := enablers.NewEnableEpochsHandler(cfgs.EpochConfig.EnableEpochs, forking.NewGenericEpochNotifier())
			require.NoError(t, err)
			if field == "GlobalMintBurnDisableEpoch" {
				require.True(t, native.IsFlagEnabledInEpoch(common.GlobalMintBurnFlag, 3))
			} else {
				require.False(t, native.IsFlagEnabledInEpoch(common.ESDTFlag, 3))
			}
			candidate, err := NewDRWAConfigurationCandidate(cfgs, 3, DRWAConfigurationSupport{RelayedV3: true})
			flag := common.ESDTFlag
			if field == "GlobalMintBurnDisableEpoch" {
				flag = common.GlobalMintBurnFlag
			}
			require.ErrorContains(t, err, string(flag))
			require.Nil(t, candidate)
			fileAfter, err := os.ReadFile(paths.Epoch)
			require.NoError(t, err)
			require.Equal(t, fileBefore, fileAfter)
		})
	}
}

func TestQualDRWAEffectiveConfigurationRoundOverride(t *testing.T) {
	cfgs, _, _ := qualDRWAEffectiveConfigs(t)
	activations := make(map[string]config.ActivationRoundByName)
	for name, value := range cfgs.RoundConfig.RoundActivations {
		activations[name] = value
	}
	changed := activations[string(common.SupernovaRoundFlag)]
	changed.Round = "441"
	activations[string(common.SupernovaRoundFlag)] = changed
	require.NoError(t, overridableConfig.OverrideConfigValues([]config.OverridableConfig{
		{File: "enableRounds.toml", Path: "RoundActivations", Value: activations},
	}, cfgs))
	require.Equal(t, "441", cfgs.RoundConfig.RoundActivations[string(common.SupernovaRoundFlag)].Round)
	candidate, err := NewDRWAConfigurationCandidate(cfgs, 3, DRWAConfigurationSupport{RelayedV3: true})
	require.ErrorIs(t, err, nodeErrors.ErrSupernovaActivationConfigMismatch)
	require.Nil(t, candidate)
}

func TestQualDRWAEffectiveConfigurationEmptyChainOverride(t *testing.T) {
	cfgs, _, _ := qualDRWAEffectiveConfigs(t)
	require.NoError(t, overridableConfig.OverrideConfigValues([]config.OverridableConfig{
		{File: "config.toml", Path: "GeneralSettings.ChainParametersByEpoch", Value: []config.ChainParametersByEpochConfig{}},
	}, cfgs))
	require.Empty(t, cfgs.GeneralConfig.GeneralSettings.ChainParametersByEpoch)
	candidate, err := NewDRWAConfigurationCandidate(cfgs, 3, DRWAConfigurationSupport{RelayedV3: true})
	require.ErrorIs(t, err, nodeErrors.ErrSupernovaActivationConfigMismatch)
	require.Nil(t, candidate)
}

func TestQualDRWAEffectiveConfigurationMissingInputs(t *testing.T) {
	for _, missing := range []string{"configs", "main", "epochs", "rounds", "economics", "ratings"} {
		t.Run(missing, func(t *testing.T) {
			cfgs, _, _ := qualDRWAEffectiveConfigs(t)
			switch missing {
			case "configs":
				cfgs = nil
			case "main":
				cfgs.GeneralConfig = nil
			case "epochs":
				cfgs.EpochConfig = nil
			case "rounds":
				cfgs.RoundConfig = nil
			case "economics":
				cfgs.EconomicsConfig = nil
			case "ratings":
				cfgs.RatingsConfig = nil
			}
			candidate, err := NewDRWAConfigurationCandidate(cfgs, 3, DRWAConfigurationSupport{RelayedV3: true})
			require.EqualError(t, err, "missing DRWA effective configuration inputs")
			require.Nil(t, candidate)
		})
	}
}

func TestQualDRWAEffectiveConfigurationPreservesVersionOrder(t *testing.T) {
	cfgs, _, _ := qualDRWAEffectiveConfigs(t)
	versions := cfgs.GeneralConfig.Versions.VersionsByEpochs
	require.GreaterOrEqual(t, len(versions), 2)
	versions[0], versions[len(versions)-1] = versions[len(versions)-1], versions[0]
	before, err := json.Marshal(cfgs)
	require.NoError(t, err)
	candidate, err := NewDRWAConfigurationCandidate(cfgs, 3, DRWAConfigurationSupport{RelayedV3: true})
	require.NoError(t, err)
	require.NoError(t, candidate.CheckEnforcedBlock(3, 440))
	after, err := json.Marshal(cfgs)
	require.NoError(t, err)
	require.Equal(t, before, after, "native sort must act on the private validation slice")
}

func TestQualDRWAEffectiveConfigurationSnapshot(t *testing.T) {
	cfgs, _, _ := qualDRWAEffectiveConfigs(t)
	candidate, err := NewDRWAConfigurationCandidate(cfgs, 3, DRWAConfigurationSupport{RelayedV3: true})
	require.NoError(t, err)
	cfgs.EpochConfig.EnableEpochs.GlobalMintBurnDisableEpoch = 4
	require.NoError(t, candidate.CheckEnforcedBlock(3, 440), "earlier validation snapshot, not approval of modified objects")
	changed, err := NewDRWAConfigurationCandidate(cfgs, 3, DRWAConfigurationSupport{RelayedV3: true})
	require.ErrorContains(t, err, string(common.GlobalMintBurnFlag))
	require.Nil(t, changed)
}

func TestQualDRWAEffectiveConfigurationPreferencesOverride(t *testing.T) {
	cfgs, _, _ := qualDRWAEffectiveConfigs(t)
	path := filepath.Join(t.TempDir(), "prefs.toml")
	require.NoError(t, os.WriteFile(path, []byte("[Preferences]\nOverridableConfigTomlValues = [{ File = 'enableEpochs.toml', Path = 'EnableEpochs.GlobalMintBurnDisableEpoch', Value = 4 }]\n"), 0600))
	prefs, err := common.LoadPreferencesConfig(path)
	require.NoError(t, err)
	require.Len(t, prefs.Preferences.OverridableConfigTomlValues, 1)
	require.NoError(t, overridableConfig.OverrideConfigValues(prefs.Preferences.OverridableConfigTomlValues, cfgs))
	require.Equal(t, uint32(4), cfgs.EpochConfig.EnableEpochs.GlobalMintBurnDisableEpoch)
	candidate, err := NewDRWAConfigurationCandidate(cfgs, 3, DRWAConfigurationSupport{RelayedV3: true})
	require.ErrorContains(t, err, string(common.GlobalMintBurnFlag))
	require.Nil(t, candidate)
}

func TestQualDRWAEffectiveConfigurationCompatibleOverride(t *testing.T) {
	cfgs, _, _ := qualDRWAEffectiveConfigs(t)
	require.NoError(t, overridableConfig.OverrideConfigValues([]config.OverridableConfig{
		{File: "enableEpochs.toml", Path: "EnableEpochs.ESDTEnableEpoch", Value: uint32(0)},
	}, cfgs))
	before, err := json.Marshal(cfgs)
	require.NoError(t, err)
	candidate, err := NewDRWAConfigurationCandidate(cfgs, 3, DRWAConfigurationSupport{RelayedV3: true})
	require.NoError(t, err)
	require.NoError(t, candidate.CheckEnforcedBlock(3, 440))
	epochs, _ := candidate.ActivationInventory()
	require.Equal(t, uint32(0), epochs["ESDTEnableEpoch"])
	after, err := json.Marshal(cfgs)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

// T09-M42: native loader checks must also cover the final overridden objects.
func TestQualDRWAEffectiveConfigurationInvalidIntervals(t *testing.T) {
	for _, tc := range []struct {
		name      string
		intervals []config.HardforkRoundExclusionConfig
		want      error
	}{
		{"descending", []config.HardforkRoundExclusionConfig{{StartRound: 20, EndRound: 10}}, common.ErrInvalidHardforkRoundExclusion},
		{"overlapping", []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 20}, {StartRound: 20, EndRound: 30}}, common.ErrOverlappingHardforkRoundExclusions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfgs, _, _ := qualDRWAEffectiveConfigs(t)
			require.NoError(t, overridableConfig.OverrideConfigValues([]config.OverridableConfig{
				{File: "config.toml", Path: "HardforkRoundExclusions", Value: tc.intervals},
			}, cfgs))
			before, err := json.Marshal(cfgs)
			require.NoError(t, err)
			_, nativeErr := common.NewConfiguredRoundExclusionHandler(cfgs.GeneralConfig)
			require.ErrorIs(t, nativeErr, tc.want)
			candidate, err := NewDRWAConfigurationCandidate(cfgs, 3, DRWAConfigurationSupport{RelayedV3: true})
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, candidate)
			after, err := json.Marshal(cfgs)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestQualDRWAEffectiveConfigurationInvalidCheckpoint(t *testing.T) {
	for _, round := range []uint64{0, 10} {
		t.Run(fmt.Sprint(round), func(t *testing.T) {
			cfgs, _, _ := qualDRWAEffectiveConfigs(t)
			cfgs.GeneralConfig.HardforkRecoveryCheckpoint.Enabled = true
			cfgs.GeneralConfig.HardforkRecoveryCheckpoint.Round = round
			cfgs.GeneralConfig.HardforkRoundExclusions = nil
			before, err := json.Marshal(cfgs)
			require.NoError(t, err)
			_, nativeErr := common.NewConfiguredRoundExclusionHandler(cfgs.GeneralConfig)
			require.ErrorIs(t, nativeErr, common.ErrInvalidRecoveryCheckpoint)
			candidate, err := NewDRWAConfigurationCandidate(cfgs, 3, DRWAConfigurationSupport{RelayedV3: true})
			require.ErrorIs(t, err, common.ErrInvalidRecoveryCheckpoint)
			require.Nil(t, candidate)
			after, err := json.Marshal(cfgs)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestQualDRWAEffectiveConfigurationValidIntervals(t *testing.T) {
	cfgs, _, _ := qualDRWAEffectiveConfigs(t)
	// Shape-only diagnostic inputs; no authentic history or recovery approval.
	cfgs.GeneralConfig.HardforkRoundExclusions = []config.HardforkRoundExclusionConfig{
		{StartRound: 30, EndRound: 40}, {StartRound: 10, EndRound: 20},
	}
	cfgs.GeneralConfig.HardforkRecoveryCheckpoint.Enabled = false
	before, err := json.Marshal(cfgs)
	require.NoError(t, err)
	native, err := common.NewConfiguredRoundExclusionHandler(cfgs.GeneralConfig)
	require.NoError(t, err)
	require.True(t, native.IsRoundExcluded(15))
	require.False(t, native.IsRoundExcluded(25))
	candidate, err := NewDRWAConfigurationCandidate(cfgs, 3, DRWAConfigurationSupport{RelayedV3: true})
	require.NoError(t, err)
	require.NoError(t, candidate.CheckEnforcedBlock(3, 440))
	after, err := json.Marshal(cfgs)
	require.NoError(t, err)
	require.Equal(t, before, after)
}
