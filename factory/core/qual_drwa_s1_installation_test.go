package core

import (
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestQualS1OverlayIsExplicitCoordinateSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "drwa.toml")
	for _, tc := range []struct {
		value   string
		want    uint32
		missing bool
	}{{"", 0, true}, {"DRWAEnforcementEnableEpoch = 0\n", 0, false}, {"DRWAEnforcementEnableEpoch = 3\n", 3, false}} {
		require.NoError(t, os.WriteFile(path, []byte(tc.value), 0600))
		epoch, err := loadDRWAEnforcementEpoch(path)
		if tc.missing {
			require.ErrorContains(t, err, "missing DRWAEnforcementEnableEpoch")
		} else {
			require.NoError(t, err)
			require.Equal(t, tc.want, epoch)
		}
	}
	require.NoError(t, os.WriteFile(path, []byte("DRWAEnforcementEnableEpoch = ["), 0600))
	_, err := NewDRWAConfigurationCandidateFromOverlay(nil, path, DRWAConfigurationSupport{})
	require.Error(t, err)
	_, err = NewDRWAConfigurationCandidateFromOverlay(nil, filepath.Join(t.TempDir(), "missing.toml"), DRWAConfigurationSupport{})
	require.Error(t, err)
	require.NoError(t, os.WriteFile(path, []byte("DRWAEnforcementEnableEpoch = 3\n"), 0600))
	_, err = NewDRWAConfigurationCandidateFromOverlay(nil, path, DRWAConfigurationSupport{})
	require.ErrorContains(t, err, "missing DRWA effective configuration inputs")
}

func TestQualS1OverlayUsesFinalEffectivePrerequisites(t *testing.T) {
	for _, mutation := range []string{"none", "mint-burn", "multi-transfer"} {
		t.Run(mutation, func(t *testing.T) {
			configs, _, overlay := qualDRWAEffectiveConfigs(t)
			switch mutation {
			case "mint-burn":
				configs.EpochConfig.EnableEpochs.GlobalMintBurnDisableEpoch = 4
			case "multi-transfer":
				configs.EpochConfig.EnableEpochs.ESDTMultiTransferEnableEpoch = 4
			}
			candidate, err := NewDRWAConfigurationCandidateFromOverlay(configs, overlay, DRWAConfigurationSupport{ProcessorV1: true, RelayedV3: true})
			if mutation != "none" {
				require.Error(t, err)
				require.Nil(t, candidate)
				return
			}
			require.NoError(t, err)
			require.False(t, candidate.Enabled(3, 439))
			require.True(t, candidate.Enabled(3, 440))
			require.NoError(t, candidate.CheckEnforcedBlock(3, 440))
			// Changing the old source after construction grants no changed coordinate.
			require.NoError(t, os.WriteFile(overlay, []byte("DRWAEnforcementEnableEpoch = 99\n"), 0600))
			require.True(t, candidate.Enabled(3, 440))
			epochs, rounds := candidate.ActivationInventory()
			require.Equal(t, uint32(2), epochs["SupernovaEnableEpoch"])
			require.Equal(t, uint64(440), rounds["SupernovaEnableRound"])
			require.False(t, candidate.epochs.IsFlagEnabledInEpoch(common.GlobalMintBurnFlag, 3))
		})
	}
}

// Each effective native input remains mandatory; the overlay never supplies it.
func TestQualS1OverlayDoesNotReloadNativeObjects(t *testing.T) {
	configs, _, overlay := qualDRWAEffectiveConfigs(t)
	for _, drop := range []func(*config.Configs){func(c *config.Configs) { c.GeneralConfig = nil }, func(c *config.Configs) { c.EpochConfig = nil }, func(c *config.Configs) { c.RoundConfig = nil }, func(c *config.Configs) { c.EconomicsConfig = nil }, func(c *config.Configs) { c.RatingsConfig = nil }} {
		copy := *configs
		drop(&copy)
		candidate, err := NewDRWAConfigurationCandidateFromOverlay(&copy, overlay, DRWAConfigurationSupport{})
		require.ErrorContains(t, err, "missing DRWA effective configuration inputs")
		require.Nil(t, candidate)
	}
}
