package core

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAPinnedManagedOverlay(t *testing.T) {
	paths, overlay := qualDRWALoadedFiles(t)
	main, err := common.LoadMainConfig(paths.MainConfig)
	require.NoError(t, err)
	epoch, err := common.LoadEpochConfig(paths.Epoch)
	require.NoError(t, err)
	round, err := common.LoadRoundConfig(paths.RoundActivation)
	require.NoError(t, err)
	economics, err := common.LoadEconomicsConfig(paths.Economics)
	require.NoError(t, err)
	ratings, err := common.LoadRatingsConfig(paths.Ratings)
	require.NoError(t, err)
	effective := &config.Configs{GeneralConfig: main, EpochConfig: epoch,
		RoundConfig: round, EconomicsConfig: economics, RatingsConfig: ratings}
	support := DRWAConfigurationSupport{ProcessorV1: true, RelayedV3: true}
	raw, err := os.ReadFile(overlay)
	require.NoError(t, err)
	pin := sha256.Sum256(raw)
	bound := int64(len(raw))

	candidate, err := NewDRWAConfigurationCandidateFromPinnedOverlay(effective, overlay, pin, bound, support)
	require.NoError(t, err)
	require.True(t, candidate.MatchesPinnedOverlay(overlay, pin))
	require.NoError(t, candidate.CheckEnforcedBlock(3, 440))

	_, err = NewDRWAConfigurationCandidateFromPinnedOverlay(effective, overlay, pin, bound-1, support)
	require.Error(t, err)
	link := filepath.Join(filepath.Dir(overlay), "alias.toml")
	require.NoError(t, os.Symlink(overlay, link))
	_, err = NewDRWAConfigurationCandidateFromPinnedOverlay(effective, link, pin, bound, support)
	require.Error(t, err)
	require.False(t, candidate.MatchesPinnedOverlay(link, pin))

	replacement := []byte("DRWAEnforcementEnableEpoch = 4\n")
	require.NoError(t, os.WriteFile(overlay, replacement, 0600))
	_, err = NewDRWAConfigurationCandidateFromPinnedOverlay(effective, overlay, pin, bound, support)
	require.Error(t, err)
	require.False(t, candidate.MatchesPinnedOverlay(overlay, sha256.Sum256(replacement)))
	require.NoError(t, candidate.CheckEnforcedBlock(3, 440))

	for _, text := range []string{
		"DRWAEnforcementEnableEpoch = 3\nDRWAEnforcementEnableEpoch = 3\n",
		"DRWAEnforcementEnableEpoch = 3\nUnselected = true\n",
		"",
	} {
		rejected := []byte(text)
		require.NoError(t, os.WriteFile(overlay, rejected, 0600))
		_, err = NewDRWAConfigurationCandidateFromPinnedOverlay(effective, overlay, sha256.Sum256(rejected), int64(len(rejected))+1, support)
		require.Error(t, err)
	}
}
