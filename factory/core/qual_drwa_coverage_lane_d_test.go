package core

import (
	"crypto/sha256"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
)

func TestQualLaneDPinnedStartupInput(t *testing.T) {
	dir := t.TempDir()
	value := []byte("public startup fixture\n")
	path := filepath.Join(dir, "input")
	link := filepath.Join(dir, "alias")
	require.NoError(t, os.WriteFile(path, value, 0600))
	require.NoError(t, os.Symlink(path, link))
	pin := sha256.Sum256(value)
	size := int64(len(value))

	got, err := ReadDRWAPinnedStartupInput(path, pin, size)
	require.NoError(t, err)
	require.Equal(t, value, got)

	for _, tc := range []struct {
		name string
		path string
		pin  [32]byte
		max  int64
	}{
		{"absent-pin", path, [32]byte{}, size},
		{"different-pin", path, sha256.Sum256([]byte("other fixture")), size},
		{"zero-bound", path, pin, 0},
		{"overflow-bound", path, pin, math.MaxInt64},
		{"too-short", path, pin, size - 1},
		{"relative", "input", pin, size},
		{"unclean", dir + "/./input", pin, size},
		{"missing", filepath.Join(dir, "absent"), pin, size},
		{"alias", link, pin, size},
		{"directory", dir, pin, size},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadDRWAPinnedStartupInput(tc.path, tc.pin, tc.max)
			require.Error(t, err)
			require.Nil(t, got)
		})
	}
	t.Run("unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("file permission check requires an unprivileged user")
		}
		unreadable := filepath.Join(dir, "unreadable")
		require.NoError(t, os.WriteFile(unreadable, value, 0000))
		got, err := ReadDRWAPinnedStartupInput(unreadable, pin, size)
		require.ErrorIs(t, err, os.ErrPermission)
		require.Nil(t, got)
	})
}

func TestQualLaneDPinnedConfigurationOverlay(t *testing.T) {
	paths, overlay := qualDRWALoadedFiles(t)
	main, err := common.LoadMainConfig(paths.MainConfig)
	require.NoError(t, err)
	epochs, err := common.LoadEpochConfig(paths.Epoch)
	require.NoError(t, err)
	rounds, err := common.LoadRoundConfig(paths.RoundActivation)
	require.NoError(t, err)
	economics, err := common.LoadEconomicsConfig(paths.Economics)
	require.NoError(t, err)
	ratings, err := common.LoadRatingsConfig(paths.Ratings)
	require.NoError(t, err)
	cfg := &config.Configs{GeneralConfig: main, EpochConfig: epochs, RoundConfig: rounds, EconomicsConfig: economics, RatingsConfig: ratings}
	support := DRWAConfigurationSupport{RelayedV3: true, RegisterMetaESDTPath: true}
	value := []byte("DRWAEnforcementEnableEpoch = 3\n")
	pin := sha256.Sum256(value)
	exactSize := int64(len(value))

	candidate, err := NewDRWAConfigurationCandidateFromPinnedOverlay(cfg, overlay, pin, exactSize, support)
	require.NoError(t, err)
	require.True(t, candidate.MatchesPinnedOverlay(overlay, pin))
	require.False(t, candidate.MatchesPinnedOverlay(overlay, [32]byte{}))
	require.NoError(t, candidate.CheckEnforcedBlock(3, 440))

	for _, tc := range []struct {
		name string
		cfg  *config.Configs
		body string
		pin  [32]byte
		max  int64
	}{
		{"missing-pin", cfg, string(value), [32]byte{}, exactSize},
		{"changed-bytes", cfg, "DRWAEnforcementEnableEpoch = 9\n", pin, exactSize},
		{"other-field", cfg, "DRWAEnforcementEnableEpoch = 3\nExtra = true\n", [32]byte{}, -1},
		{"absent-epoch", cfg, "# empty overlay\n", [32]byte{}, -1},
		{"native-config-missing", nil, string(value), pin, exactSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(tc.body)
			require.NoError(t, os.WriteFile(overlay, raw, 0600))
			pin, bound := tc.pin, tc.max
			if bound == -1 {
				pin, bound = sha256.Sum256(raw), int64(len(raw))
			}
			got, err := NewDRWAConfigurationCandidateFromPinnedOverlay(tc.cfg, overlay, pin, bound, support)
			require.Error(t, err)
			require.Nil(t, got)
		})
	}
}
