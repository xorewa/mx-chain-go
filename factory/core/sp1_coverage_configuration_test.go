package core

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSP1CoverageConfigurationLoadFailures(t *testing.T) {
	for _, which := range []string{"epoch", "round", "economics", "ratings"} {
		t.Run(which, func(t *testing.T) {
			paths, overlay := qualDRWALoadedFiles(t)
			missing := filepath.Join(t.TempDir(), "absent-native-config.toml")
			switch which {
			case "epoch":
				paths.Epoch = missing
			case "round":
				paths.RoundActivation = missing
			case "economics":
				paths.Economics = missing
			case "ratings":
				paths.Ratings = missing
			}
			candidate, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true, RegisterMetaESDTPath: true})
			require.Error(t, err)
			require.Nil(t, candidate)
		})
	}
	var absent *DRWAConfigurationCandidate
	epochs, rounds := absent.ActivationInventory()
	require.Nil(t, epochs)
	require.Nil(t, rounds)
}
