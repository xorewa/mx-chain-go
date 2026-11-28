package common_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

// These are detached parser fixtures, not selected programme configuration.
// Preserve the integer denomination and decimal supply as separate report inputs.
func TestQualSP219OrdinaryEconomicsReportFields(t *testing.T) {
	t.Parallel()

	const fixture = `
[GlobalSettings]
    Denomination = 8
    GenesisTotalSupply = "123456789012345678901234567890"
`
	file := filepath.Join(t.TempDir(), "economics.toml")
	require.NoError(t, os.WriteFile(file, []byte(fixture), 0600))

	cfg, err := common.LoadEconomicsConfig(file)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, 8, cfg.GlobalSettings.Denomination)
	require.Equal(t, "123456789012345678901234567890", cfg.GlobalSettings.GenesisTotalSupply)
}

// The ordinary ratings presentation consumes distinct minimum and maximum
// numeric fields. This checks only their representation in the real loader.
func TestQualSP219OrdinaryRatingsReportFields(t *testing.T) {
	t.Parallel()

	const fixture = `
[General]
    MinRating = 7
    StartRating = 41
    MaxRating = 129
`
	file := filepath.Join(t.TempDir(), "ratings.toml")
	require.NoError(t, os.WriteFile(file, []byte(fixture), 0600))

	cfg, err := common.LoadRatingsConfig(file)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, uint32(7), cfg.General.MinRating)
	require.Equal(t, uint32(41), cfg.General.StartRating)
	require.Equal(t, uint32(129), cfg.General.MaxRating)
}
