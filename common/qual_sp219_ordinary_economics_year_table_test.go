package common_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
)

// These values are the ordinary year table in the unchanged upstream v2.1.9
// economics template. This fixture checks only ordered TOML representation;
// it does not configure or execute the economics engine.
func TestQualSP219OrdinaryEconomicsYearTable(t *testing.T) {
	t.Parallel()

	const fixture = `
[GlobalSettings]
    YearSettings = [
        {Year = 1, MaximumInflation = 0.10845130},
        {Year = 2, MaximumInflation = 0.09703538},
        {Year = 3, MaximumInflation = 0.08561945},
        {Year = 4, MaximumInflation = 0.07420352},
        {Year = 5, MaximumInflation = 0.06278760},
        {Year = 6, MaximumInflation = 0.05137167},
        {Year = 7, MaximumInflation = 0.03995574},
        {Year = 8, MaximumInflation = 0.02853982},
        {Year = 9, MaximumInflation = 0.01712389},
        {Year = 10, MaximumInflation = 0.00570796},
        {Year = 11, MaximumInflation = 0.0},
    ]
`
	expected := []*config.YearSetting{
		{Year: 1, MaximumInflation: 0.10845130},
		{Year: 2, MaximumInflation: 0.09703538},
		{Year: 3, MaximumInflation: 0.08561945},
		{Year: 4, MaximumInflation: 0.07420352},
		{Year: 5, MaximumInflation: 0.06278760},
		{Year: 6, MaximumInflation: 0.05137167},
		{Year: 7, MaximumInflation: 0.03995574},
		{Year: 8, MaximumInflation: 0.02853982},
		{Year: 9, MaximumInflation: 0.01712389},
		{Year: 10, MaximumInflation: 0.00570796},
		{Year: 11, MaximumInflation: 0.0},
	}

	file := filepath.Join(t.TempDir(), "economics.toml")
	require.NoError(t, os.WriteFile(file, []byte(fixture), 0600))
	cfg, err := common.LoadEconomicsConfig(file)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, expected, cfg.GlobalSettings.YearSettings)
}
