package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/config/overridableConfig"
	logger "github.com/multiversx/mx-chain-logger-go"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

// Verify that the CLI orchestration preserves the ordinary configuration error.
// The fixture is deliberately limited to local configuration parsing; the
// preflight verifies the exact stopping error before invoking the orchestration.
func TestQualSP281COrdinaryStartupOverrideError(t *testing.T) {
	dir := t.TempDir()
	const prefs = `[Preferences]
OverridableConfigTomlValues = [
  { File = "display-settings.toml", Path = "DisplayName", Value = "sample label" },
]
`
	flags := []struct {
		flag cli.StringFlag
		body string
	}{
		{configurationFile, ""},
		{configurationApiFile, ""},
		{configurationEconomicsFile, ""},
		{configurationSystemSCFile, ""},
		{configurationRatingsFile, ""},
		{configurationPreferencesFile, prefs},
		{externalConfigFile, ""},
		{p2pConfigurationFile, ""},
		{fullArchiveP2PConfigurationFile, ""},
		{epochConfigurationFile, ""},
		{roundConfigurationFile, ""},
		{nodesFile, "{}"},
	}

	app := cli.NewApp()
	app.Flags = getFlags()
	args := []string{"ordinary-config", "--" + workingDirectory.Name, dir}
	for _, entry := range flags {
		path := filepath.Join(dir, entry.flag.Name)
		require.NoError(t, os.WriteFile(path, []byte(entry.body), 0600))
		args = append(args, "--"+entry.flag.Name, path)
	}

	log := logger.GetOrCreate("qual-ordinary-config")
	const expectedPrefix = "invalid config file <display-settings.toml>."
	app.Action = func(ctx *cli.Context) error {
		cfgs, err := readConfigs(ctx, log)
		require.NoError(t, err)
		require.Len(t, cfgs.PreferencesConfig.Preferences.OverridableConfigTomlValues, 1)
		// Establish the stopping condition without constructing a NodeRunner.
		expected := overridableConfig.OverrideConfigValues(cfgs.PreferencesConfig.Preferences.OverridableConfigTomlValues, cfgs)
		require.ErrorContains(t, expected, expectedPrefix)
		got := startNodeRunner(ctx, log, "ordinary-base", "ordinary-version")
		require.EqualError(t, got, expected.Error())
		return got
	}
	require.ErrorContains(t, app.Run(args), expectedPrefix)
}
