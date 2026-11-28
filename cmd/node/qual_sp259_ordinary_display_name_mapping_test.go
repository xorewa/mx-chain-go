package main

import (
	"os"
	"path/filepath"
	"testing"

	logger "github.com/multiversx/mx-chain-logger-go"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

// Exercise only local configuration parsing, not runner construction or startup.
func TestQualSP259OrdinaryDisplayNameMapping(t *testing.T) {
	dir := t.TempDir()
	const configured = "Café — configured"
	const selected = "Mønte 🌿 display"
	const preferences = "[Preferences]\nNodeDisplayName = \"" + configured + "\"\n"
	fixtures := []struct {
		flag cli.StringFlag
		body string
	}{
		{configurationFile, ""},
		{configurationApiFile, ""},
		{configurationEconomicsFile, ""},
		{configurationSystemSCFile, ""},
		{configurationRatingsFile, ""},
		{configurationPreferencesFile, preferences},
		{externalConfigFile, ""},
		{p2pConfigurationFile, ""},
		{fullArchiveP2PConfigurationFile, ""},
		{epochConfigurationFile, ""},
		{roundConfigurationFile, ""},
		{nodesFile, "{}"},
	}
	baseArgs := []string{"ordinary-display"}
	for _, fixture := range fixtures {
		path := filepath.Join(dir, fixture.flag.Name)
		require.NoError(t, os.WriteFile(path, []byte(fixture.body), 0600))
		baseArgs = append(baseArgs, "--"+fixture.flag.Name, path)
	}

	for _, tc := range []struct {
		name  string
		extra []string
		want  string
	}{
		{"configured_default", nil, configured},
		{"explicit_display_override", []string{"--display-name", selected}, selected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := cli.NewApp()
			app.Flags = getFlags()
			invoked := false
			app.Action = func(ctx *cli.Context) error {
				invoked = true
				cfgs, err := readConfigs(ctx, logger.GetOrCreate("qual-ordinary-display"))
				require.NoError(t, err)
				require.NotNil(t, cfgs)
				require.Equal(t, tc.want, cfgs.PreferencesConfig.Preferences.NodeDisplayName)
				return nil
			}
			args := append(append([]string(nil), baseArgs...), tc.extra...)
			require.NoError(t, app.Run(args))
			require.True(t, invoked)
			data, err := os.ReadFile(filepath.Join(dir, configurationPreferencesFile.Name))
			require.NoError(t, err)
			require.Equal(t, preferences, string(data))
		})
	}
}
