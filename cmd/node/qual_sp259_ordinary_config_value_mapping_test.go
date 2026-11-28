package main

import (
	"os"
	"path/filepath"
	"testing"

	logger "github.com/multiversx/mx-chain-logger-go"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

// This test only parses local configuration into ordinary data fields. It
// neither starts a runner nor opens a listener, selects a shard, or collects state.
func TestQualSP259OrdinaryConfigValueMapping(t *testing.T) {
	dir := t.TempDir()
	const mainTOML = "[StateAccessesCollectorConfig]\nTypesToCollect = [\"READ\"]\n"
	const prefsTOML = "[Preferences]\nDestinationShardAsObserver = \"0\"\nIdentity = \"display-sample-alpha\"\n"
	const mainP2PTOML = "[Node]\nPort = \"16000\"\n"
	const archiveP2PTOML = "[Node]\nPort = \"17000-17009\"\n"
	fixtures := []struct {
		flag cli.StringFlag
		body string
	}{
		{configurationFile, mainTOML},
		{configurationApiFile, ""},
		{configurationEconomicsFile, ""},
		{configurationSystemSCFile, ""},
		{configurationRatingsFile, ""},
		{configurationPreferencesFile, prefsTOML},
		{externalConfigFile, ""},
		{p2pConfigurationFile, mainP2PTOML},
		{fullArchiveP2PConfigurationFile, archiveP2PTOML},
		{epochConfigurationFile, ""},
		{roundConfigurationFile, ""},
		{nodesFile, "{}"},
	}
	args := []string{"ordinary-config-values"}
	for _, fixture := range fixtures {
		path := filepath.Join(dir, fixture.flag.Name)
		require.NoError(t, os.WriteFile(path, []byte(fixture.body), 0600))
		args = append(args, "--"+fixture.flag.Name, path)
	}

	type mappedValues struct {
		mainPort, archivePort, observerShard, displayIdentity string
		collectorTypes                                        []string
	}
	cases := []struct {
		name  string
		extra []string
		want  mappedValues
	}{
		{"configured_defaults", nil, mappedValues{"16000", "17000-17009", "0", "display-sample-alpha", []string{"READ"}}},
		{"main_port_string", []string{"--port", "18000-18009"}, mappedValues{"18000-18009", "17000-17009", "0", "display-sample-alpha", []string{"READ"}}},
		{"archive_port_string", []string{"--full-archive-port", "19000"}, mappedValues{"16000", "19000", "0", "display-sample-alpha", []string{"READ"}}},
		{"observer_shard_label", []string{"--destination-shard-as-observer", "1"}, mappedValues{"16000", "17000-17009", "1", "display-sample-alpha", []string{"READ"}}},
		{"monitoring_identity_label", []string{"--keybase-identity", "display-sample-beta"}, mappedValues{"16000", "17000-17009", "0", "display-sample-beta", []string{"READ"}}},
		{"collector_type_list", []string{"--state-accesses-types-to-collect", "WRITE", "--state-accesses-types-to-collect", "READ"}, mappedValues{"16000", "17000-17009", "0", "display-sample-alpha", []string{"WRITE", "READ"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := cli.NewApp()
			app.Flags = getFlags()
			invoked := false
			app.Action = func(ctx *cli.Context) error {
				invoked = true
				cfg, err := readConfigs(ctx, logger.GetOrCreate("qual-ordinary-config-values"))
				require.NoError(t, err)
				require.NotNil(t, cfg)
				got := mappedValues{
					mainPort:        cfg.MainP2pConfig.Node.Port,
					archivePort:     cfg.FullArchiveP2pConfig.Node.Port,
					observerShard:   cfg.PreferencesConfig.Preferences.DestinationShardAsObserver,
					displayIdentity: cfg.PreferencesConfig.Preferences.Identity,
					collectorTypes:  cfg.GeneralConfig.StateAccessesCollectorConfig.TypesToCollect,
				}
				require.Equal(t, tc.want, got)
				return nil
			}
			require.NoError(t, app.Run(append(append([]string(nil), args...), tc.extra...)))
			require.True(t, invoked)
			for _, fixture := range fixtures {
				data, err := os.ReadFile(filepath.Join(dir, fixture.flag.Name))
				require.NoError(t, err)
				require.Equal(t, fixture.body, string(data))
			}
		})
	}
}
