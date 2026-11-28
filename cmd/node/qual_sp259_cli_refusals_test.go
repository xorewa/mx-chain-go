package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	logger "github.com/multiversx/mx-chain-logger-go"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

func TestQualSP259UnsupportedModesRefusedByCLI(t *testing.T) {
	for _, mode := range []string{"checkpoint", "hardfork", "import-database", "migration"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			raw := []byte(fmt.Sprintf("Mode = %q\n", mode))
			path := filepath.Join(dir, "startup.toml")
			require.NoError(t, os.WriteFile(path, raw, 0600))
			anchor := fmt.Sprintf("%x:%d:%s", sha256.Sum256(raw), len(raw), path)
			retained := filepath.Join(dir, "retained")
			require.NoError(t, os.WriteFile(retained, []byte("unchanged"), 0600))
			logs := filepath.Join(dir, "logs")
			app := cli.NewApp()
			app.Flags = getFlags()
			app.Action = func(ctx *cli.Context) error {
				return startNodeRunner(ctx, logger.GetOrCreate("qual-sp259-cli"), "base", "version")
			}
			err := app.Run([]string{"qual-sp259", "--" + drwaStartupRecord.Name, anchor, "--" + configurationFile.Name, filepath.Join(dir, "not-opened.toml"), "--" + workingDirectory.Name, dir, "--" + logsDirectory.Name, logs, "--" + logSaveFile.Name})
			require.ErrorIs(t, err, errDRWAStartupRecord)
			require.NoDirExists(t, logs)
			data, err := os.ReadFile(retained)
			require.NoError(t, err)
			require.Equal(t, []byte("unchanged"), data)
		})
	}
}

func TestQualSP259OrdinaryCLIStillRejectsInvalidImportFlag(t *testing.T) {
	dir := qualDRWANativeStartupFixtureDir(t)
	logs := filepath.Join(dir, "logs")
	app := cli.NewApp()
	app.Flags = getFlags()
	app.Action = func(ctx *cli.Context) error {
		return startNodeRunner(ctx, logger.GetOrCreate("qual-sp259-ordinary"), "base", "version")
	}
	// No file logging or node construction. The ordinary flag validator
	// retains the same native error independently of DRWA admission.
	args := []string{"qual-ordinary", "--" + importDbNoSigCheck.Name}
	for _, input := range [][2]string{
		{configurationFile.Name, "config.toml"}, {configurationApiFile.Name, "api.toml"}, {configurationEconomicsFile.Name, "economics.toml"}, {configurationSystemSCFile.Name, "systemSmartContractsConfig.toml"}, {configurationRatingsFile.Name, "ratings.toml"}, {configurationPreferencesFile.Name, "prefs.toml"}, {externalConfigFile.Name, "external.toml"}, {p2pConfigurationFile.Name, "p2p.toml"}, {fullArchiveP2PConfigurationFile.Name, "fullArchiveP2P.toml"}, {epochConfigurationFile.Name, "enableEpochs.toml"}, {roundConfigurationFile.Name, "enableRounds.toml"}, {nodesFile.Name, "nodesSetup.json"}, {workingDirectory.Name, "."}, {logsDirectory.Name, "logs"},
	} {
		args = append(args, "--"+input[0], filepath.Join(dir, input[1]))
	}
	require.EqualError(t, app.Run(args), "import-db-no-sig-check can only be used with the import-db flag")
	require.NoDirExists(t, logs)
	require.NoDirExists(t, filepath.Join(dir, "db"))
}
