package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/drwa"
	logger "github.com/multiversx/mx-chain-logger-go"
	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

// These fixtures stop before provider creation. None starts a node or
// acquires a DRWA startup grant.
func sp259OrdinaryCLIArgs(dir string) []string {
	args := []string{"qual-ordinary-lifecycle"}
	for _, input := range [][2]string{
		{configurationFile.Name, "config.toml"}, {configurationApiFile.Name, "api.toml"},
		{configurationEconomicsFile.Name, "economics.toml"}, {configurationSystemSCFile.Name, "systemSmartContractsConfig.toml"},
		{configurationRatingsFile.Name, "ratings.toml"}, {configurationPreferencesFile.Name, "prefs.toml"},
		{externalConfigFile.Name, "external.toml"}, {p2pConfigurationFile.Name, "p2p.toml"},
		{fullArchiveP2PConfigurationFile.Name, "fullArchiveP2P.toml"}, {epochConfigurationFile.Name, "enableEpochs.toml"},
		{roundConfigurationFile.Name, "enableRounds.toml"}, {nodesFile.Name, "nodesSetup.json"},
		{workingDirectory.Name, "."}, {logsDirectory.Name, "logs"},
	} {
		args = append(args, "--"+input[0], filepath.Join(dir, input[1]))
	}
	return args
}

func sp259OrdinaryRunCLI(t *testing.T, dir string, flags ...string) error {
	t.Helper()
	pattern := logger.GetLogLevelPattern()
	defer func() { require.NoError(t, logger.SetLogLevel(pattern)) }()
	app := cli.NewApp()
	app.Flags = getFlags()
	app.Action = func(ctx *cli.Context) error {
		return startNodeRunner(ctx, logger.GetOrCreate("qual-sp259-ordinary-lifecycle"), "base", "version")
	}
	return app.Run(append(sp259OrdinaryCLIArgs(dir), flags...))
}

func sp259OrdinaryFixture(t *testing.T, configure func(*toml.Tree)) string {
	t.Helper()
	dir := qualDRWANativeStartupFixtureDir(t)
	path := filepath.Join(dir, "config.toml")
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	tree, err := toml.LoadBytes(body)
	require.NoError(t, err)
	// Every fixture has a deterministic native refusal before provider setup,
	// independent of the earlier validation exercised by its test.
	tree.Set("Hardfork.AfterHardFork", true)
	tree.Set("Hardfork.ImportFolder", "absent-export")
	tree.Set("HardwareRequirements.CPUFlags", []string{})
	if configure != nil {
		configure(tree)
	}
	encoded, err := tree.ToTomlString()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte(encoded), 0600))
	return dir
}

func TestQualSP259OrdinaryCLIPreProviderRefusals(t *testing.T) {
	t.Run("undeclared deployment identity", func(t *testing.T) {
		dir := sp259OrdinaryFixture(t, func(tree *toml.Tree) {
			tree.Set("GeneralSettings.DRWADeploymentIdentity.Path", "qualification-unavailable")
		})
		require.ErrorIs(t, sp259OrdinaryRunCLI(t, dir), drwa.ErrDeploymentIdentity)
		require.NoDirExists(t, filepath.Join(dir, "logs"))
		require.NoDirExists(t, filepath.Join(dir, "db"))
	})
	t.Run("unrecognised logger level", func(t *testing.T) {
		dir := sp259OrdinaryFixture(t, nil)
		require.ErrorContains(t, sp259OrdinaryRunCLI(t, dir, "--"+logLevel.Name, "*:QUALIFICATION_UNKNOWN"), "unknown log level")
		require.NoDirExists(t, filepath.Join(dir, "db"))
	})
	t.Run("unrecognised hardware capability", func(t *testing.T) {
		dir := sp259OrdinaryFixture(t, func(tree *toml.Tree) {
			tree.Set("HardwareRequirements.CPUFlags", []string{"QUALIFICATION_UNKNOWN"})
		})
		require.ErrorContains(t, sp259OrdinaryRunCLI(t, dir), "hardware requirements checks failed")
		require.NoDirExists(t, filepath.Join(dir, "db"))
	})
	t.Run("native missing export input", func(t *testing.T) {
		dir := sp259OrdinaryFixture(t, nil)
		require.EqualError(t, sp259OrdinaryRunCLI(t, dir), "cannot find "+common.NodesSetupJsonFileName+" in the export folder")
		require.NoDirExists(t, filepath.Join(dir, "db"))
		require.NoDirExists(t, filepath.Join(dir, "logs"))
	})
}

func TestQualSP259OrdinaryCLIFileLoggerLifecycle(t *testing.T) {
	// Native file logging redirects process stderr. Keep its observer,
	// rotation worker and stderr redirection inside a bounded child process.
	const childEnv = "QUAL_SP259_ORDINARY_LOGGER_CHILD"
	if os.Getenv(childEnv) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestQualSP259OrdinaryCLIFileLoggerLifecycle$", "-test.v")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		return
	}
	dir := sp259OrdinaryFixture(t, func(tree *toml.Tree) {
		tree.Set("Logs.LogFileLifeSpanInSec", int64(120))
		tree.Set("Logs.LogFileLifeSpanInMB", int64(1))
	})
	// Ordinary CLI's inherited return value is the successful logger close,
	// while the native missing-input refusal is reported in its log.
	require.NoError(t, sp259OrdinaryRunCLI(t, dir, "--"+logSaveFile.Name))
	var files []string
	require.NoError(t, filepath.WalkDir(filepath.Join(dir, "logs"), func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() && filepath.Ext(path) == ".log" {
			files = append(files, path)
		}
		return err
	}))
	require.Len(t, files, 1)
	body, err := os.ReadFile(files[0])
	require.NoError(t, err)
	require.Contains(t, string(body), "cannot find "+common.NodesSetupJsonFileName+" in the export folder")
	require.NoDirExists(t, filepath.Join(dir, "db"))
}
