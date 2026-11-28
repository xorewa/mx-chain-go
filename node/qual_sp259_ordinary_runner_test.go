package node

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
)

func TestQualSP259OrdinaryRunnerRequiresNativeExportInput(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, common.DefaultDBPath)
	require.NoError(t, os.MkdirAll(store, 0700))
	marker := filepath.Join(store, "retained")
	require.NoError(t, os.WriteFile(marker, []byte("retained"), 0600))
	paths := &config.ConfigurationPathsHolder{Nodes: filepath.Join(dir, "ordinary-nodes.json")}
	cfg := &config.Configs{
		GeneralConfig: &config.Config{}, FlagsConfig: &config.ContextFlagsConfig{WorkingDir: dir, DbDir: dir},
		ConfigurationPathsHolder: paths,
	}
	// Ordinary startup must continue to use its native missing-export-input
	// error before provider setup or any storage operation.
	cfg.GeneralConfig.Hardfork.AfterHardFork = true
	cfg.GeneralConfig.Hardfork.ImportFolder = "absent-export"
	require.NoError(t, ValidateDRWAStartupMode(cfg))
	runner, err := NewNodeRunner(cfg)
	require.NoError(t, err)
	require.EqualError(t, runner.Start(), "cannot find "+common.NodesSetupJsonFileName+" in the export folder")
	body, err := os.ReadFile(marker)
	require.NoError(t, err)
	require.Equal(t, []byte("retained"), body)
	require.NoDirExists(t, filepath.Join(dir, "absent-export"))
}

func TestQualSP259OrdinaryRunnerSelectsConfiguredNodesInput(t *testing.T) {
	dir := t.TempDir()
	configured := filepath.Join(dir, "ordinary-nodes.json")
	cfg := &config.Configs{
		GeneralConfig: &config.Config{}, FlagsConfig: &config.ContextFlagsConfig{WorkingDir: dir, DbDir: dir},
		ConfigurationPathsHolder: &config.ConfigurationPathsHolder{Nodes: configured},
	}
	runner, err := NewNodeRunner(cfg)
	require.NoError(t, err)
	selected, err := runner.getNodesFileName()
	require.NoError(t, err)
	require.Equal(t, configured, selected)

	cfg.GeneralConfig.Hardfork.AfterHardFork = true
	cfg.GeneralConfig.Hardfork.ImportFolder = "ordinary-export"
	export := filepath.Join(dir, "ordinary-export")
	require.NoError(t, os.MkdirAll(export, 0700))
	setup := filepath.Join(export, common.NodesSetupJsonFileName)
	require.NoError(t, os.WriteFile(setup, []byte("{}"), 0600))
	selected, err = runner.getNodesFileName()
	require.NoError(t, err)
	require.Equal(t, setup, selected)
	// Selection only; do not construct providers or launch a node.
	require.NoDirExists(t, filepath.Join(dir, common.DefaultDBPath))
}

func TestQualSP259OrdinaryRunnerReturnsNativeCleanupError(t *testing.T) {
	dir := t.TempDir()
	unavailable := filepath.Join(dir, "not-a-directory")
	require.NoError(t, os.WriteFile(unavailable, []byte("retained"), 0600))
	cfg := &config.Configs{
		GeneralConfig: &config.Config{}, FlagsConfig: &config.ContextFlagsConfig{WorkingDir: dir, DbDir: unavailable, CleanupStorage: true},
		ConfigurationPathsHolder: &config.ConfigurationPathsHolder{Nodes: filepath.Join(dir, "ordinary-nodes.json")},
	}
	// Confirm the temporary native dependency fails before calling Start:
	// even on a different filesystem this fixture cannot reach providers.
	expected := cleanupStorageIfNecessary(unavailable, true)
	require.Error(t, expected)
	runner, err := NewNodeRunner(cfg)
	require.NoError(t, err)
	require.EqualError(t, runner.Start(), expected.Error())
	body, err := os.ReadFile(unavailable)
	require.NoError(t, err)
	require.Equal(t, []byte("retained"), body)
}
