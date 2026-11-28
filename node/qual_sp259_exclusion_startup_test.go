package node

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/stretchr/testify/require"
)

func TestQualSP259OriginalStartupExclusionValidation(t *testing.T) {
	cfg := &config.Configs{GeneralConfig: &config.Config{HardforkRoundExclusions: []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 20}}}}
	require.NoError(t, ValidateDRWAStartupMode(cfg))
	cfg.DRWAInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{}
	require.NoError(t, ValidateDRWAStartupMode(cfg))
	cfg.GeneralConfig.HardforkRoundExclusions[0].EndRound = 9
	runner, err := NewNodeRunner(cfg)
	require.Nil(t, runner)
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.ErrorIs(t, err, common.ErrInvalidHardforkRoundExclusion)
	// An ordinary runner does not gain the DRWA-specific validation path.
	cfg.DRWAInitialProgrammeStartup = nil
	runner, err = NewNodeRunner(cfg)
	require.NoError(t, err)
	require.NotNil(t, runner)
}

func TestQualSP259UnsupportedNativeStartupModes(t *testing.T) {
	for _, name := range []string{"checkpoint", "hardfork", "import-database", "migration", "network-bootstrap", "cleanup"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			role := filepath.Join(root, "validator0")
			path := filepath.Join(role, "db", "qualification")
			require.NoError(t, os.MkdirAll(path, 0700))
			marker := filepath.Join(path, "retained")
			require.NoError(t, os.WriteFile(marker, []byte("unchanged"), 0600))
			cfg := &config.Configs{FlagsConfig: &config.ContextFlagsConfig{WorkingDir: role, DbDir: role}, GeneralConfig: &config.Config{}, ImportDbConfig: &config.ImportDbConfig{}, DRWAInitialProgrammeStartup: &config.DRWAInitialProgrammeStartup{OriginalDatabasePath: path, RecordDigest: [32]byte{1}, ReleaseWait: 1, ReleaseMaxBytes: 64}}
			cfg.GeneralConfig.GeneralSettings.ChainID = "qualification"
			cfg.GeneralConfig.GeneralSettings.DRWADeploymentIdentity = &config.DRWADeploymentIdentityConfig{}
			switch name {
			case "checkpoint":
				cfg.GeneralConfig.HardforkRecoveryCheckpoint.Enabled = true
			case "hardfork":
				cfg.GeneralConfig.Hardfork.AfterHardFork = true
			case "import-database":
				cfg.ImportDbConfig.IsImportDBMode = true
			case "migration":
				cfg.DRWAInitialProgrammeStartup.OriginalDatabasePath = filepath.Join(root, "other")
			case "network-bootstrap":
				cfg.FlagsConfig.ForceStartFromNetwork = true
			case "cleanup":
				cfg.FlagsConfig.CleanupStorage = true
			}
			runner, err := NewNodeRunner(cfg)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			require.Nil(t, runner)
			data, err := os.ReadFile(marker)
			require.NoError(t, err)
			require.Equal(t, []byte("unchanged"), data)
		})
	}
}

func TestQualSP259RestartPreflightBeforeNativeProviders(t *testing.T) {
	role := t.TempDir()
	path := filepath.Join(role, "db", "qualification")
	selected := &config.DRWAStartupConfiguration{RecordDigest: [32]byte{1}, MainConfigDigest: [32]byte{2}, RestartConfigDigest: [32]byte{3}}
	prior := selected.Clone()
	prior.RecordDigest = [32]byte{4}
	cfg := &config.Configs{
		FlagsConfig:   &config.ContextFlagsConfig{WorkingDir: role, DbDir: role, BootstrapRoundIndex: math.MaxUint64},
		GeneralConfig: &config.Config{}, ImportDbConfig: &config.ImportDbConfig{},
		DRWAInitialProgrammeStartup: &config.DRWAInitialProgrammeStartup{Persisted: true, OriginalDatabasePath: path, RecordDigest: selected.RecordDigest, SelectedConfiguration: selected, PredecessorConfiguration: prior},
	}
	cfg.GeneralConfig.GeneralSettings.ChainID = "qualification"
	cfg.GeneralConfig.GeneralSettings.DRWADeploymentIdentity = &config.DRWADeploymentIdentityConfig{}
	require.NoError(t, ValidateDRWAStartupMode(cfg))
	runner, err := NewNodeRunner(cfg)
	require.Error(t, err)
	require.Nil(t, runner)
	require.NoDirExists(t, path)
	// Start repeats preflight before acquiring any native provider.
	runner = &nodeRunner{configs: cfg}
	require.Error(t, runner.Start())
	stop, err := runner.executeOneComponentCreationCycle(nil)
	require.True(t, stop)
	require.Error(t, err)
	require.NoDirExists(t, path)
	cfg.FlagsConfig.DbDir = "relative"
	require.ErrorIs(t, validateDRWARestartStore(cfg), drwa.ErrDeploymentIdentity)
	cfg.FlagsConfig.DbDir = role
	cfg.ImportDbConfig = nil
	require.ErrorIs(t, validateDRWARestartStore(cfg), drwa.ErrDeploymentIdentity)
	cfg.ImportDbConfig = &config.ImportDbConfig{}
	cfg.GeneralConfig.GeneralSettings.ChainID = ""
	require.ErrorIs(t, validateDRWARestartStore(cfg), drwa.ErrDeploymentIdentity)
	cfg.GeneralConfig.GeneralSettings.ChainID = "qualification"
	cfg.FlagsConfig.BootstrapRoundIndex = 1
	require.ErrorIs(t, ValidateDRWAStartupMode(cfg), drwa.ErrDeploymentIdentity)
}

func TestQualSP259OriginalRunnerStillRequiresNativeProvenance(t *testing.T) {
	root := t.TempDir()
	role := filepath.Join(root, "validator0")
	path := filepath.Join(role, "db", "qualification")
	require.NoError(t, os.MkdirAll(path, 0700))
	selected := &config.DRWAStartupConfiguration{RecordDigest: [32]byte{1}, MainConfigDigest: [32]byte{2}, RestartConfigDigest: [32]byte{3}}
	cfg := &config.Configs{GeneralConfig: &config.Config{}, ImportDbConfig: &config.ImportDbConfig{},
		FlagsConfig:                 &config.ContextFlagsConfig{WorkingDir: role, DbDir: role, BootstrapRoundIndex: math.MaxUint64},
		DRWAInitialProgrammeStartup: &config.DRWAInitialProgrammeStartup{RecordDigest: selected.RecordDigest, SelectedConfiguration: selected, OriginalDatabasePath: path, ReleaseWait: 1, ReleaseMaxBytes: 64}}
	cfg.GeneralConfig.GeneralSettings.ChainID = "qualification"
	cfg.GeneralConfig.GeneralSettings.DRWADeploymentIdentity = &config.DRWADeploymentIdentityConfig{}
	require.NoError(t, ValidateDRWAStartupMode(cfg))
	runner, err := NewNodeRunner(cfg)
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Nil(t, runner)
	// No process-bound release grant was acquired, so a cycle must refuse.
	runner = &nodeRunner{configs: cfg}
	stop, err := runner.executeOneComponentCreationCycle(nil)
	require.True(t, stop)
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	items, err := os.ReadDir(path)
	require.NoError(t, err)
	require.Empty(t, items)
}
