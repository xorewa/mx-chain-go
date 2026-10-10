package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nativeCore "github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/config/overridableConfig"
	coreFactory "github.com/multiversx/mx-chain-go/factory/core"
	logger "github.com/multiversx/mx-chain-logger-go"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

// T09-M43 adopts the real pre-NodeRunner config sequence in startNodeRunner.
// No attachFileLogger, hardware check, NodeRunner, VM, service or network starts.
func qualDRWANativeStartup(t *testing.T, dir string, extra ...string) (*config.Configs, error) {
	t.Helper()
	app := cli.NewApp()
	app.Flags = getFlags()
	args := []string{"qual-drwa-native-config"}
	for _, binding := range [][2]string{
		{configurationFile.Name, "config.toml"}, {configurationApiFile.Name, "api.toml"},
		{configurationEconomicsFile.Name, "economics.toml"}, {configurationSystemSCFile.Name, "systemSmartContractsConfig.toml"},
		{configurationRatingsFile.Name, "ratings.toml"}, {configurationPreferencesFile.Name, "prefs.toml"},
		{externalConfigFile.Name, "external.toml"}, {p2pConfigurationFile.Name, "p2p.toml"},
		{fullArchiveP2PConfigurationFile.Name, "fullArchiveP2P.toml"}, {epochConfigurationFile.Name, "enableEpochs.toml"},
		{roundConfigurationFile.Name, "enableRounds.toml"}, {nodesFile.Name, "nodesSetup.json"},
		{workingDirectory.Name, "."}, {genesisFile.Name, "genesis.json"},
		{smartContractsFile.Name, "genesisSmartContracts.json"}, {gasScheduleConfigurationDirectory.Name, "gasSchedules"},
		{validatorKeyPemFile.Name, "absent-validator.pem"}, {allValidatorKeysPemFile.Name, "absent-managed.pem"},
		{p2pKeyPemFile.Name, "absent-p2p.pem"},
	} {
		args = append(args, "--"+binding[0], filepath.Join(dir, binding[1]))
	}
	args = append(args, extra...)
	var cfgs *config.Configs
	app.Action = func(ctx *cli.Context) error {
		log := logger.GetOrCreate("qual-native-config")
		flagsConfig := getFlagsConfig(ctx, log)
		var err error
		cfgs, err = readConfigs(ctx, log)
		if err != nil {
			return err
		}
		if err = overridableConfig.OverrideConfigValues(cfgs.PreferencesConfig.Preferences.OverridableConfigTomlValues, cfgs); err != nil {
			return err
		}
		return applyFlags(ctx, cfgs, flagsConfig, log)
	}
	err := app.Run(args)
	return cfgs, err
}

func qualDRWANativePreferencesOverride(t *testing.T, dir, item string) {
	t.Helper()
	path := filepath.Join(dir, "prefs.toml")
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(body), "[Preferences]"))
	changed := strings.Replace(string(body), "[Preferences]", "[Preferences]\nOverridableConfigTomlValues = ["+item+"]", 1)
	require.NoError(t, os.WriteFile(path, []byte(changed), 0600))
}

func qualDRWANativeStartupCandidate(t *testing.T, dir string, cfgs *config.Configs) (*coreFactory.DRWAConfigurationCandidate, error) {
	t.Helper()
	var overlay struct{ DRWAEnforcementEnableEpoch *uint32 }
	require.NoError(t, nativeCore.LoadTomlFile(&overlay, filepath.Join(dir, "drwa.toml")))
	require.NotNil(t, overlay.DRWAEnforcementEnableEpoch)
	require.Equal(t, uint32(3), *overlay.DRWAEnforcementEnableEpoch)
	return coreFactory.NewDRWAConfigurationCandidate(cfgs, *overlay.DRWAEnforcementEnableEpoch,
		coreFactory.DRWAConfigurationSupport{RelayedV3: true})
}

func TestQualDRWANativeStartupCompleteInputs(t *testing.T) {
	dir := qualDRWANativeStartupFixtureDir(t)
	cfgs, err := qualDRWANativeStartup(t, dir)
	require.NoError(t, err)
	for _, object := range []interface{}{cfgs.GeneralConfig, cfgs.ApiRoutesConfig, cfgs.EconomicsConfig,
		cfgs.SystemSCConfig, cfgs.RatingsConfig, cfgs.PreferencesConfig, cfgs.ExternalConfig,
		cfgs.MainP2pConfig, cfgs.FullArchiveP2pConfig, cfgs.EpochConfig, cfgs.RoundConfig, cfgs.NodesConfig,
		cfgs.FlagsConfig, cfgs.ImportDbConfig, cfgs.ConfigurationPathsHolder} {
		require.NotNil(t, object)
	}
	paths := cfgs.ConfigurationPathsHolder
	for file, actual := range map[string]string{"config.toml": paths.MainConfig, "api.toml": paths.ApiRoutes,
		"economics.toml": paths.Economics, "systemSmartContractsConfig.toml": paths.SystemSC,
		"ratings.toml": paths.Ratings, "prefs.toml": paths.Preferences, "external.toml": paths.External,
		"p2p.toml": paths.MainP2p, "fullArchiveP2P.toml": paths.FullArchiveP2p,
		"enableEpochs.toml": paths.Epoch, "enableRounds.toml": paths.RoundActivation, "nodesSetup.json": paths.Nodes} {
		require.Equal(t, filepath.Join(dir, file), actual)
	}
	before, err := json.Marshal(cfgs)
	require.NoError(t, err)
	candidate, err := qualDRWANativeStartupCandidate(t, dir, cfgs)
	require.NoError(t, err)
	require.NoError(t, candidate.CheckEnforcedBlock(3, 440))
	after, err := json.Marshal(cfgs)
	require.NoError(t, err)
	require.Equal(t, before, after)
	for name, fixture := range qualDRWANativeStartupFixtures {
		body, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		require.Equal(t, []byte(fixture.body), body)
	}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, len(qualDRWANativeStartupFixtures), "no keys, DB or runtime output created")
	// applyFlags binds these locators without loading them at this stage.
	// Separate genesis/gas/key factory qualification and admission remain due.
	require.Equal(t, filepath.Join(dir, "genesis.json"), paths.Genesis)
	require.Equal(t, filepath.Join(dir, "gasSchedules"), paths.GasScheduleDirectoryName)
	require.False(t, cfgs.ImportDbConfig.IsImportDBMode)
}

func TestQualDRWANativeStartupPreferencesCannotBypass(t *testing.T) {
	dir := qualDRWANativeStartupFixtureDir(t)
	qualDRWANativePreferencesOverride(t, dir, "{ File = 'enableEpochs.toml', Path = 'EnableEpochs.GlobalMintBurnDisableEpoch', Value = 4 }")
	cfgs, err := qualDRWANativeStartup(t, dir)
	require.NoError(t, err)
	require.Equal(t, uint32(4), cfgs.EpochConfig.EnableEpochs.GlobalMintBurnDisableEpoch)
	candidate, err := qualDRWANativeStartupCandidate(t, dir, cfgs)
	require.ErrorContains(t, err, string(common.GlobalMintBurnFlag))
	require.Nil(t, candidate)
	body, err := os.ReadFile(filepath.Join(dir, "enableEpochs.toml"))
	require.NoError(t, err)
	require.Equal(t, []byte(qualDRWANativeStartupFixtures["enableEpochs.toml"].body), body)
}

func TestQualDRWANativeStartupCLIPrecedence(t *testing.T) {
	dir := qualDRWANativeStartupFixtureDir(t)
	qualDRWANativePreferencesOverride(t, dir, "{ File = 'config.toml', Path = 'GeneralSettings.StartInEpochEnabled', Value = true }")
	cfgs, err := qualDRWANativeStartup(t, dir, "--"+startInEpoch.Name+"=false")
	require.NoError(t, err)
	require.False(t, cfgs.GeneralConfig.GeneralSettings.StartInEpochEnabled)
	candidate, err := qualDRWANativeStartupCandidate(t, dir, cfgs)
	require.NoError(t, err)
	require.NoError(t, candidate.CheckEnforcedBlock(3, 440))
}

func TestQualDRWANativeStartupInvalidImportFlags(t *testing.T) {
	dir := qualDRWANativeStartupFixtureDir(t)
	_, err := qualDRWANativeStartup(t, dir, "--"+importDbNoSigCheck.Name)
	require.EqualError(t, err, "import-db-no-sig-check can only be used with the import-db flag")
}

func TestQualDRWANativeStartupMissingInputs(t *testing.T) {
	for _, name := range []string{"config.toml", "api.toml", "economics.toml", "systemSmartContractsConfig.toml", "ratings.toml",
		"prefs.toml", "external.toml", "p2p.toml", "fullArchiveP2P.toml", "enableEpochs.toml", "enableRounds.toml", "nodesSetup.json"} {
		t.Run(name, func(t *testing.T) {
			dir := qualDRWANativeStartupFixtureDir(t)
			require.NoError(t, os.Remove(filepath.Join(dir, name)))
			cfgs, err := qualDRWANativeStartup(t, dir)
			require.ErrorIs(t, err, os.ErrNotExist)
			require.Nil(t, cfgs)
		})
	}
}
