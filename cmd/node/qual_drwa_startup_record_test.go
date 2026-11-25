package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/drwa"
	logger "github.com/multiversx/mx-chain-logger-go"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

func TestQualDRWAStartupRecordBindsNativeRoleDatabase(t *testing.T) {
	root := t.TempDir()
	const chainID = "local-testnet"
	makeRole := func(name string) drwaStartupRole {
		work := filepath.Join(root, name)
		return drwaStartupRole{
			WorkingDirectory:     work,
			MainConfig:           drwaStartupMember{Path: filepath.Join(root, "config_"+name+".toml")},
			OriginalDatabasePath: filepath.Join(work, "db", chainID),
		}
	}
	validator := makeRole("validator")
	observer := makeRole("observer")
	roles := []drwaStartupRole{validator, observer}
	for _, expected := range roles {
		t.Run(filepath.Base(expected.WorkingDirectory), func(t *testing.T) {
			flags := &config.ContextFlagsConfig{WorkingDir: expected.WorkingDirectory, DbDir: expected.WorkingDirectory}
			selected, err := selectDRWAStartupRole(roles, flags, chainID, expected.MainConfig.Path)
			require.NoError(t, err)
			require.Equal(t, expected, *selected)
		})
	}

	flags := &config.ContextFlagsConfig{WorkingDir: validator.WorkingDirectory, DbDir: validator.WorkingDirectory}
	t.Run("other role main config", func(t *testing.T) {
		_, err := selectDRWAStartupRole(roles, flags, chainID, observer.MainConfig.Path)
		require.ErrorIs(t, err, errDRWAStartupRecord)
	})
	t.Run("effective db-directory changed", func(t *testing.T) {
		different := *flags
		different.DbDir = observer.WorkingDirectory
		_, err := selectDRWAStartupRole(roles, &different, chainID, validator.MainConfig.Path)
		require.ErrorIs(t, err, errDRWAStartupRecord)
	})
	t.Run("same DB claimed by both roles", func(t *testing.T) {
		duplicate := observer
		duplicate.OriginalDatabasePath = validator.OriginalDatabasePath
		_, err := selectDRWAStartupRole([]drwaStartupRole{validator, duplicate}, flags, chainID, validator.MainConfig.Path)
		require.ErrorIs(t, err, errDRWAStartupRecord)
	})
	t.Run("same working directory claimed twice", func(t *testing.T) {
		duplicate := observer
		duplicate.WorkingDirectory = validator.WorkingDirectory
		_, err := selectDRWAStartupRole([]drwaStartupRole{validator, duplicate}, flags, chainID, validator.MainConfig.Path)
		require.ErrorIs(t, err, errDRWAStartupRecord)
	})
}

func TestQualDRWAStartupRecordBindsNodesSetup(t *testing.T) {
	for _, tc := range []struct {
		name, body    string
		effective     int64
		differentPath bool
		afterHardFork bool
		wantError     bool
	}{
		{name: "same sealed setup", body: `{"startTime":2}`, effective: 2},
		{name: "changed effective start", body: `{"startTime":2}`, effective: 3, wantError: true},
		{name: "native dynamic start forbidden", body: `{"startTime":0}`, wantError: true},
		{name: "different setup path", body: `{"startTime":2}`, effective: 2, differentPath: true, wantError: true},
		{name: "hardfork clock replacement", body: `{"startTime":2}`, effective: 2, afterHardFork: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nodesSetup.json")
			raw := []byte(tc.body)
			require.NoError(t, os.WriteFile(path, raw, 0600))
			digest := sha256.Sum256(raw)
			member := drwaStartupMember{Path: path, SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(raw))}
			cfg := &config.Configs{
				GeneralConfig:            &config.Config{},
				ConfigurationPathsHolder: &config.ConfigurationPathsHolder{Nodes: path},
				NodesConfig:              &config.NodesConfig{StartTime: tc.effective},
			}
			cfg.GeneralConfig.Hardfork.AfterHardFork = tc.afterHardFork
			if tc.differentPath {
				cfg.ConfigurationPathsHolder.Nodes = path + ".other"
			}
			err := matchDRWAStartupNodes(cfg, member)
			if tc.wantError {
				require.ErrorIs(t, err, errDRWAStartupRecord)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestQualDRWAStartupRecordBindsMinimumDeclarations(t *testing.T) {
	const profile = `{"max_ever_regulated_tokens":64,"registry_proof_bytes":1048576,"processor_support":{"v2":true}}`
	write := func(t *testing.T, name, data string) drwaStartupMember {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		require.NoError(t, os.WriteFile(path, []byte(data), 0600))
		digest := sha256.Sum256([]byte(data))
		return drwaStartupMember{Path: path, SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(data))}
	}
	makeRecord := func(t *testing.T, body string) drwaStartupRecordInput {
		t.Helper()
		profileMember := write(t, "profile.json", body)
		release := write(t, "release.json", `{"profile_sha256":"`+profileMember.SHA256+`"}`)
		return drwaStartupRecordInput{
			Profile: profileMember, Release: release,
			MinimumMaxEverTokens: 64, MinimumRegistryProofBytes: 1048576,
		}
	}
	t.Run("exact experimental minimum declarations", func(t *testing.T) {
		record := makeRecord(t, profile)
		minimum, err := readDRWAStartupMinimum(record)
		require.NoError(t, err)
		require.Equal(t, uint64(64), minimum.MaxEverTokens)
		require.Equal(t, uint64(1048576), minimum.RegistryProofBytes)
		require.Equal(t, sha256.Sum256([]byte(profile)), minimum.ProfileDigest)
		require.Equal(t, record.Release.SHA256, hex.EncodeToString(minimum.ReleaseDigest[:]))
	})
	t.Run("matching zero maximum violates native minimum", func(t *testing.T) {
		record := makeRecord(t, `{"max_ever_regulated_tokens":0,"registry_proof_bytes":1048576}`)
		record.MinimumMaxEverTokens = 0

		minimum, err := readDRWAStartupMinimum(record)
		require.EqualError(t, err, "DRWA provisioning requires an empty native genesis store")
		require.Equal(t, config.DRWAMinimumGenesis{}, minimum)
	})
	t.Run("matching zero proof budget violates native minimum", func(t *testing.T) {
		record := makeRecord(t, `{"max_ever_regulated_tokens":64,"registry_proof_bytes":0}`)
		record.MinimumRegistryProofBytes = 0

		minimum, err := readDRWAStartupMinimum(record)
		require.EqualError(t, err, "DRWA provisioning requires an empty native genesis store")
		require.Equal(t, config.DRWAMinimumGenesis{}, minimum)
	})
	for _, tc := range []struct {
		name   string
		body   string
		change func(*testing.T, *drwaStartupRecordInput)
	}{
		{name: "release points elsewhere", body: profile, change: func(t *testing.T, record *drwaStartupRecordInput) {
			record.Release = write(t, "release.json", `{"profile_sha256":"other"}`)
		}},
		{name: "carrier max differs", body: profile, change: func(_ *testing.T, record *drwaStartupRecordInput) {
			record.MinimumMaxEverTokens++
		}},
		{name: "carrier proof budget differs", body: profile, change: func(_ *testing.T, record *drwaStartupRecordInput) {
			record.MinimumRegistryProofBytes++
		}},
		{name: "noninteger minimum", body: `{"max_ever_regulated_tokens":true,"registry_proof_bytes":1048576}`},
		{name: "null minimum", body: `{"max_ever_regulated_tokens":null,"registry_proof_bytes":1048576}`},
		{name: "null release link", body: profile, change: func(t *testing.T, record *drwaStartupRecordInput) {
			record.Release = write(t, "release.json", `{"profile_sha256":null}`)
		}},
		{name: "duplicate exact minimum", body: `{"max_ever_regulated_tokens":63,"max_ever_regulated_tokens":64,"registry_proof_bytes":1048576}`},
		{name: "escaped duplicate budget", body: `{"max_ever_regulated_tokens":64,"registry_proof_bytes":1,"registry_proof_byte\u0073":1048576}`},
		{name: "lone minimum case alias", body: `{"MAX_EVER_REGULATED_TOKENS":64,"registry_proof_bytes":1048576}`},
		{name: "mixed budget case alias", body: `{"max_ever_regulated_tokens":64,"Registry_Proof_Bytes":1,"registry_proof_bytes":1048576}`},
		{name: "duplicate release link", body: profile, change: func(t *testing.T, record *drwaStartupRecordInput) {
			record.Release = write(t, "release.json", `{"profile_sha256":"other","profile_sha256":"`+record.Profile.SHA256+`"}`)
		}},
		{name: "release case alias", body: profile, change: func(t *testing.T, record *drwaStartupRecordInput) {
			record.Release = write(t, "release.json", `{"PROFILE_SHA256":"`+record.Profile.SHA256+`"}`)
		}},
		{name: "malformed member name", body: `{"max_ever_regulated_tokens":64,7:0,"registry_proof_bytes":1048576}`},
		{name: "malformed nested member value", body: `{"max_ever_regulated_tokens":64,"registry_proof_bytes":1048576,"processor_support":{"v2":}}`},
		{name: "trailing member", body: profile + ` {}`},
		{name: "malformed object", body: profile[:len(profile)-1]},
		{name: "missing key after comma", body: `{"max_ever_regulated_tokens":64,}`},
		{name: "missing declaration value", body: `{"max_ever_regulated_tokens":`},
		{name: "nonobject declaration", body: "[" + profile + "]"},
		{name: "missing budget", body: `{"max_ever_regulated_tokens":64}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := makeRecord(t, tc.body)
			if tc.change != nil {
				tc.change(t, &record)
			}
			minimum, err := readDRWAStartupMinimum(record)
			require.ErrorIs(t, err, errDRWAStartupRecord)
			require.Equal(t, config.DRWAMinimumGenesis{}, minimum)
		})
	}
	t.Run("matched zero token cap fails native minimum validation", func(t *testing.T) {
		record := makeRecord(t, `{"max_ever_regulated_tokens":0,"registry_proof_bytes":1048576}`)
		record.MinimumMaxEverTokens = 0
		minimum, err := readDRWAStartupMinimum(record)
		require.EqualError(t, err, "DRWA provisioning requires an empty native genesis store")
		require.Equal(t, config.DRWAMinimumGenesis{}, minimum)
	})
}

func TestQualDRWAStartupRecordUsesNativeCLI(t *testing.T) {
	for _, tc := range []struct {
		name   string
		anchor string
		want   error
	}{
		{name: "invalid anchor before missing configuration", anchor: "missing-delimiters", want: errDRWAStartupRecord},
		{name: "ordinary startup reports missing configuration", want: os.ErrNotExist},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			app := cli.NewApp()
			app.Flags = getFlags()
			app.Action = func(ctx *cli.Context) error {
				return startNodeRunner(ctx, logger.GetOrCreate("qual-startup-preconditions"), "base", "version")
			}
			args := []string{"qual-startup", "--" + configurationFile.Name, filepath.Join(dir, "missing.toml"),
				"--" + workingDirectory.Name, dir, "--" + logSaveFile.Name}
			if tc.anchor != "" {
				args = append(args, "--"+drwaStartupRecord.Name, tc.anchor)
			}
			require.ErrorIs(t, app.Run(args), tc.want)
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}

	t.Run("ordinary config keeps the startup carrier absent", func(t *testing.T) {
		cfg, err := qualDRWANativeStartup(t, qualDRWANativeStartupFixtureDir(t))
		require.NoError(t, err)
		require.NotNil(t, cfg.FlagsConfig)
		require.NotNil(t, cfg.NodesConfig)
		require.Nil(t, cfg.DRWAInitialProgrammeStartup)
	})
	for _, tc := range []struct {
		name  string
		early bool
		arg   func(t *testing.T) string
	}{
		{name: "malformed anchor", early: true, arg: func(_ *testing.T) string { return "missing-delimiters" }},
		{name: "pinned persisted record with no chain", arg: func(t *testing.T) string {
			raw := []byte("Mode = \"persisted\"\n")
			path := filepath.Join(t.TempDir(), "startup.toml")
			require.NoError(t, os.WriteFile(path, raw, 0600))
			digest := sha256.Sum256(raw)
			return hex.EncodeToString(digest[:]) + ":" + strconv.Itoa(len(raw)) + ":" + path
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := qualDRWANativeStartupFixtureDir(t)
			cfg, err := qualDRWANativeStartup(t, dir, "--"+drwaStartupRecord.Name, tc.arg(t))
			require.ErrorIs(t, err, errDRWAStartupRecord)
			if tc.early {
				require.Nil(t, cfg)
				return
			}
			require.NotNil(t, cfg)
			require.NotNil(t, cfg.FlagsConfig)
			require.NotNil(t, cfg.NodesConfig)
			require.Nil(t, cfg.DRWAInitialProgrammeStartup)
		})
	}
}

func TestQualDRWAOriginalCLIRefusesBeforeNativeEffects(t *testing.T) {
	t.Run("native configuration declares programme but startup anchor is omitted", func(t *testing.T) {
		cfg, err := qualDRWANativeStartup(t, qualDRWANativeStartupFixtureDir(t))
		require.NoError(t, err)
		// Observe the existing post-load bind with an explicitly nonempty,
		// inert declaration. No programme member or native store is opened.
		cfg.GeneralConfig.GeneralSettings.DRWAInitialProgrammeInputs = []config.DRWAInitialProgrammeInput{{}}
		require.ErrorIs(t, bindDRWAStartupRecord(cfg, nil), errDRWAOriginalProvenance)
		require.Nil(t, cfg.DRWAInitialProgrammeStartup)
	})
	for _, tc := range []struct {
		name     string
		backing  bool
		attempts int
	}{
		{name: "no prior store but no provenance", attempts: 1},
		{name: "selected store exists but no provenance", backing: true, attempts: 1},
		{name: "same record following possible earlier Commit", backing: true, attempts: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			store := filepath.Join(root, "db", "test-chain")
			marker := filepath.Join(store, "retained")
			if tc.backing {
				require.NoError(t, os.MkdirAll(store, 0700))
				require.NoError(t, os.WriteFile(marker, []byte("unchanged"), 0600))
			}
			path := filepath.Join(root, "startup.toml")
			raw := []byte("Mode = \"original\"\nChainID = \"test-chain\"\n")
			require.NoError(t, os.WriteFile(path, raw, 0600))
			digest := sha256.Sum256(raw)
			anchor := hex.EncodeToString(digest[:]) + ":" + strconv.Itoa(len(raw)) + ":" + path
			logs := filepath.Join(root, "log-root")
			for i := 0; i < tc.attempts; i++ {
				app := cli.NewApp()
				app.Flags = getFlags()
				app.Action = func(ctx *cli.Context) error {
					return startNodeRunner(ctx, logger.GetOrCreate("qual-original-drwa-cli"), "", "")
				}
				err := app.Run([]string{"qual-original", "--" + drwaStartupRecord.Name, anchor,
					"--" + configurationFile.Name, filepath.Join(root, "missing-main.toml"),
					"--" + workingDirectory.Name, root, "--" + logsDirectory.Name, logs,
					"--" + logSaveFile.Name})
				require.ErrorIs(t, err, errDRWAOriginalProvenance)
				_, err = os.Lstat(logs)
				require.True(t, os.IsNotExist(err))
				if tc.backing {
					data, err := os.ReadFile(marker)
					require.NoError(t, err)
					require.Equal(t, "unchanged", string(data))
				} else {
					_, err = os.Lstat(filepath.Join(root, "db"))
					require.True(t, os.IsNotExist(err))
				}
			}
		})
	}
}

func TestQualDRWAPersistedCLIRefusesBeforeNativeEffects(t *testing.T) {
	root := t.TempDir()
	raw := []byte("Mode = \"persisted\"\n")
	record := filepath.Join(root, "startup.toml")
	require.NoError(t, os.WriteFile(record, raw, 0600))
	digest := sha256.Sum256(raw)
	anchor := hex.EncodeToString(digest[:]) + ":" + strconv.Itoa(len(raw)) + ":" + record

	retained := filepath.Join(root, "db", "test-chain")
	require.NoError(t, os.MkdirAll(retained, 0700))
	marker := filepath.Join(retained, "retained")
	require.NoError(t, os.WriteFile(marker, []byte("unchanged"), 0600))

	logs := filepath.Join(root, "logs")
	app := cli.NewApp()
	app.Flags = getFlags()
	app.Action = func(ctx *cli.Context) error {
		return startNodeRunner(ctx, logger.GetOrCreate("qual-persisted-drwa-cli"), "", "")
	}
	err := app.Run([]string{"qual-persisted", "--" + drwaStartupRecord.Name, anchor,
		"--" + configurationFile.Name, filepath.Join(root, "missing-main.toml"),
		"--" + workingDirectory.Name, root, "--" + logsDirectory.Name, logs,
		"--" + logSaveFile.Name, "--" + storageCleanup.Name})
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	_, err = os.Lstat(logs)
	require.True(t, os.IsNotExist(err))
	require.NoFileExists(t, filepath.Join(retained, "config.toml"))
	contents, err := os.ReadFile(marker)
	require.NoError(t, err)
	require.Equal(t, "unchanged", string(contents))
}

func TestQualDRWANilCarrierConfiguredCLIRefusesBeforeNativeEffects(t *testing.T) {
	// Keep any logger installed by the old CLI in this one bounded subprocess.
	if mode := os.Getenv("QUAL_NIL_CARRIER_CLI_CHILD"); mode != "" {
		dir := os.Getenv("QUAL_NIL_CARRIER_CLI_DIR")
		logs := filepath.Join(dir, "logs")
		app := cli.NewApp()
		app.Flags = getFlags()
		app.Action = func(ctx *cli.Context) error {
			require.Empty(t, ctx.GlobalString(drwaStartupRecord.Name))
			return startNodeRunner(ctx, logger.GetOrCreate("qual-nil-carrier-drwa-cli"), "", "")
		}
		args := []string{"qual-nil-carrier", "--" + importDbNoSigCheck.Name,
			"--" + logSaveFile.Name, "--" + storageCleanup.Name}
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
		err := app.Run(args)
		if mode == "configured_identity" {
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			require.NoDirExists(t, logs)
		} else {
			require.EqualError(t, err, "import-db-no-sig-check can only be used with the import-db flag")
			require.DirExists(t, logs)
		}
		return
	}

	for _, mode := range []string{"configured_identity", "ordinary"} {
		t.Run(mode, func(t *testing.T) {
			dir := qualDRWANativeStartupFixtureDir(t)
			path := filepath.Join(dir, "config.toml")
			if mode == "configured_identity" {
				native, err := os.ReadFile(path)
				require.NoError(t, err)
				native = append(native, []byte("\n[GeneralSettings.DRWADeploymentIdentity]\nPath = \"/qualification-absent-identity\"\n")...)
				require.NoError(t, os.WriteFile(path, native, 0600))
			}
			loaded, err := common.LoadMainConfig(path)
			require.NoError(t, err)
			require.Equal(t, mode == "configured_identity", loaded.GeneralSettings.DRWADeploymentIdentity != nil)
			require.Empty(t, loaded.GeneralSettings.DRWAInitialProgrammeInputs)

			cmd := exec.Command(os.Args[0], "-test.run=^TestQualDRWANilCarrierConfiguredCLIRefusesBeforeNativeEffects$", "-test.v")
			cmd.Env = append(os.Environ(), "QUAL_NIL_CARRIER_CLI_CHILD="+mode, "QUAL_NIL_CARRIER_CLI_DIR="+dir)
			raw, err := cmd.CombinedOutput()
			require.NoError(t, err, "%s", raw)
			require.NoDirExists(t, filepath.Join(dir, "db"))
			if mode == "configured_identity" {
				require.NoDirExists(t, filepath.Join(dir, "logs"))
			}
		})
	}
}
