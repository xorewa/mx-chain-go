//go:build linux

package node

import (
	"crypto/sha256"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	mainFactory "github.com/multiversx/mx-chain-go/factory"
	factoryMocks "github.com/multiversx/mx-chain-go/node/mock/factory"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestQualDRWALaneBOriginalStoreObservation(t *testing.T) {
	dir := t.TempDir()
	info, err := os.Stat(dir)
	require.NoError(t, err)
	dirMount, err := readOriginalDirectory(dir)
	require.NoError(t, err)
	require.NotZero(t, dirMount.mount)
	require.False(t, dirMount.readonly)
	require.NoError(t, recheckOriginalStore(&acquiredDRWAOriginal{path: dir, store: dirMount}))
	_, err = readOriginalDirectory(filepath.Join(dir, "absent"))
	require.ErrorIs(t, err, unix.ENOENT)
	require.ErrorIs(t, recheckOriginalStore(&acquiredDRWAOriginal{path: t.TempDir(), store: dirMount}), drwa.ErrDeploymentIdentity)

	// Observation of an empty directory confers no role grant.
	path := filepath.Join(dir, "ordinary")
	require.NoError(t, os.WriteFile(path, []byte("ordinary"), 0600))
	stillThere, err := os.Stat(dir)
	require.NoError(t, err)
	require.True(t, os.SameFile(info, stillThere))
	require.ErrorIs(t, recheckOriginalStore(&acquiredDRWAOriginal{path: dir, store: dirMount}), drwa.ErrDeploymentIdentity)
	acquired := &acquiredDRWAOriginal{path: dir, store: dirMount}
	require.ErrorIs(t, acquired.consume(), drwa.ErrDeploymentIdentity)
	require.True(t, acquired.used.Load())
	require.ErrorIs(t, acquired.consume(), drwa.ErrDeploymentIdentity)
	var missing *acquiredDRWAOriginal
	require.ErrorIs(t, missing.consume(), drwa.ErrDeploymentIdentity)

	file, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	_, err = statOriginalMount(int(file.Fd()), true)
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	_, err = statOriginalMount(-1, false)
	require.ErrorIs(t, err, unix.EBADF)
}

func TestQualDRWALaneBOriginalProcessObservation(t *testing.T) {
	identity, err := originalSubject()
	require.NoError(t, err)
	require.Equal(t, os.Getpid(), identity.PID)
	require.Equal(t, os.Geteuid(), identity.UID)
	require.Equal(t, os.Getegid(), identity.GID)
	require.NotZero(t, identity.StartTicks)
	for ns, observed := range map[string]string{
		"pid": identity.PIDNS, "mnt": identity.MountNS, "user": identity.UserNS, "net": identity.NetNS,
	} {
		want, err := os.Readlink("/proc/self/ns/" + ns)
		require.NoError(t, err)
		require.Equal(t, want, observed)
	}
}

func TestQualDRWALaneBOriginalGrantRequiresReadonlyMember(t *testing.T) {
	dir := t.TempDir()
	directory, err := os.Open(dir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, directory.Close()) })
	fd := int(directory.Fd())
	mount, err := statOriginalMount(fd, true)
	require.NoError(t, err)
	require.False(t, mount.readonly)

	const name = "qualification"
	const limit = 64
	grant, err := readOriginalRoleGrant(fd, name, mount.mount, limit)
	require.ErrorIs(t, err, unix.ENOENT)
	require.Equal(t, originalRoleGrant{}, grant)

	path := filepath.Join(dir, name+".json")
	require.NoError(t, os.Mkdir(path, 0700))
	grant, err = readOriginalRoleGrant(fd, name, mount.mount, limit)
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Equal(t, originalRoleGrant{}, grant)

	require.NoError(t, os.Remove(path))
	require.NoError(t, os.WriteFile(path, []byte("{}\n"), 0600))
	grant, err = readOriginalRoleGrant(fd, name, mount.mount, limit)
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Equal(t, originalRoleGrant{}, grant)

	for _, tc := range []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"over limit", limit + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(path, make([]byte, tc.size), 0600))
			grant, err := readOriginalRoleGrant(fd, name, mount.mount, limit)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			require.Equal(t, originalRoleGrant{}, grant)
		})
	}
	t.Run("symlink", func(t *testing.T) {
		target := filepath.Join(dir, "ordinary.json")
		require.NoError(t, os.WriteFile(target, []byte("{}\n"), 0600))
		require.NoError(t, os.Remove(path))
		require.NoError(t, os.Symlink(target, path))
		grant, err := readOriginalRoleGrant(fd, name, mount.mount, limit)
		require.ErrorIs(t, err, unix.ELOOP)
		require.Equal(t, originalRoleGrant{}, grant)
	})
}

func TestQualDRWALaneBStartupMode(t *testing.T) {
	require.ErrorIs(t, ValidateDRWAStartupMode(nil), drwa.ErrDeploymentIdentity)
	cfg := &config.Configs{GeneralConfig: &config.Config{}}
	require.NoError(t, ValidateDRWAStartupMode(cfg))

	cfg.GeneralConfig.GeneralSettings.DRWADeploymentIdentity = &config.DRWADeploymentIdentityConfig{}
	require.ErrorIs(t, ValidateDRWAStartupMode(cfg), drwa.ErrDeploymentIdentity)
	cfg.DRWAInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{Persisted: true}
	require.ErrorIs(t, ValidateDRWAStartupMode(cfg), drwa.ErrDeploymentIdentity)

	// This mode check does not admit the original identity or grant startup.
	cfg.DRWAInitialProgrammeStartup.Persisted = false
	require.NoError(t, ValidateDRWAStartupMode(cfg))
}

func TestQualDRWALaneBOriginalAcquisitionPreconditions(t *testing.T) {
	root := t.TempDir()
	role := filepath.Join(root, "observer-qualification")
	require.NoError(t, os.Mkdir(role, 0700))
	const chain = "qualification"

	for _, tc := range []struct {
		name   string
		change func(*config.Configs)
	}{
		{"missing-flags", func(cfg *config.Configs) { cfg.FlagsConfig = nil }},
		{"missing-general", func(cfg *config.Configs) { cfg.GeneralConfig = nil }},
		{"missing-import", func(cfg *config.Configs) { cfg.ImportDbConfig = nil }},
		{"cleanup", func(cfg *config.Configs) { cfg.FlagsConfig.CleanupStorage = true }},
		{"force-network", func(cfg *config.Configs) { cfg.FlagsConfig.ForceStartFromNetwork = true }},
		{"gops", func(cfg *config.Configs) { cfg.FlagsConfig.EnableGops = true }},
		{"import", func(cfg *config.Configs) { cfg.ImportDbConfig.IsImportDBMode = true }},
		{"after-hardfork", func(cfg *config.Configs) { cfg.GeneralConfig.Hardfork.AfterHardFork = true }},
		{"hardfork-recovery", func(cfg *config.Configs) { cfg.GeneralConfig.HardforkRecoveryCheckpoint.Enabled = true }},
		{"missing-identity", func(cfg *config.Configs) { cfg.GeneralConfig.GeneralSettings.DRWADeploymentIdentity = nil }},
		{"missing-record-digest", func(cfg *config.Configs) { cfg.DRWAInitialProgrammeStartup.RecordDigest = [32]byte{} }},
		{"zero-wait", func(cfg *config.Configs) { cfg.DRWAInitialProgrammeStartup.ReleaseWait = 0 }},
		{"zero-file-limit", func(cfg *config.Configs) { cfg.DRWAInitialProgrammeStartup.ReleaseMaxBytes = 0 }},
		{"overflowing-file-limit", func(cfg *config.Configs) {
			cfg.DRWAInitialProgrammeStartup.ReleaseMaxBytes = math.MaxInt64
		}},
		{"relative-work-path", func(cfg *config.Configs) {
			cfg.FlagsConfig.WorkingDir = "observer-qualification"
			cfg.FlagsConfig.DbDir = cfg.FlagsConfig.WorkingDir
		}},
		{"unclean-work-path", func(cfg *config.Configs) {
			cfg.FlagsConfig.WorkingDir = role + string(filepath.Separator) + "."
			cfg.FlagsConfig.DbDir = cfg.FlagsConfig.WorkingDir
		}},
		{"split-work-and-store-path", func(cfg *config.Configs) { cfg.FlagsConfig.DbDir = root }},
		{"ordinary-role", func(cfg *config.Configs) {
			cfg.FlagsConfig.WorkingDir = root
			cfg.FlagsConfig.DbDir = root
		}},
		{"other-store", func(cfg *config.Configs) { cfg.DRWAInitialProgrammeStartup.OriginalDatabasePath = root }},
		{"writable-role", func(_ *config.Configs) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Configs{
				GeneralConfig:  &config.Config{},
				FlagsConfig:    &config.ContextFlagsConfig{WorkingDir: role, DbDir: role},
				ImportDbConfig: &config.ImportDbConfig{},
				DRWAInitialProgrammeStartup: &config.DRWAInitialProgrammeStartup{
					RecordDigest: [32]byte{1}, ReleaseWait: time.Second, ReleaseMaxBytes: 64,
					OriginalDatabasePath: filepath.Join(role, storage.DefaultDBPath, chain),
				},
			}
			cfg.GeneralConfig.GeneralSettings.ChainID = chain
			cfg.GeneralConfig.GeneralSettings.DRWADeploymentIdentity = &config.DRWADeploymentIdentityConfig{}
			tc.change(cfg)
			acquiredBefore := drwaOriginalProcessAcquired.Load()
			got, err := acquireDRWAOriginal(cfg)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			require.Nil(t, got)
			require.Equal(t, acquiredBefore, drwaOriginalProcessAcquired.Load())
		})
	}
}

func TestQualDRWALaneBManagedStartupProviderBoundaries(t *testing.T) {
	cfg := &config.Configs{GeneralConfig: &config.Config{}}
	check := func(components mainFactory.CoreComponentsHolder, want error) {
		t.Helper()
		programmes, startup, candidate, err := loadManagedInitialProgrammeData(cfg, components)
		require.ErrorIs(t, err, want)
		require.Nil(t, programmes)
		require.Nil(t, startup)
		require.Nil(t, candidate)
	}
	check(nil, nil)
	cfg.DRWAInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{
		Persisted: true,
		Limits:    *qualStageALimits(),
		Minimum: config.DRWAMinimumGenesis{
			ProfileDigest: [32]byte{1}, ReleaseDigest: [32]byte{2},
			MaxEverTokens: 1, RegistryProofBytes: 1,
		},
	}
	check(nil, drwa.ErrDeploymentIdentity)

	dir := t.TempDir()
	overlay := filepath.Join(dir, "drwa.toml")
	cfg.ConfigurationPathsHolder = &config.ConfigurationPathsHolder{DRWA: overlay}
	cfg.DRWAInitialProgrammeStartup.OriginalDatabasePath = filepath.Join(dir, "unopened-store")
	cfg.GeneralConfig.GeneralSettings.DRWADeploymentIdentity = &config.DRWADeploymentIdentityConfig{}
	check(nil, ErrNilCoreComponents)

	components := &factoryMocks.CoreComponentsMock{}
	check(components, core.ErrNilMarshalizer)
	components.IntMarsh = &marshal.GogoProtoMarshalizer{}
	check(components, core.ErrNilHasher)
	components.Hash = blake2b.NewBlake2b()

	raw := []byte("# no enforcement epoch\n")
	require.NoError(t, os.WriteFile(overlay, raw, 0600))
	cfg.DRWAInitialProgrammeStartup.OverlaySHA256 = sha256.Sum256(raw)
	cfg.DRWAInitialProgrammeStartup.OverlayMaxBytes = int64(len(raw))
	programmes, startup, candidate, err := loadManagedInitialProgrammeData(cfg, components)
	require.EqualError(t, err, "missing DRWAEnforcementEnableEpoch")
	require.Nil(t, programmes)
	require.Nil(t, startup)
	require.Nil(t, candidate)

	configDir := filepath.Join("..", "cmd", "node", "config")
	cfg.GeneralConfig, err = common.LoadMainConfig(filepath.Join(configDir, "config.toml"))
	require.NoError(t, err)
	cfg.EpochConfig, err = common.LoadEpochConfig(filepath.Join(configDir, "enableEpochs.toml"))
	require.NoError(t, err)
	cfg.RoundConfig, err = common.LoadRoundConfig(filepath.Join(configDir, "enableRounds.toml"))
	require.NoError(t, err)
	cfg.EconomicsConfig, err = common.LoadEconomicsConfig(filepath.Join(configDir, "economics.toml"))
	require.NoError(t, err)
	cfg.RatingsConfig, err = common.LoadRatingsConfig(filepath.Join(configDir, "ratings.toml"))
	require.NoError(t, err)
	cfg.GeneralConfig.GeneralSettings.DRWADeploymentIdentity = &config.DRWADeploymentIdentityConfig{}
	raw = []byte("DRWAEnforcementEnableEpoch = 3\n")
	require.NoError(t, os.WriteFile(overlay, raw, 0600))
	overlayPin := sha256.Sum256(raw)
	cfg.DRWAInitialProgrammeStartup.OverlaySHA256 = overlayPin
	cfg.DRWAInitialProgrammeStartup.OverlayMaxBytes = int64(len(raw))

	programmes, startup, candidate, err = loadManagedInitialProgrammeData(cfg, components)
	require.NoError(t, err)
	require.Nil(t, programmes)
	require.Equal(t, cfg.DRWAInitialProgrammeStartup, startup)
	require.NotSame(t, cfg.DRWAInitialProgrammeStartup, startup)
	require.True(t, candidate.MatchesPinnedOverlay(overlay, overlayPin))

	// Use the existing synthetic programme only to observe the data loader.
	cfg.DRWAInitialProgrammeStartup.Persisted = false
	data := qualStageARaw(t)
	path := filepath.Join(dir, "programme")
	require.NoError(t, os.WriteFile(path, data, 0600))
	cfg.GeneralConfig.GeneralSettings.DRWAInitialProgrammeInputs = []config.DRWAInitialProgrammeInput{{
		Path: path, SHA256: fmt.Sprintf("%x", sha256.Sum256(data)),
	}}
	programmes, startup, candidate, err = loadManagedInitialProgrammeData(cfg, components)
	require.NoError(t, err)
	require.Len(t, programmes, 1)
	require.Equal(t, data, programmes[0].Raw())
	require.Equal(t, cfg.DRWAInitialProgrammeStartup, startup)
	require.True(t, candidate.MatchesPinnedOverlay(overlay, overlayPin))
}
