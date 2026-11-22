package node

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestQualDRWAOriginalTransportRefusesWritableBacking(t *testing.T) {
	role := filepath.Join(t.TempDir(), "validator0")
	db := filepath.Join(role, "db", "qualification")
	require.NoError(t, os.MkdirAll(db, 0700))
	// No host grant, sealed profile or native programme is supplied.
	cfg := &config.Configs{
		FlagsConfig: &config.ContextFlagsConfig{WorkingDir: role, DbDir: role},
		GeneralConfig: &config.Config{},
		ImportDbConfig: &config.ImportDbConfig{},
		DRWAInitialProgrammeStartup: &config.DRWAInitialProgrammeStartup{
			RecordDigest: [32]byte{1}, ReleaseWait: time.Millisecond, ReleaseMaxBytes: 1,
			OriginalDatabasePath: db,
		},
	}
	cfg.GeneralConfig.GeneralSettings.ChainID = "qualification"
	cfg.GeneralConfig.GeneralSettings.DRWADeploymentIdentity = &config.DRWADeploymentIdentityConfig{}
	require.NoError(t, ValidateDRWAStartupMode(cfg))
	runner, err := NewNodeRunner(cfg)
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Nil(t, runner)
	items, err := os.ReadDir(db)
	require.NoError(t, err)
	require.Empty(t, items)
}

func TestQualDRWAOriginalGrantStrictReleaseDeadline(t *testing.T) {
	// Relative timestamps are fixture inputs. The production path reads its
	// actual monotonic clock and supplies the completed read to the decision.
	deadline := time.Unix(0, 100)
	type observation struct {
		offset time.Duration
		matched bool
		err error
		accept bool
		retry bool
	}
	for _, tc := range []struct {
		name string
		reads []observation
	}{
		{"missing_then_late", []observation{{-time.Nanosecond, false, unix.ENOENT, false, true}, {time.Nanosecond, true, nil, false, false}}},
		{"read_crosses_deadline", []observation{{time.Nanosecond, true, nil, false, false}}},
		{"exactly_deadline", []observation{{0, true, nil, false, false}}},
		{"just_before", []observation{{-time.Nanosecond, true, nil, true, false}}},
		{"missing_at_deadline", []observation{{0, false, unix.ENOENT, false, false}}},
		{"malformed_before_deadline", []observation{{-time.Nanosecond, false, drwa.ErrDeploymentIdentity, false, false}}},
		{"wrong_subject_before_deadline", []observation{{-time.Nanosecond, false, nil, false, false}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, read := range tc.reads {
				accepted, retry := originalGrantReadDecision(deadline.Add(read.offset), deadline, read.matched, read.err)
				require.Equal(t, read.accept, accepted)
				require.Equal(t, read.retry, retry)
			}
		})
	}
}

func TestQualDRWAOriginalGrantNotReadForOtherModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		startup *config.DRWAInitialProgrammeStartup
		wantErr error
	}{
		{"ordinary", nil, nil},
		{"persisted", &config.DRWAInitialProgrammeStartup{Persisted: true}, drwa.ErrDeploymentIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The original acquisition would reject these deliberately absent
			// transport inputs. Neither selected constructor may consult them.
			runner, err := NewNodeRunner(&config.Configs{DRWAInitialProgrammeStartup: tc.startup})
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, runner)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, runner)
			require.Nil(t, runner.drwaOriginal)
			require.False(t, runner.drwaOriginalCycleStarted.Load())
		})
	}
}

func TestQualDRWAPersistedRunnerRefusesBeforeNativeEffects(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		identityWithoutCarrier bool
	}{
		{name: "validator"},
		{name: "observer"},
		{name: "nil_carrier_validator", identityWithoutCarrier: true},
		{name: "nil_carrier_observer", identityWithoutCarrier: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dbDir := t.TempDir()
			marker := filepath.Join(dbDir, "retained")
			require.NoError(t, os.WriteFile(marker, []byte("unchanged"), 0600))
			cfg := &config.Configs{
				FlagsConfig:   &config.ContextFlagsConfig{DbDir: dbDir, CleanupStorage: true},
				GeneralConfig: &config.Config{},
			}
			if tc.identityWithoutCarrier {
				cfg.GeneralConfig.GeneralSettings.DRWADeploymentIdentity = &config.DRWADeploymentIdentityConfig{
					Path: filepath.Join(dbDir, "must-not-open-identity"),
				}
			} else {
				cfg.DRWAInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{Persisted: true, OriginalDatabasePath: dbDir}
			}
			runner, err := NewNodeRunner(cfg)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			require.Nil(t, runner)

			// Deliberately bypass construction. No provider is set up, so
			// reaching a native opener would fail this fixture.
			r := &nodeRunner{configs: cfg}
			require.ErrorIs(t, r.Start(), drwa.ErrDeploymentIdentity)
			stop, err := r.executeOneComponentCreationCycle(nil)
			require.True(t, stop)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			require.False(t, r.drwaOriginalCycleStarted.Load())

			_, err = r.CreateManagedBootstrapComponents(nil, nil, nil, nil)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			_, err = r.CreateManagedDataComponents(nil, nil, nil, nil)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			_, err = r.CreateManagedStateComponents(nil, nil, nil)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			_, err = r.CreateManagedProcessComponents(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			_, err = r.CreateManagedCoreComponents(nil)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			_, err = r.CreateManagedStatusCoreComponents(nil)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			_, err = r.CreateManagedCryptoComponents(nil)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			_, err = r.CreateManagedNetworkComponents(nil, nil, nil)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			_, err = r.CreateManagedStatusComponents(nil, nil, nil, nil, nil, nil, false, nil)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			_, err = r.CreateManagedConsensusComponents(nil, nil, nil, nil, nil, nil, nil, nil)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			_, err = r.CreateManagedHeartbeatV2Components(nil, nil, nil, nil, nil, nil, nil)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			raw, err := os.ReadFile(marker)
			require.NoError(t, err)
			require.Equal(t, "unchanged", string(raw))
			require.NoFileExists(t, filepath.Join(dbDir, "config.toml"))
		})
	}
}
