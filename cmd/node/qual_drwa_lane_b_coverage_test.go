package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
)

func TestQualDRWALaneBStartupAnchor(t *testing.T) {
	raw := []byte("Mode = \"persisted\"\n")
	path := filepath.Join(t.TempDir(), "record.toml")
	require.NoError(t, os.WriteFile(path, raw, 0600))
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	member := drwaStartupMember{Path: path, SHA256: hash, Bytes: int64(len(raw))}
	got, pin, err := readDRWAStartupMember(member)
	require.NoError(t, err)
	require.Equal(t, raw, got)
	require.Equal(t, digest, pin)

	record, err := readDRWAStartupRecord(fmt.Sprintf("%s:%d:%s", hash, len(raw), path))
	require.NoError(t, err)
	require.Equal(t, "persisted", record.Mode)
	for _, anchor := range []string{
		fmt.Sprintf("%s:0%d:%s", hash, len(raw), path),
		fmt.Sprintf("%s:%d:%s", hash, len(raw)+1, path),
		fmt.Sprintf("%064x:%d:%s", 0, len(raw), path),
		fmt.Sprintf("%s:%d:%s", "g"+hash[1:], len(raw), path),
	} {
		record, err := readDRWAStartupRecord(anchor)
		require.ErrorIs(t, err, errDRWAStartupRecord)
		require.Nil(t, record)
	}
	record, err = readDRWAStartupRecord("")
	require.NoError(t, err)
	require.Nil(t, record)

	cfg := &config.Configs{GeneralConfig: &config.Config{}}
	require.NoError(t, bindDRWAStartupRecord(cfg, nil))
	require.Nil(t, cfg.DRWAInitialProgrammeStartup)
	cfg.GeneralConfig.GeneralSettings.DRWAInitialProgrammeInputs = []config.DRWAInitialProgrammeInput{{}}
	require.ErrorIs(t, bindDRWAStartupRecord(cfg, nil), errDRWAOriginalProvenance)
	require.Nil(t, cfg.DRWAInitialProgrammeStartup)
}

func TestQualDRWALaneBStartupRecordModeSyntax(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want error
	}{
		{name: "original syntax", body: "Mode = \"original\"\nOriginalReleaseWaitMilliseconds = 1\nOriginalReleaseMaxBytes = 64\n"},
		{name: "original bounds missing", body: "Mode = \"original\"\n", want: errDRWAOriginalProvenance},
		{name: "persisted with release bound", body: "Mode = \"persisted\"\nOriginalReleaseMaxBytes = 64\n", want: errDRWAStartupRecord},
		{name: "unknown mode", body: "Mode = \"other\"\n", want: errDRWAStartupRecord},
		{name: "unknown field", body: "Mode = \"persisted\"\nUnknown = 1\n", want: errDRWAStartupRecord},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "record.toml")
			require.NoError(t, os.WriteFile(path, []byte(tc.body), 0600))
			digest := sha256.Sum256([]byte(tc.body))
			record, err := readDRWAStartupRecord(fmt.Sprintf("%x:%d:%s", digest, len(tc.body), path))
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
				require.Nil(t, record)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, record)
			require.Equal(t, "original", record.Mode)
			require.Equal(t, int64(1), record.OriginalReleaseWaitMilliseconds)
			require.Equal(t, int64(64), record.OriginalReleaseMaxBytes)
			require.Equal(t, digest, record.recordDigest)
		})
	}
}

func TestQualDRWALaneBPersistedStartupBinding(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) drwaStartupMember {
		t.Helper()
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(body), 0600))
		digest := sha256.Sum256([]byte(body))
		return drwaStartupMember{Path: path, SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(body))}
	}
	const chainID = "qualification"
	const overlayBody = "[GeneralSettings]\n"
	const profileBody = `{"max_ever_regulated_tokens":64,"registry_proof_bytes":1048576}`
	nodes := write("nodes.json", `{"startTime":2}`)
	invalidNodes := write("invalid-nodes.json", `{}`)
	main := write("config.toml", "[GeneralSettings]\n")
	overlay := write("drwa.toml", overlayBody)
	profile := write("profile.json", profileBody)
	releaseBody := `{"profile_sha256":"` + profile.SHA256 + `"}`
	release := write("release.json", releaseBody)
	database := filepath.Join(dir, "db", chainID)
	epoch := uint32(3)
	limits := config.DRWAInitialProgrammeLimits{
		Files: 5, FileBytes: 64, AggregateBytes: 320, RecordBytes: 64,
		FieldBytes: 16, RoleBytes: 8, Members: 5, Records: 5,
		RetainedBytes: 320, NewRecordsPerEpoch: 5,
		AdmissionRole: []byte("admit"), IndependentRole: []byte("review"),
	}
	for _, tc := range []struct {
		name   string
		change func(*config.Configs, *drwaStartupRecordInput)
		want   error
	}{
		{name: "selected persisted role"},
		{name: "different chain", change: func(_ *config.Configs, r *drwaStartupRecordInput) {
			r.ChainID = "other"
		}, want: errDRWAStartupRecord},
		{name: "missing effective nodes", change: func(c *config.Configs, _ *drwaStartupRecordInput) {
			c.NodesConfig = nil
		}, want: errDRWAStartupRecord},
		{name: "missing pinned nodes", change: func(c *config.Configs, r *drwaStartupRecordInput) {
			r.Nodes.Path = filepath.Join(dir, "absent")
			c.ConfigurationPathsHolder.Nodes = r.Nodes.Path
		}, want: errDRWAStartupRecord},
		{name: "nonpositive pinned start time", change: func(c *config.Configs, r *drwaStartupRecordInput) {
			r.Nodes = invalidNodes
			c.ConfigurationPathsHolder.Nodes = invalidNodes.Path
		}, want: errDRWAStartupRecord},
		{name: "different working directory", change: func(c *config.Configs, _ *drwaStartupRecordInput) {
			c.FlagsConfig.WorkingDir = filepath.Join(dir, "other")
		}, want: errDRWAStartupRecord},
		{name: "relative effective database directory", change: func(c *config.Configs, _ *drwaStartupRecordInput) {
			c.FlagsConfig.DbDir = "db"
		}, want: errDRWAStartupRecord},
		{name: "noncanonical effective database directory", change: func(c *config.Configs, _ *drwaStartupRecordInput) {
			c.FlagsConfig.DbDir = dir + string(filepath.Separator) + "."
		}, want: errDRWAStartupRecord},
		{name: "noncanonical sealed working directory", change: func(_ *config.Configs, r *drwaStartupRecordInput) {
			r.Roles[0].WorkingDirectory += string(filepath.Separator) + "."
		}, want: errDRWAStartupRecord},
		{name: "noncanonical sealed database path", change: func(_ *config.Configs, r *drwaStartupRecordInput) {
			r.Roles[0].OriginalDatabasePath += string(filepath.Separator) + "."
		}, want: errDRWAStartupRecord},
		{name: "duplicate role working directory", change: func(_ *config.Configs, r *drwaStartupRecordInput) {
			duplicate := r.Roles[0]
			duplicate.OriginalDatabasePath = filepath.Join(dir, "other-db")
			r.Roles = append(r.Roles, duplicate)
		}, want: errDRWAStartupRecord},
		{name: "duplicate role database path", change: func(_ *config.Configs, r *drwaStartupRecordInput) {
			duplicate := r.Roles[0]
			duplicate.WorkingDirectory = filepath.Join(dir, "other")
			r.Roles = append(r.Roles, duplicate)
		}, want: errDRWAStartupRecord},
		{name: "wrong main member size", change: func(_ *config.Configs, r *drwaStartupRecordInput) {
			r.Roles[0].MainConfig.Bytes++
		}, want: errDRWAStartupRecord},
		{name: "no overlay budget", change: func(_ *config.Configs, r *drwaStartupRecordInput) {
			r.Overlay.Bytes = 0
		}, want: errDRWAStartupRecord},
		{name: "missing pinned release", change: func(_ *config.Configs, r *drwaStartupRecordInput) {
			r.Release.Path = filepath.Join(dir, "absent")
		}, want: errDRWAStartupRecord},
		{name: "missing pinned profile", change: func(_ *config.Configs, r *drwaStartupRecordInput) {
			r.Profile.Path = filepath.Join(dir, "absent")
		}, want: errDRWAStartupRecord},
		{name: "absent retention budget", change: func(_ *config.Configs, r *drwaStartupRecordInput) {
			r.Limits.RetainedBytes = 0
		}, want: config.ErrDRWAInitialProgrammeLimits},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Configs{
				GeneralConfig:            &config.Config{},
				FlagsConfig:              &config.ContextFlagsConfig{WorkingDir: dir, DbDir: dir},
				ConfigurationPathsHolder: &config.ConfigurationPathsHolder{MainConfig: main.Path, Nodes: nodes.Path, DRWA: overlay.Path},
				NodesConfig:              &config.NodesConfig{StartTime: 2},
			}
			cfg.GeneralConfig.GeneralSettings.ChainID = chainID
			cfg.GeneralConfig.EpochStartConfig.GenesisEpoch = epoch
			cfg.GeneralConfig.GeneralSettings.DRWADeploymentIdentity = &config.DRWADeploymentIdentityConfig{}
			record := drwaStartupRecordInput{
				Mode: "persisted", ChainID: chainID, GenesisEpoch: &epoch,
				Nodes: nodes, Overlay: overlay, Profile: profile, Release: release,
				Roles:                []drwaStartupRole{{WorkingDirectory: dir, OriginalDatabasePath: database, MainConfig: main}},
				MinimumMaxEverTokens: 64, MinimumRegistryProofBytes: 1048576, Limits: limits,
			}
			if tc.change != nil {
				tc.change(cfg, &record)
			}
			err := bindDRWAStartupRecord(cfg, &record)
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
				require.Nil(t, cfg.DRWAInitialProgrammeStartup)
				return
			}
			require.NoError(t, err)
			require.Equal(t, &config.DRWAInitialProgrammeStartup{
				OverlaySHA256: sha256.Sum256([]byte(overlayBody)), OverlayMaxBytes: int64(len(overlayBody)),
				Limits: limits, OriginalDatabasePath: database, Persisted: true,
				Minimum: config.DRWAMinimumGenesis{
					ProfileDigest: sha256.Sum256([]byte(profileBody)), ReleaseDigest: sha256.Sum256([]byte(releaseBody)),
					MaxEverTokens: 64, RegistryProofBytes: 1048576,
				},
			}, cfg.DRWAInitialProgrammeStartup)
		})
	}
}

type qualLaneBLogLifetime struct {
	duration time.Duration
	sizeMB   uint64
	err      error
}

func (l *qualLaneBLogLifetime) ChangeFileLifeSpan(duration time.Duration, sizeMB uint64) error {
	l.duration = duration
	l.sizeMB = sizeMB
	return l.err
}

func (l *qualLaneBLogLifetime) Close() error         { return nil }
func (l *qualLaneBLogLifetime) IsInterfaceNil() bool { return l == nil }

func TestQualDRWALaneBLogLifetime(t *testing.T) {
	require.NoError(t, configureLogLifetime(nil, nil))
	refused := errors.New("log lifetime refused")
	logger := &qualLaneBLogLifetime{err: refused}
	cfg := &config.Configs{GeneralConfig: &config.Config{
		Logs: config.LogsConfig{LogFileLifeSpanInSec: 3, LogFileLifeSpanInMB: 7},
	}}
	require.ErrorIs(t, configureLogLifetime(logger, cfg), refused)
	require.Equal(t, 3*time.Second, logger.duration)
	require.Equal(t, uint64(7), logger.sizeMB)
}
