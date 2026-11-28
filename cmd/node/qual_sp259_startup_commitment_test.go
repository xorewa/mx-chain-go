package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
)

func TestQualSP259PinnedPredecessorConfiguration(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) drwaStartupMember {
		t.Helper()
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, data, 0600))
		return drwaStartupMember{Path: path, SHA256: fmt.Sprintf("%x", sha256.Sum256(data)), Bytes: int64(len(data))}
	}
	const chain = "qualification"
	var epoch uint32 = 3
	programme := config.DRWAInitialProgrammeInput{Path: filepath.Join(dir, "programme"), SHA256: fmt.Sprintf("%064x", 1)}
	base := []byte("[GeneralSettings]\nChainID = 'qualification'\n[[HardforkRoundExclusions]]\nStartRound=10\nEndRound=20\n")
	originalMain := write("original.toml", append(append([]byte(nil), base...), []byte(fmt.Sprintf("\n[[GeneralSettings.DRWAInitialProgrammeInputs]]\nPath=%q\nSHA256=%q\n", programme.Path, programme.SHA256))...))
	persistedMain := write("persisted.toml", base)
	otherMain := write("different.toml", []byte("[GeneralSettings]\nChainID='different'\n"))
	badMain := write("invalid.toml", []byte("[invalid"))
	role := drwaStartupRole{WorkingDirectory: dir, OriginalDatabasePath: filepath.Join(dir, "db", chain), MainConfig: originalMain}
	nodes := write("nodes.json", []byte(`{"startTime":2}`))
	overlay := write("overlay.toml", []byte("[GeneralSettings]\n"))
	profile := write("profile.json", []byte(`{"max_ever_regulated_tokens":64,"registry_proof_bytes":1048576}`))
	release := write("release.json", []byte(`{"profile_sha256":"`+profile.SHA256+`"}`))
	limits := config.DRWAInitialProgrammeLimits{Files: 5, FileBytes: 64, AggregateBytes: 320, RecordBytes: 64, FieldBytes: 16, RoleBytes: 8, Members: 5, Records: 5, RetainedBytes: 320, NewRecordsPerEpoch: 5, AdmissionRole: []byte("admit"), IndependentRole: []byte("review")}
	original := drwaStartupRecordInput{Mode: "original", ChainID: chain, GenesisEpoch: &epoch, Roles: []drwaStartupRole{role}, Programmes: []config.DRWAInitialProgrammeInput{programme}, OriginalReleaseWaitMilliseconds: 1, OriginalReleaseMaxBytes: 64, Nodes: nodes, Overlay: overlay, Profile: profile, Release: release, MinimumMaxEverTokens: 64, MinimumRegistryProofBytes: 1048576, Limits: limits}
	makeRecord := func(name string, rec drwaStartupRecordInput) drwaStartupMember {
		t.Helper()
		raw, err := toml.Marshal(rec)
		require.NoError(t, err)
		return write(name, raw)
	}
	prior := makeRecord("original-record.toml", original)
	current := original
	current.Mode, current.Predecessor, current.Programmes = "persisted", prior, nil
	current.OriginalReleaseWaitMilliseconds, current.OriginalReleaseMaxBytes = 0, 0
	current.Roles = []drwaStartupRole{{WorkingDirectory: dir, OriginalDatabasePath: role.OriginalDatabasePath, MainConfig: persistedMain}}
	member := makeRecord("persisted-record.toml", current)
	parsedCurrent, err := readDRWAStartupRecord(fmt.Sprintf("%s:%d:%s", member.SHA256, member.Bytes, member.Path))
	require.NoError(t, err)
	current = *parsedCurrent
	cfg := &config.Configs{FlagsConfig: &config.ContextFlagsConfig{WorkingDir: dir, DbDir: dir},
		GeneralConfig: &config.Config{}, ConfigurationPathsHolder: &config.ConfigurationPathsHolder{MainConfig: persistedMain.Path, Nodes: nodes.Path, DRWA: overlay.Path}, NodesConfig: &config.NodesConfig{StartTime: 2}}
	cfg.GeneralConfig.GeneralSettings.ChainID = chain
	cfg.GeneralConfig.GeneralSettings.DRWADeploymentIdentity = &config.DRWADeploymentIdentityConfig{}
	cfg.GeneralConfig.EpochStartConfig.GenesisEpoch = epoch
	cfg.GeneralConfig.HardforkRoundExclusions = []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 20}}
	parsed, err := readDRWAStartupRecord(fmt.Sprintf("%s:%d:%s", prior.SHA256, prior.Bytes, prior.Path))
	require.NoError(t, err)
	require.Equal(t, original.Programmes, parsed.Programmes)
	current.Limits = parsed.Limits
	chosen, err := selectDRWAStartupRole(parsed.Roles, cfg.FlagsConfig, chain, role.MainConfig.Path)
	require.NoError(t, err)
	_, err = startupConfiguration(parsed, chosen)
	require.NoError(t, err)
	previous, err := predecessorConfiguration(cfg, &current)
	require.NoError(t, err)
	require.NotZero(t, previous.RecordDigest)
	selected, err := startupConfiguration(&current, &drwaStartupRole{MainConfig: persistedMain})
	require.NoError(t, err)
	require.NotEqual(t, selected.MainConfigDigest, previous.MainConfigDigest)
	require.Equal(t, selected.RestartConfigDigest, previous.RestartConfigDigest)
	require.Equal(t, selected.Exclusions, previous.Exclusions)
	require.NoError(t, bindDRWAStartupRecord(cfg, &current))
	require.Equal(t, previous, cfg.DRWAInitialProgrammeStartup.PredecessorConfiguration)
	require.Equal(t, selected, cfg.DRWAInitialProgrammeStartup.SelectedConfiguration)
	cfg.GeneralConfig.HardforkRoundExclusions = nil
	require.ErrorIs(t, bindDRWAStartupRecord(cfg, &current), errDRWAStartupRecord)
	cfg.GeneralConfig.HardforkRoundExclusions = selected.Exclusions
	badRestart := current
	badRestart.Predecessor = drwaStartupMember{}
	cfg.DRWAInitialProgrammeStartup = nil
	require.ErrorIs(t, bindDRWAStartupRecord(cfg, &badRestart), errDRWAStartupRecord)
	require.Nil(t, cfg.DRWAInitialProgrammeStartup)
	changed, err := startupConfiguration(&current, &drwaStartupRole{MainConfig: otherMain})
	require.NoError(t, err)
	require.NotEqual(t, selected.RestartConfigDigest, changed.RestartConfigDigest)
	for _, main := range []drwaStartupMember{badMain, originalMain, {Path: filepath.Join(dir, "absent")}} {
		_, err := startupConfiguration(&current, &drwaStartupRole{MainConfig: main})
		require.Error(t, err)
	}
	for _, change := range []func(*drwaStartupRecordInput){
		func(r *drwaStartupRecordInput) { r.Predecessor = drwaStartupMember{} },
		func(r *drwaStartupRecordInput) { r.ChainID = "other" },
		func(r *drwaStartupRecordInput) { r.GenesisEpoch = nil },
	} {
		bad := current
		change(&bad)
		_, err := predecessorConfiguration(cfg, &bad)
		require.Error(t, err)
	}
	cfg.FlagsConfig.WorkingDir = filepath.Join(dir, "different")
	_, err = predecessorConfiguration(cfg, &current)
	require.Error(t, err)
}
