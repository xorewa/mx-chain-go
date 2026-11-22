package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/multiversx/mx-chain-go/config"
	coreFactory "github.com/multiversx/mx-chain-go/factory/core"
	"github.com/multiversx/mx-chain-go/process/drwa"
	storageFactory "github.com/multiversx/mx-chain-go/storage/factory"
	"github.com/pelletier/go-toml"
)

var (
	errDRWAStartupRecord      = errors.New("invalid pinned DRWA startup record")
	errDRWAOriginalProvenance = errors.New("original DRWA generation provenance unavailable")
)

// These types are the proposed local synthetic startup transport. They are not
// a protocol frame, a release commitment algorithm, or an authority provider.
type drwaStartupMember struct {
	Path   string
	SHA256 string
	Bytes  int64
}

type drwaStartupRole struct {
	WorkingDirectory, OriginalDatabasePath string
	MainConfig drwaStartupMember
}

type drwaStartupRecordInput struct {
	OriginalReleaseWaitMilliseconds int64
	OriginalReleaseMaxBytes        int64
	recordDigest [32]byte
	Mode, ChainID                     string
	GenesisEpoch                      *uint32
	Nodes, Overlay, Profile, Release         drwaStartupMember
	Roles                             []drwaStartupRole
	MinimumMaxEverTokens, MinimumRegistryProofBytes uint64
	Limits config.DRWAInitialProgrammeLimits
	Programmes []config.DRWAInitialProgrammeInput
	Identity config.DRWADeploymentIdentityConfig
}

func drwaStartupDigest(text string) ([32]byte, error) {
	var value [32]byte
	digest, err := hex.DecodeString(text)
	if err != nil || len(digest) != len(value) || hex.EncodeToString(digest) != text {
		return value, errDRWAStartupRecord
	}
	copy(value[:], digest)
	if value == [32]byte{} {
		return value, errDRWAStartupRecord
	}
	return value, nil
}

func readDRWAStartupMember(member drwaStartupMember) ([]byte, [32]byte, error) {
	digest, err := drwaStartupDigest(member.SHA256)
	if err != nil {
		return nil, digest, err
	}
	raw, err := coreFactory.ReadDRWAPinnedStartupInput(member.Path, digest, member.Bytes)
	if err != nil || int64(len(raw)) != member.Bytes {
		return nil, digest, errDRWAStartupRecord
	}
	return raw, digest, nil
}

// selectDRWAStartupRole binds the chosen sealed role to the path the native
// core will use after the CLI has applied any working or database directory flag.
func selectDRWAStartupRole(roles []drwaStartupRole, flags *config.ContextFlagsConfig, chainID, mainConfig string) (*drwaStartupRole, error) {
	if !filepath.IsAbs(flags.DbDir) || filepath.Clean(flags.DbDir) != flags.DbDir {
		return nil, errDRWAStartupRecord
	}
	paths, err := storageFactory.CreatePathManager(storageFactory.ArgCreatePathManager{
		WorkingDir: flags.DbDir, ChainID: chainID,
	})
	if err != nil {
		return nil, err
	}

	var selected *drwaStartupRole
	workingDirs := make(map[string]struct{}, len(roles))
	databasePaths := make(map[string]struct{}, len(roles))
	for i := range roles {
		entry := &roles[i]
		if !filepath.IsAbs(entry.WorkingDirectory) || filepath.Clean(entry.WorkingDirectory) != entry.WorkingDirectory ||
			!filepath.IsAbs(entry.OriginalDatabasePath) || filepath.Clean(entry.OriginalDatabasePath) != entry.OriginalDatabasePath {
			return nil, errDRWAStartupRecord
		}
		if _, used := workingDirs[entry.WorkingDirectory]; used {
			return nil, errDRWAStartupRecord
		}
		if _, used := databasePaths[entry.OriginalDatabasePath]; used {
			return nil, errDRWAStartupRecord
		}
		workingDirs[entry.WorkingDirectory] = struct{}{}
		databasePaths[entry.OriginalDatabasePath] = struct{}{}
		if entry.WorkingDirectory == flags.WorkingDir {
			selected = entry
		}
	}
	if selected == nil || selected.MainConfig.Path != mainConfig || selected.OriginalDatabasePath != paths.DatabasePath() {
		return nil, errDRWAStartupRecord
	}
	return selected, nil
}

func matchDRWAStartupNodes(cfg *config.Configs, member drwaStartupMember) error {
	if cfg.NodesConfig == nil || cfg.GeneralConfig.Hardfork.AfterHardFork ||
		member.Path != cfg.ConfigurationPathsHolder.Nodes {
		return errDRWAStartupRecord
	}
	raw, _, err := readDRWAStartupMember(member)
	if err != nil {
		return err
	}
	var sealed config.NodesConfig
	if err = json.Unmarshal(raw, &sealed); err != nil || sealed.StartTime <= 0 || !reflect.DeepEqual(&sealed, cfg.NodesConfig) {
		return errDRWAStartupRecord
	}
	return nil
}

// checkDRWAStartupDeclaration checks one pinned outer object and just the
// exact keys this ingress interprets. Unconsumed values keep their native shape.
func checkDRWAStartupDeclaration(raw []byte, required ...string) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errDRWAStartupRecord
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return errDRWAStartupRecord
		}
		if _, duplicate := seen[key]; duplicate {
			return errDRWAStartupRecord
		}
		seen[key] = struct{}{}
		for _, field := range required {
			if key != field && strings.EqualFold(key, field) {
				return errDRWAStartupRecord
			}
		}
		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil {
			return errDRWAStartupRecord
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return errDRWAStartupRecord
	}
	if _, err = decoder.Token(); err != io.EOF {
		return errDRWAStartupRecord
	}
	for _, field := range required {
		if _, ok := seen[field]; !ok {
			return errDRWAStartupRecord
		}
	}
	return nil
}

// readDRWAStartupMinimum joins the sealed experimental profile and release
// declarations to the exact typed operands the native genesis path consumes.
func readDRWAStartupMinimum(record drwaStartupRecordInput) (config.DRWAMinimumGenesis, error) {
	var minimum config.DRWAMinimumGenesis
	profile, profileDigest, err := readDRWAStartupMember(record.Profile)
	if err != nil {
		return minimum, err
	}
	release, releaseDigest, err := readDRWAStartupMember(record.Release)
	if err != nil {
		return minimum, err
	}
	if checkDRWAStartupDeclaration(profile, "max_ever_regulated_tokens", "registry_proof_bytes") != nil ||
		checkDRWAStartupDeclaration(release, "profile_sha256") != nil {
		return minimum, errDRWAStartupRecord
	}
	var selected struct {
		MaxEverTokens      *uint64 `json:"max_ever_regulated_tokens"`
		RegistryProofBytes *uint64 `json:"registry_proof_bytes"`
	}
	var linked struct {
		ProfileSHA256 *string `json:"profile_sha256"`
	}
	if json.Unmarshal(profile, &selected) != nil || json.Unmarshal(release, &linked) != nil ||
		linked.ProfileSHA256 == nil || *linked.ProfileSHA256 != hex.EncodeToString(profileDigest[:]) ||
		selected.MaxEverTokens == nil || *selected.MaxEverTokens != record.MinimumMaxEverTokens ||
		selected.RegistryProofBytes == nil || *selected.RegistryProofBytes != record.MinimumRegistryProofBytes {
		return minimum, errDRWAStartupRecord
	}
	minimum = config.DRWAMinimumGenesis{
		ProfileDigest: profileDigest, ReleaseDigest: releaseDigest,
		MaxEverTokens: *selected.MaxEverTokens, RegistryProofBytes: *selected.RegistryProofBytes,
	}
	if err = drwa.ValidateInitialProgrammeMinimum(minimum); err != nil {
		return config.DRWAMinimumGenesis{}, err
	}
	return minimum, nil
}

// Read before logging or startup. A pinned file and an empty adapter
// cannot prove first use of the selected backing store across processes.
func readDRWAStartupRecord(anchor string) (*drwaStartupRecordInput, error) {
	if anchor == "" {
		return nil, nil
	}
	hash, remainder, found := strings.Cut(anchor, ":")
	size, path, restFound := strings.Cut(remainder, ":")
	limit, err := strconv.ParseInt(size, 10, 64)
	if !found || !restFound || err != nil || limit <= 0 || strconv.FormatInt(limit, 10) != size {
		return nil, errDRWAStartupRecord
	}
	raw, digest, err := readDRWAStartupMember(drwaStartupMember{Path: path, SHA256: hash, Bytes: limit})
	if err != nil {
		return nil, err
	}
	var record drwaStartupRecordInput
	if err = toml.NewDecoder(bytes.NewReader(raw)).Strict(true).Decode(&record); err != nil {
		return nil, errDRWAStartupRecord
	}
	switch record.Mode {
	case "original":
		const maxMillis = int64(1<<63-1) / int64(time.Millisecond)
		if record.OriginalReleaseWaitMilliseconds <= 0 || record.OriginalReleaseWaitMilliseconds > maxMillis ||
			record.OriginalReleaseMaxBytes <= 0 || record.OriginalReleaseMaxBytes == int64(1<<63-1) {
			return nil, errDRWAOriginalProvenance
		}
		record.recordDigest = digest
		return &record, nil
	case "persisted":
		if record.OriginalReleaseWaitMilliseconds != 0 || record.OriginalReleaseMaxBytes != 0 {
			return nil, errDRWAStartupRecord
		}
		return &record, nil
	default:
		return nil, errDRWAStartupRecord
	}
}

func bindDRWAStartupRecord(cfg *config.Configs, record *drwaStartupRecordInput) error {
	if record == nil {
		if cfg != nil && cfg.GeneralConfig != nil && len(cfg.GeneralConfig.GeneralSettings.DRWAInitialProgrammeInputs) != 0 {
			return errDRWAOriginalProvenance
		}
		return nil
	}
	original := record.Mode == "original"
	if !original && record.Mode != "persisted" || original != (len(record.Programmes) != 0) {
		return errDRWAStartupRecord
	}
	if cfg == nil || cfg.GeneralConfig == nil || cfg.FlagsConfig == nil || cfg.ConfigurationPathsHolder == nil ||
		record.ChainID == "" || record.ChainID != cfg.GeneralConfig.GeneralSettings.ChainID ||
		record.GenesisEpoch == nil || *record.GenesisEpoch != cfg.GeneralConfig.EpochStartConfig.GenesisEpoch ||
		record.Overlay.Path != cfg.ConfigurationPathsHolder.DRWA ||
		!reflect.DeepEqual(&record.Identity, cfg.GeneralConfig.GeneralSettings.DRWADeploymentIdentity) ||
		!reflect.DeepEqual(record.Programmes, cfg.GeneralConfig.GeneralSettings.DRWAInitialProgrammeInputs) {
		return errDRWAStartupRecord
	}
	if err := matchDRWAStartupNodes(cfg, record.Nodes); err != nil {
		return err
	}
	selected, err := selectDRWAStartupRole(record.Roles, cfg.FlagsConfig, record.ChainID, cfg.ConfigurationPathsHolder.MainConfig)
	if err != nil {
		return err
	}
	if _, _, err = readDRWAStartupMember(selected.MainConfig); err != nil {
		return err
	}
	overlayPin, err := drwaStartupDigest(record.Overlay.SHA256)
	if err != nil || record.Overlay.Bytes <= 0 {
		return errDRWAStartupRecord
	}
	// The actual managed consumer reads and validates this overlay once. The
	// manifest pins the exact member outside the operator's mutable fields.
	minimum, err := readDRWAStartupMinimum(*record)
	if err != nil {
		return err
	}
	if err = record.Limits.Validate(); err != nil {
		return err
	}
	cfg.DRWAInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{
		OverlaySHA256: overlayPin, OverlayMaxBytes: record.Overlay.Bytes,
		Limits: record.Limits, Minimum: minimum,
		OriginalDatabasePath: selected.OriginalDatabasePath, Persisted: !original,
		RecordDigest: record.recordDigest, ReleaseWait: time.Duration(record.OriginalReleaseWaitMilliseconds) * time.Millisecond,
		ReleaseMaxBytes: record.OriginalReleaseMaxBytes,
	}
	return nil
}
