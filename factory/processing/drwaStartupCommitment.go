package processing

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"

	"github.com/multiversx/mx-chain-go/config"
	factoryCore "github.com/multiversx/mx-chain-go/factory/core"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// Local deployment identity unit, not a protocol record or recovery authority.
// Fixed-width digests bind the original sealed startup record, its selected
// role configuration, exact exclusions, database path and retained identity.
const drwaStartupCommitmentKey = "DRWA_STARTUP_CONFIG_COMMITMENT_V1"

func validStartupConfiguration(c *config.DRWAStartupConfiguration) bool {
	return c != nil && c.RecordDigest != [32]byte{} && c.MainConfigDigest != [32]byte{} && c.RestartConfigDigest != [32]byte{}
}

func startupCommitment(c *config.DRWAStartupConfiguration, identity []byte, path string) []byte {
	if !validStartupConfiguration(c) || len(identity) == 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil
	}
	identityDigest := sha256.Sum256(identity)
	pathDigest := sha256.Sum256([]byte(path))
	exclusionHash := sha256.New()
	var interval [16]byte
	for _, item := range c.Exclusions {
		binary.BigEndian.PutUint64(interval[:8], item.StartRound)
		binary.BigEndian.PutUint64(interval[8:], item.EndRound)
		_, _ = exclusionHash.Write(interval[:])
	}
	value := make([]byte, 0, 6*sha256.Size)
	value = append(value, c.RecordDigest[:]...)
	value = append(value, c.MainConfigDigest[:]...)
	value = append(value, c.RestartConfigDigest[:]...)
	value = append(value, identityDigest[:]...)
	value = append(value, pathDigest[:]...)
	return append(value, exclusionHash.Sum(nil)...)
}

// CheckDRWAStartupHistory checks the effective loaded configuration against
// the selected pinned input. A persisted restart admits only the original
// package's configuration; a changed deployment needs separate governance.
func CheckDRWAStartupHistory(startup *config.DRWAInitialProgrammeStartup, proposed *config.Config) error {
	if startup == nil || proposed == nil || !validStartupConfiguration(startup.SelectedConfiguration) ||
		proposed.Hardfork.AfterHardFork || proposed.HardforkRecoveryCheckpoint.Enabled ||
		startup.SelectedConfiguration.RecordDigest != startup.RecordDigest ||
		!slices.Equal(startup.SelectedConfiguration.Exclusions, proposed.HardforkRoundExclusions) {
		return drwa.ErrDeploymentIdentity
	}
	if !startup.Persisted {
		if startup.PredecessorConfiguration != nil {
			return drwa.ErrDeploymentIdentity
		}
		return factoryCore.CheckDRWAExclusionHistory(nil, proposed, factoryCore.DRWAExclusionHistoryOriginalGenesis)
	}
	predecessor := startup.PredecessorConfiguration
	if !validStartupConfiguration(predecessor) {
		return drwa.ErrDeploymentIdentity
	}
	prior := &config.Config{HardforkRoundExclusions: predecessor.Exclusions}
	if err := factoryCore.CheckDRWAExclusionHistory(prior, proposed); err != nil {
		return err
	}
	if predecessor.RestartConfigDigest != startup.SelectedConfiguration.RestartConfigDigest {
		return drwa.ErrDeploymentIdentity
	}
	return nil
}

// CheckDRWARestartIdentity is a read-only preflight performed before native
// recovery providers open or modify the database. Both records must already
// exist and correspond to the same sealed deployment. The process factory
// independently repeats the commitment check on its owned native identity DB.
func CheckDRWARestartIdentity(path string, input *config.DRWADeploymentIdentityConfig, startup *config.DRWAInitialProgrammeStartup, proposed *config.Config) (returnErr error) {
	if startup == nil || !startup.Persisted || path != startup.OriginalDatabasePath || input == nil {
		return drwa.ErrDeploymentIdentity
	}
	if err := CheckDRWAStartupHistory(startup, proposed); err != nil {
		return err
	}
	pinBytes, err := hex.DecodeString(input.SHA256)
	if err != nil || len(pinBytes) != sha256.Size || input.MaxBytes <= 0 {
		return drwa.ErrDeploymentIdentity
	}
	var pin [sha256.Size]byte
	copy(pin[:], pinBytes)
	raw, err := factoryCore.ReadDRWAPinnedStartupInput(input.Path, pin, int64(input.MaxBytes))
	if err != nil {
		return err
	}
	expected := startupCommitment(startup.PredecessorConfiguration, raw, path)
	if expected == nil {
		return drwa.ErrDeploymentIdentity
	}
	unitPath, err := drwaIdentityPath(path)
	if err != nil {
		return err
	}
	stat, err := os.Lstat(unitPath)
	if err != nil || !stat.IsDir() {
		return drwa.ErrDeploymentIdentity
	}
	db, err := leveldb.OpenFile(unitPath, &opt.Options{ReadOnly: true, ErrorIfMissing: true})
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, db.Close()) }()
	identity, err := db.Get([]byte(drwa.DeploymentIdentityRecord), nil)
	if err != nil || !bytes.Equal(identity, raw) {
		return drwa.ErrDeploymentIdentity
	}
	retained, err := db.Get([]byte(drwaStartupCommitmentKey), nil)
	if err != nil || !bytes.Equal(retained, expected) {
		return drwa.ErrDeploymentIdentity
	}
	return nil
}
