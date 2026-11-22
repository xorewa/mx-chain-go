package processing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math"
	"os"
	"path/filepath"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/drwa"
)

func cloneDRWAIdentityConfig(input *config.DRWADeploymentIdentityConfig) *config.DRWADeploymentIdentityConfig {
	if input == nil {
		return nil
	}
	cloned := *input
	return &cloned
}

func (pcf *processComponentsFactory) readConfiguredDRWAIdentity() (*drwa.DeploymentIdentity, error) {
	if pcf.drwaDeploymentIdentity == nil {
		return nil, nil
	}
	input := *pcf.drwaDeploymentIdentity
	if input.MaxBytes <= 0 || input.MaxBytes == math.MaxInt || input.MaxChainIDBytes <= 0 || input.MaxHeaderBytes <= 0 || input.MaxChainIDBytes > input.MaxBytes || input.MaxHeaderBytes > input.MaxBytes || len(input.SHA256) != hex.EncodedLen(sha256.Size) || !filepath.IsAbs(input.Path) || filepath.Clean(input.Path) != input.Path {
		return nil, drwa.ErrDeploymentIdentity
	}
	// The unit path/backend are selected by the retained construction, not DB
	// path/type/shard overrides. Refuse unsupported settings rather than ignore them.
	if input.DB.FilePath != "" || input.DB.Type != "" || input.DB.UseTmpAsFilePath || input.DB.ShardIDProviderType != "" || input.DB.NumShards != 0 {
		return nil, drwa.ErrDeploymentIdentity
	}
	// Refuse symlink/nonregular inputs; hold and compare the actual opened inode.
	for current := input.Path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, drwa.ErrDeploymentIdentity
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	before, err := os.Lstat(input.Path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > int64(input.MaxBytes) {
		return nil, drwa.ErrDeploymentIdentity
	}
	file, err := os.Open(input.Path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, drwa.ErrDeploymentIdentity
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(input.MaxBytes)+1))
	if err != nil || len(raw) > input.MaxBytes {
		return nil, drwa.ErrDeploymentIdentity
	}
	pin, err := hex.DecodeString(input.SHA256)
	if err != nil || len(pin) != sha256.Size {
		return nil, drwa.ErrDeploymentIdentity
	}
	if check.IfNil(pcf.coreData) || check.IfNil(pcf.coreData.PathHandler()) {
		return nil, drwa.ErrDeploymentIdentity
	}
	identity, err := drwa.DecodeDeploymentIdentity(raw, pin, []byte(pcf.coreData.ChainID()), pcf.config.EpochStartConfig.GenesisEpoch,
		drwa.DeploymentIdentityBounds{Bytes: input.MaxBytes, ChainIDBytes: input.MaxChainIDBytes, HeaderBytes: input.MaxHeaderBytes}, pcf.coreData.InternalMarshalizer(), pcf.coreData.Hasher())
	if err != nil {
		return nil, err
	}
	return identity, nil
}

func (pcf *processComponentsFactory) openConfiguredDRWAIdentity() (*drwaIdentityUnit, error) {
	identity, err := pcf.readConfiguredDRWAIdentity()
	if err != nil || identity == nil {
		return nil, err
	}
	// The persisted-start path requires the existing unit. Only the separately
	// selected original-genesis path may create one.
	unitPath, err := drwaIdentityPath(pcf.coreData.PathHandler().DatabasePath())
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(unitPath)
	if err != nil || !info.IsDir() {
		return nil, drwa.ErrDeploymentIdentity
	}
	return pcf.drwaIdentityOwner.open(pcf.coreData.PathHandler().DatabasePath(), pcf.drwaDeploymentIdentity.DB, identity, drwaIdentityMode{})
}

// prepareOriginalDRWAGenesis checks the independently supplied original
// generation input before touching native state. Absence of a store alone
// cannot choose this route.
func (pcf *processComponentsFactory) prepareOriginalDRWAGenesis() (*drwa.DeploymentIdentity, error) {
	startup := pcf.drwaInitialProgrammeStartup
	if startup == nil || startup.OriginalDatabasePath == "" || pcf.config.Hardfork.AfterHardFork ||
		pcf.config.HardforkRecoveryCheckpoint.Enabled || pcf.importDBConfig.IsImportDBMode ||
		check.IfNil(pcf.bootstrapComponents) || check.IfNil(pcf.bootstrapComponents.EpochBootstrapParams()) ||
		pcf.bootstrapComponents.EpochBootstrapParams().Epoch() != pcf.config.EpochStartConfig.GenesisEpoch {
		return nil, drwa.ErrDeploymentIdentity
	}
	if err := drwa.ValidateInitialProgrammeMinimum(startup.Minimum); err != nil {
		return nil, err
	}
	identity, err := pcf.readConfiguredDRWAIdentity()
	if err != nil {
		return nil, err
	}
	if identity == nil || pcf.coreData.PathHandler().DatabasePath() != startup.OriginalDatabasePath {
		return nil, drwa.ErrDeploymentIdentity
	}
	if err = validateDRWAIdentityStorage(pcf.drwaDeploymentIdentity.DB, identity); err != nil {
		return nil, err
	}
	if err = checkAbsentDRWAIdentity(startup.OriginalDatabasePath); err != nil {
		return nil, err
	}
	if check.IfNil(pcf.state) || check.IfNil(pcf.state.AccountsAdapter()) {
		return nil, drwa.ErrDeploymentIdentity
	}
	accounts := pcf.state.AccountsAdapter()
	root, err := accounts.RootHash()
	if err != nil {
		return nil, err
	}
	if accounts.JournalLen() != 0 || !common.IsEmptyTrie(root) {
		return nil, drwa.ErrDeploymentIdentity
	}
	return identity, nil
}

func checkAbsentDRWAIdentity(databasePath string) error {
	unitPath, err := drwaIdentityPath(databasePath)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(unitPath); !os.IsNotExist(err) {
		return drwa.ErrDeploymentIdentity
	}
	return nil
}

func (pcf *processComponentsFactory) openFinalizedDRWAGenesis(identity *drwa.DeploymentIdentity,
	header data.MetaHeaderHandler) (*drwaIdentityUnit, error) {
	if identity == nil || pcf.drwaInitialProgrammeStartup == nil {
		return nil, drwa.ErrDeploymentIdentity
	}
	path := pcf.drwaInitialProgrammeStartup.OriginalDatabasePath
	if check.IfNil(header) || header.GetShardID() != core.MetachainShardId ||
		header.GetEpoch() != identity.GenesisEpoch() || pcf.coreData.PathHandler().DatabasePath() != path {
		return nil, drwa.ErrDeploymentIdentity
	}
	canonical, err := pcf.coreData.InternalMarshalizer().Marshal(header)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, identity.Header()) {
		return nil, drwa.ErrDeploymentIdentity
	}
	if err = checkAbsentDRWAIdentity(path); err != nil {
		return nil, err
	}
	return pcf.drwaIdentityOwner.open(path, pcf.drwaDeploymentIdentity.DB, identity, drwaIdentityMode{
		freshGenesis: true, startEpoch: pcf.bootstrapComponents.EpochBootstrapParams().Epoch(),
		genesisEpoch: pcf.config.EpochStartConfig.GenesisEpoch, finalizedMetachainHeader: canonical,
	})
}
