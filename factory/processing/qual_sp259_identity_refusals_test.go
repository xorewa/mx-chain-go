package processing

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	factoryMock "github.com/multiversx/mx-chain-go/factory/mock"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/storage/database"
	"github.com/multiversx/mx-chain-go/testscommon/bootstrapMocks"
	"github.com/multiversx/mx-chain-go/testscommon/mainFactoryMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/stretchr/testify/require"
)

func sp259GenesisPreparationFixture(t *testing.T) (*processComponentsFactory, *drwa.DeploymentIdentity, *stateMock.AccountsStub) {
	t.Helper()
	f, identity := qualD18StartupFactory(t)
	f.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{
		OriginalDatabasePath: f.coreData.PathHandler().DatabasePath(),
		Minimum:              config.DRWAMinimumGenesis{ProfileDigest: [32]byte{1}, ReleaseDigest: [32]byte{2}, MaxEverTokens: 1, RegistryProofBytes: 64},
		RecordDigest:         [32]byte{3}, SelectedConfiguration: &config.DRWAStartupConfiguration{RecordDigest: [32]byte{3}, RestartConfigDigest: [32]byte{3}, MainConfigDigest: [32]byte{4}},
	}
	f.bootstrapComponents = &mainFactoryMocks.BootstrapComponentsStub{BootstrapParams: &bootstrapMocks.BootstrapParamsHandlerMock{EpochCalled: func() uint32 { return identity.GenesisEpoch() }}}
	accounts := &stateMock.AccountsStub{RootHashCalled: func() ([]byte, error) { return common.EmptyTrieHash, nil }}
	f.state = &factoryMock.StateComponentsHolderStub{AccountsAdapterCalled: func() state.AccountsAdapter { return accounts }}
	return f, identity, accounts
}

func TestQualSP259OriginalGenesisPreparation(t *testing.T) {
	dependencyFailure := errors.New("test fixture: root unavailable")
	for _, name := range []string{"healthy", "invalid profile", "invalid exclusion", "missing identity input", "missing identity config", "different database", "unsupported storage", "existing identity", "missing state", "missing accounts", "root unavailable", "nonempty root", "pending journal", "checkpoint", "hardfork", "import", "late epoch"} {
		t.Run(name, func(t *testing.T) {
			f, identity, accounts := sp259GenesisPreparationFixture(t)
			path := f.drwaInitialProgrammeStartup.OriginalDatabasePath
			want := drwa.ErrDeploymentIdentity
			switch name {
			case "invalid profile":
				f.drwaInitialProgrammeStartup.Minimum = config.DRWAMinimumGenesis{}
				want = nil // assert non-nil refusal, exact reason belongs to minimum validator
			case "invalid exclusion":
				f.config.HardforkRoundExclusions = []config.HardforkRoundExclusionConfig{{StartRound: 20, EndRound: 10}}
				f.drwaInitialProgrammeStartup.SelectedConfiguration.Exclusions = append([]config.HardforkRoundExclusionConfig(nil), f.config.HardforkRoundExclusions...)
				want = common.ErrInvalidHardforkRoundExclusion
			case "missing identity input":
				f.drwaDeploymentIdentity.Path = filepath.Join(t.TempDir(), "missing")
			case "missing identity config":
				f.drwaDeploymentIdentity = nil
			case "different database":
				f.drwaInitialProgrammeStartup.OriginalDatabasePath = filepath.Join(t.TempDir(), "other")
			case "unsupported storage":
				f.drwaDeploymentIdentity.DB.MaxBatchSize = 2
			case "existing identity":
				unit, err := drwaIdentityPath(path)
				require.NoError(t, err)
				require.NoError(t, os.MkdirAll(unit, 0700))
			case "missing state":
				f.state = nil
			case "missing accounts":
				f.state = &factoryMock.StateComponentsHolderStub{}
			case "root unavailable":
				accounts.RootHashCalled = func() ([]byte, error) { return nil, dependencyFailure }
				want = dependencyFailure
			case "nonempty root":
				accounts.RootHashCalled = func() ([]byte, error) { return []byte("nonempty fixture root"), nil }
			case "pending journal":
				accounts.JournalLenCalled = func() int { return 1 }
			case "checkpoint":
				f.config.HardforkRecoveryCheckpoint.Enabled = true
			case "hardfork":
				f.config.Hardfork.AfterHardFork = true
			case "import":
				f.importDBConfig.IsImportDBMode = true
			case "late epoch":
				f.bootstrapComponents = &mainFactoryMocks.BootstrapComponentsStub{BootstrapParams: &bootstrapMocks.BootstrapParamsHandlerMock{EpochCalled: func() uint32 { return identity.GenesisEpoch() + 1 }}}
			}
			if name == "healthy" {
				got, err := f.prepareOriginalDRWAGenesis()
				require.NoError(t, err)
				require.Equal(t, identity.Raw(), got.Raw())
			} else {
				components, err := f.Create()
				require.Nil(t, components)
				require.Error(t, err)
				if want != nil {
					require.ErrorIs(t, err, want)
				}
			}
			require.Nil(t, f.drwaIdentityOwner.unit)
			if name != "existing identity" {
				require.NoError(t, checkAbsentDRWAIdentity(path))
			}
		})
	}
}

func TestQualSP259IdentityOpenUnavailableStore(t *testing.T) {
	f, identity := qualD18StartupFactory(t)
	path := f.coreData.PathHandler().DatabasePath()
	owner := &drwaIdentityLifecycle{}
	owner.mutex.Lock()
	unit, err := owner.open(path, qualA77IdentityParameters(), identity, drwaIdentityMode{})
	owner.mutex.Unlock()
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Nil(t, unit)
	require.NoError(t, checkAbsentDRWAIdentity(path))
	// A normal file at the database directory prevents opening the native DB.
	require.NoError(t, os.WriteFile(path, []byte("not a database directory"), 0600))
	unit, err = owner.open(path, qualA77IdentityParameters(), identity, drwaIdentityMode{})
	require.Error(t, err)
	require.Nil(t, unit)
	retained, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("not a database directory"), retained)

	// The actual native database refuses a second open while its owner holds
	// the filesystem lock; this is distinct from path validation.
	other := filepath.Join(t.TempDir(), "chain")
	unitPath, err := drwaIdentityPath(other)
	require.NoError(t, err)
	db, err := database.NewLevelDB(unitPath, 1, 1, 8, 0)
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()
	unit, err = owner.open(other, qualA77IdentityParameters(), identity, drwaIdentityMode{})
	require.Error(t, err)
	require.Nil(t, unit)
}

func TestQualSP259PersistedStartupRequiresIdentity(t *testing.T) {
	f, identity, _ := sp259GenesisPreparationFixture(t)
	f.drwaInitialProgrammeStartup.Persisted = true
	f.bootstrapComponents = &mainFactoryMocks.BootstrapComponentsStub{BootstrapParams: &bootstrapMocks.BootstrapParamsHandlerMock{EpochCalled: func() uint32 { return identity.GenesisEpoch() + 1 }}}
	components, err := f.Create()
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Nil(t, components)
	require.Nil(t, f.drwaIdentityOwner.unit)
	require.NoError(t, checkAbsentDRWAIdentity(f.drwaInitialProgrammeStartup.OriginalDatabasePath))
}

func TestQualSP259FinalizedGenesisIdentity(t *testing.T) {
	for _, name := range []string{"wrong epoch", "valid finalized header"} {
		t.Run(name, func(t *testing.T) {
			f, identity, _ := sp259GenesisPreparationFixture(t)
			header := &block.MetaBlock{}
			require.NoError(t, f.coreData.InternalMarshalizer().Unmarshal(header, identity.Header()))
			if name == "wrong epoch" {
				header.Epoch++
			}
			unit, err := f.openFinalizedDRWAGenesis(identity, header)
			if name == "wrong epoch" {
				require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
				require.Nil(t, unit)
				require.NoError(t, checkAbsentDRWAIdentity(f.drwaInitialProgrammeStartup.OriginalDatabasePath))
				return
			}
			require.NoError(t, err)
			require.Equal(t, identity.Domain(), unit.Domain())
			require.NoError(t, unit.Close())
		})
	}
}
