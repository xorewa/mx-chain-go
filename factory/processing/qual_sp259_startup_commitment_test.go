package processing

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/storage/database"
	"github.com/multiversx/mx-chain-go/testscommon/bootstrapMocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/mainFactoryMocks"
	"github.com/stretchr/testify/require"
)

func sp259CommittedGenesis(t *testing.T) (*processComponentsFactory, *drwa.DeploymentIdentity) {
	t.Helper()
	f, identity, _ := sp259GenesisPreparationFixture(t)
	selected := f.drwaInitialProgrammeStartup.SelectedConfiguration
	selected.Exclusions = []config.HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 20}}
	f.config.HardforkRoundExclusions = append([]config.HardforkRoundExclusionConfig(nil), selected.Exclusions...)
	prepared, err := f.prepareOriginalDRWAGenesis()
	require.NoError(t, err)
	header := &block.MetaBlock{}
	require.NoError(t, f.coreData.InternalMarshalizer().Unmarshal(header, identity.Header()))
	unit, err := f.openFinalizedDRWAGenesis(prepared, header)
	require.NoError(t, err)
	require.Equal(t, identity.Domain(), unit.Domain())
	require.NoError(t, unit.Close())
	f.drwaInitialProgrammeStartup.PredecessorConfiguration = selected.Clone()
	f.drwaInitialProgrammeStartup.SelectedConfiguration.RecordDigest = [32]byte{5}
	f.drwaInitialProgrammeStartup.RecordDigest = [32]byte{5}
	f.drwaInitialProgrammeStartup.Persisted = true
	return f, identity
}

func TestQualSP259NativeStartupCommitment(t *testing.T) {
	for _, name := range []string{"healthy", "missing predecessor", "wrong record", "different config", "missing exclusion", "wrong database", "missing identity input", "invalid identity pin", "missing retained commitment", "invalid retained identity"} {
		t.Run(name, func(t *testing.T) {
			f, identity := sp259CommittedGenesis(t)
			s := f.drwaInitialProgrammeStartup
			path := s.OriginalDatabasePath
			want := drwa.ErrDeploymentIdentity
			switch name {
			case "missing predecessor":
				s.PredecessorConfiguration = nil
			case "wrong record":
				s.PredecessorConfiguration.RecordDigest = [32]byte{9}
			case "different config":
				s.SelectedConfiguration.RestartConfigDigest = [32]byte{9}
			case "missing exclusion":
				f.config.HardforkRoundExclusions = nil
				s.SelectedConfiguration.Exclusions = nil
				want = nil
			case "wrong database":
				path = filepath.Join(t.TempDir(), "other")
			case "missing identity input":
				f.drwaDeploymentIdentity.Path = filepath.Join(t.TempDir(), "missing")
				want = nil
			case "invalid identity pin":
				f.drwaDeploymentIdentity.SHA256 = "invalid"
			case "missing retained commitment", "invalid retained identity":
				// A real identity unit that never completed both genesis
				// records or contains an unavailable identity is not admitted.
				f2, id, _ := sp259GenesisPreparationFixture(t)
				path = f2.drwaInitialProgrammeStartup.OriginalDatabasePath
				s.OriginalDatabasePath = path
				f.drwaDeploymentIdentity = f2.drwaDeploymentIdentity
				seed := &drwaIdentityLifecycle{}
				unit, err := seed.open(path, qualA77IdentityParameters(), id, qualA77IdentityFresh(id))
				require.NoError(t, err)
				require.NoError(t, unit.Close())
				if name == "invalid retained identity" {
					dbPath, err := drwaIdentityPath(path)
					require.NoError(t, err)
					db, err := database.NewLevelDB(dbPath, 1, 1, 8, 0)
					require.NoError(t, err)
					require.NoError(t, db.Put([]byte(drwa.DeploymentIdentityRecord), []byte("unusable record")))
					require.NoError(t, db.Close())
				}
			}
			err := CheckDRWARestartIdentity(path, f.drwaDeploymentIdentity, s, &f.config)
			if name == "healthy" {
				require.NoError(t, err)
				unit, err := f.openConfiguredDRWAIdentity()
				require.NoError(t, err)
				require.Equal(t, identity.Domain(), unit.Domain())
				require.NoError(t, unit.Close())
				require.NoError(t, CheckDRWARestartIdentity(path, f.drwaDeploymentIdentity, s, &f.config))
			} else {
				require.Error(t, err)
				if want != nil {
					require.ErrorIs(t, err, want)
				}
				require.Nil(t, f.drwaIdentityOwner.unit)
			}
		})
	}
}

func TestQualSP259CommitmentHistoryControls(t *testing.T) {
	f, identity, _ := sp259GenesisPreparationFixture(t)
	s := f.drwaInitialProgrammeStartup
	require.Nil(t, startupCommitment(nil, identity.Raw(), s.OriginalDatabasePath))
	require.Nil(t, startupCommitment(s.SelectedConfiguration, nil, s.OriginalDatabasePath))
	require.Len(t, startupCommitment(s.SelectedConfiguration, identity.Raw(), s.OriginalDatabasePath), 192)
	require.Error(t, CheckDRWAStartupHistory(nil, &f.config))
	require.Error(t, CheckDRWAStartupHistory(s, nil))
	clone := s.Clone()
	clone.RecordDigest = [32]byte{8}
	require.Error(t, CheckDRWAStartupHistory(clone, &f.config))
	clone = s.Clone()
	clone.PredecessorConfiguration = clone.SelectedConfiguration.Clone()
	require.Error(t, CheckDRWAStartupHistory(clone, &f.config))
	require.NoError(t, CheckDRWAStartupHistory(s, &f.config))
	require.Error(t, CheckDRWARestartIdentity(s.OriginalDatabasePath, f.drwaDeploymentIdentity, s, &f.config))
	require.Error(t, CheckDRWARestartIdentity(s.OriginalDatabasePath, nil, s, &f.config))
	s.Persisted = true
	s.PredecessorConfiguration = s.SelectedConfiguration.Clone()
	require.ErrorIs(t, CheckDRWARestartIdentity(s.OriginalDatabasePath, f.drwaDeploymentIdentity, s, &f.config), drwa.ErrDeploymentIdentity)
	unitPath, err := drwaIdentityPath(s.OriginalDatabasePath)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(unitPath, 0700))
	require.Error(t, CheckDRWARestartIdentity(s.OriginalDatabasePath, f.drwaDeploymentIdentity, s, &f.config))
}

type sp259CommitmentFault struct {
	drwaIdentityDB
	getErr, putErr error
}

func (d *sp259CommitmentFault) Get(key []byte) ([]byte, error) {
	if bytes.Equal(key, []byte(drwaStartupCommitmentKey)) && d.getErr != nil {
		return nil, d.getErr
	}
	return d.drwaIdentityDB.Get(key)
}
func (d *sp259CommitmentFault) Put(key, value []byte) error {
	if bytes.Equal(key, []byte(drwaStartupCommitmentKey)) && d.putErr != nil {
		return d.putErr
	}
	return d.drwaIdentityDB.Put(key, value)
}

func TestQualSP259CommitmentNativeDependencyFailures(t *testing.T) {
	failure := errors.New("test fixture: commitment unavailable")
	for _, name := range []string{"genesis read failure", "genesis write failure", "restart read failure", "restart absent commitment", "restart mismatch"} {
		t.Run(name, func(t *testing.T) {
			f, identity, _ := sp259GenesisPreparationFixture(t)
			path, err := drwaIdentityPath(f.drwaInitialProgrammeStartup.OriginalDatabasePath)
			require.NoError(t, err)
			db, err := database.NewLevelDB(path, 1, 1, 8, 0)
			require.NoError(t, err)
			fault := &sp259CommitmentFault{drwaIdentityDB: db}
			expected := startupCommitment(f.drwaInitialProgrammeStartup.SelectedConfiguration, identity.Raw(), f.drwaInitialProgrammeStartup.OriginalDatabasePath)
			mode := qualA77IdentityFresh(identity)
			mode.startupCommitment = expected
			want := failure
			switch name {
			case "genesis read failure":
				fault.getErr = failure
			case "genesis write failure":
				fault.putErr = failure
			default:
				mode.freshGenesis = false
				require.NoError(t, db.Put([]byte(drwa.DeploymentIdentityRecord), identity.Raw()))
				switch name {
				case "restart read failure":
					fault.getErr = failure
				case "restart absent commitment":
					want = storage.ErrKeyNotFound
				case "restart mismatch":
					want = drwa.ErrDeploymentIdentity
					require.NoError(t, db.Put([]byte(drwaStartupCommitmentKey), []byte("unusable record")))
				}
			}
			owner := &drwaIdentityLifecycle{}
			owner.mutex.Lock()
			unit, err := owner.admitLocked(fault, identity, mode)
			owner.mutex.Unlock()
			require.ErrorIs(t, err, want)
			require.Nil(t, unit)
			require.Nil(t, owner.unit)
			require.Error(t, owner.failure)
		})
	}
}

func TestQualSP259NativeStartupFinalAdmissionRefusals(t *testing.T) {
	for _, name := range []string{"missing unit", "invalid path", "missing predecessor", "noncanonical path"} {
		t.Run("restart/"+name, func(t *testing.T) {
			f, _, _ := sp259GenesisPreparationFixture(t)
			if name == "missing predecessor" || name == "noncanonical path" {
				f, _ = sp259CommittedGenesis(t)
				if name == "missing predecessor" {
					f.drwaInitialProgrammeStartup.PredecessorConfiguration = nil
				} else {
					f.coreData.(*qualD18Core).path += string(filepath.Separator) + "."
				}
			} else if name == "invalid path" {
				f.coreData.(*qualD18Core).path = "relative"
			}
			unit, err := f.openConfiguredDRWAIdentity()
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			require.Nil(t, unit)
			require.Nil(t, f.drwaIdentityOwner.unit)
		})
	}
	for _, name := range []string{"missing configuration", "noncanonical path"} {
		t.Run("genesis/"+name, func(t *testing.T) {
			f, identity, _ := sp259GenesisPreparationFixture(t)
			header := &block.MetaBlock{}
			require.NoError(t, f.coreData.InternalMarshalizer().Unmarshal(header, identity.Header()))
			if name == "missing configuration" {
				f.drwaInitialProgrammeStartup.SelectedConfiguration = nil
			} else {
				f.coreData.(*qualD18Core).path += string(filepath.Separator) + "."
				f.drwaInitialProgrammeStartup.OriginalDatabasePath = f.coreData.PathHandler().DatabasePath()
			}
			unit, err := f.openFinalizedDRWAGenesis(identity, header)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			require.Nil(t, unit)
			require.NoError(t, checkAbsentDRWAIdentity(f.coreData.PathHandler().DatabasePath()))
		})
	}
}

// Only the next, unrelated provider fails; identity admission uses the actual
// co-recorded LevelDB pair written by openFinalizedDRWAGenesis.
type sp259UnavailableEpochProviderCore struct{ *qualD18Core }

func (*sp259UnavailableEpochProviderCore) GenesisTime() time.Time { return time.Unix(100, 0) }
func (*sp259UnavailableEpochProviderCore) EnableEpochsHandler() common.EnableEpochsHandler {
	return &enableEpochsHandlerMock.EnableEpochsHandlerStub{}
}
func (*sp259UnavailableEpochProviderCore) ChainParametersHandler() process.ChainParametersHandler {
	return nil
}

func TestQualSP259CreateRetainsIdentityOnLaterProviderFailure(t *testing.T) {
	f, identity := sp259CommittedGenesis(t)
	f.coreData = &sp259UnavailableEpochProviderCore{f.coreData.(*qualD18Core)}
	f.bootstrapComponents = &mainFactoryMocks.BootstrapComponentsStub{BootstrapParams: &bootstrapMocks.BootstrapParamsHandlerMock{EpochCalled: func() uint32 { return identity.GenesisEpoch() + 1 }}}
	f.prefConfigs.Preferences.FullArchive = true
	components, err := f.Create()
	require.ErrorIs(t, err, process.ErrNilChainParametersHandler)
	require.Nil(t, components)
	require.Nil(t, f.drwaIdentityOwner.unit)
	require.NoError(t, CheckDRWARestartIdentity(f.drwaInitialProgrammeStartup.OriginalDatabasePath, f.drwaDeploymentIdentity, f.drwaInitialProgrammeStartup, &f.config))
	unit, err := f.openConfiguredDRWAIdentity()
	require.NoError(t, err)
	require.Equal(t, identity.Domain(), unit.Domain())
	require.NoError(t, unit.Close())
}
