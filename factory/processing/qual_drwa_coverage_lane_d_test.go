package processing

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/config"
	processGenesis "github.com/multiversx/mx-chain-go/genesis/process"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/process/factory/interceptorscontainer"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/require"
)

func TestQualLaneDIdentityStartupInput(t *testing.T) {
	empty := &processComponentsFactory{}
	identity, err := empty.readConfiguredDRWAIdentity()
	require.NoError(t, err)
	require.Nil(t, identity)
	require.NoError(t, empty.configureNativeValidationSource(interceptorscontainer.CommonInterceptorsContainerFactoryArgs{}))

	f, expected := qualD18StartupFactory(t)
	_, err = empty.prepareOriginalDRWAGenesis()
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	_, err = empty.openFinalizedDRWAGenesis(nil, nil)
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	_, err = f.openFinalizedDRWAGenesis(expected, nil)
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.NoError(t, validateDRWAIdentityStorage(qualA77IdentityParameters(), expected))
	require.ErrorIs(t, validateDRWAIdentityStorage(qualA77IdentityParameters(), nil), drwa.ErrDeploymentIdentity)
	bad := qualA77IdentityParameters()
	bad.MaxBatchSize = 2
	require.ErrorIs(t, validateDRWAIdentityStorage(bad, expected), drwa.ErrDeploymentIdentity)

	config := f.drwaDeploymentIdentity
	_, err = f.readConfiguredDRWAIdentity()
	require.NoError(t, err)
	oldDigest := config.SHA256
	config.SHA256 = strings.Repeat("0", 64)
	_, err = f.readConfiguredDRWAIdentity()
	require.Error(t, err)
	config.SHA256 = oldDigest

	path := f.coreData.PathHandler().DatabasePath()
	require.NoError(t, checkAbsentDRWAIdentity(path))
	unitPath, err := drwaIdentityPath(path)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(unitPath), 0700))
	require.NoError(t, os.WriteFile(unitPath, []byte("unused"), 0600))
	require.Error(t, checkAbsentDRWAIdentity(path))
	require.Error(t, checkAbsentDRWAIdentity("relative"))

	_, _, err = f.finalizeGenesisHeaders(nil)
	require.Error(t, err)
	_, _, err = f.finalizeGenesisHeaders(map[uint32]data.HeaderHandler{core.MetachainShardId: &block.Header{}})
	require.Error(t, err)
	require.ErrorIs(t, f.configureNativeValidationSource(interceptorscontainer.CommonInterceptorsContainerFactoryArgs{}), vm.ErrDRWAExecution)
}

func TestQualLaneDIdentityStoreOwnership(t *testing.T) {
	f, identity := qualD18StartupFactory(t)
	path := f.coreData.PathHandler().DatabasePath()
	owner := &drwaIdentityLifecycle{}
	_, err := owner.open("relative", qualA77IdentityParameters(), identity, drwaIdentityMode{})
	require.Error(t, err)
	parameters := qualA77IdentityParameters()
	parameters.MaxBatchSize = 2
	refused, err := owner.open(path, parameters, identity, drwaIdentityMode{})
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Nil(t, refused)

	db := &qualA77PendingIdentityDB{value: identity.Raw()}
	owner.mutex.Lock()
	unit, err := owner.admitLocked(db, identity, drwaIdentityMode{})
	owner.mutex.Unlock()
	require.NoError(t, err)
	refused, err = owner.open(path, qualA77IdentityParameters(), identity, drwaIdentityMode{})
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Nil(t, refused)
	require.Same(t, unit, owner.unit)
	require.NoError(t, checkAbsentDRWAIdentity(path))
	domain := unit.Domain()
	require.NotEmpty(t, domain)
	domain[0] ^= 1
	require.NotEqual(t, domain, unit.Domain())
	require.NoError(t, unit.Close())
	require.Empty(t, unit.Domain())
	require.NoError(t, unit.Close())
	require.Equal(t, 1, db.closes)
	require.Zero(t, db.puts)
}

func TestQualLaneDIdentityStoreRefusal(t *testing.T) {
	f, identity := qualD18StartupFactory(t)
	path := f.coreData.PathHandler().DatabasePath()
	parameters := qualA77IdentityParameters()
	var missingUnit *drwaIdentityUnit
	require.Nil(t, missingUnit.Domain())
	var missingOwner *drwaIdentityLifecycle
	unit, err := missingOwner.open(path, parameters, identity, drwaIdentityMode{})
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Nil(t, unit)
	require.ErrorIs(t, validateDRWAIdentityStorage(parameters, new(drwa.DeploymentIdentity)), drwa.ErrDeploymentIdentity)

	retained := errors.New("fixture retained store failure")
	owner := &drwaIdentityLifecycle{failure: retained}
	unit, err = owner.open(path, parameters, identity, drwaIdentityMode{})
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.ErrorIs(t, err, retained)
	require.Nil(t, unit)
	require.NoError(t, checkAbsentDRWAIdentity(path))

	for _, tc := range []struct {
		name  string
		value []byte
	}{
		{name: "missing-nonfresh-record"},
		{name: "mismatched-record", value: []byte("different existing record")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &qualA77PendingIdentityDB{value: tc.value}
			owner := &drwaIdentityLifecycle{}
			owner.mutex.Lock()
			unit, err := owner.admitLocked(db, identity, drwaIdentityMode{})
			owner.mutex.Unlock()
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			require.Nil(t, unit)
			require.Nil(t, owner.unit)
			require.Equal(t, 1, db.closes)
			require.Zero(t, db.puts)
			require.Equal(t, tc.value, db.value)
		})
	}
}

type qualLaneDIdentityReadFailureDB struct {
	qualA77PendingIdentityDB
	readErr  error
	closeErr error
}

func (db *qualLaneDIdentityReadFailureDB) Get([]byte) ([]byte, error) {
	return nil, db.readErr
}

func (db *qualLaneDIdentityReadFailureDB) Close() error {
	db.closes++
	return db.closeErr
}

func TestQualLaneDIdentityStoreRetainsReadAndCloseErrors(t *testing.T) {
	f, identity := qualD18StartupFactory(t)
	db := &qualLaneDIdentityReadFailureDB{
		readErr:  errors.New("fixture identity read failed"),
		closeErr: errors.New("fixture identity close failed"),
	}
	owner := &drwaIdentityLifecycle{}
	owner.mutex.Lock()
	unit, err := owner.admitLocked(db, identity, drwaIdentityMode{})
	owner.mutex.Unlock()
	require.Nil(t, unit)
	require.Nil(t, owner.unit)
	require.ErrorIs(t, err, db.readErr)
	require.ErrorIs(t, err, db.closeErr)
	require.Equal(t, 1, db.closes)
	require.Zero(t, db.puts)

	path := f.coreData.PathHandler().DatabasePath()
	unit, err = owner.open(path, qualA77IdentityParameters(), identity, drwaIdentityMode{})
	require.Nil(t, unit)
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.ErrorIs(t, err, db.readErr)
	require.ErrorIs(t, err, db.closeErr)
	require.NoError(t, checkAbsentDRWAIdentity(path))
}

func TestQualLaneDIdentityStartupRefusesUnboundPublicInput(t *testing.T) {
	f, identity := qualD18StartupFactory(t)
	valid := *f.drwaDeploymentIdentity
	for _, tc := range []struct {
		name   string
		change func(*config.DRWADeploymentIdentityConfig)
	}{
		{"unsupported bounds", func(input *config.DRWADeploymentIdentityConfig) { input.MaxHeaderBytes = input.MaxBytes + 1 }},
		{"database override", func(input *config.DRWADeploymentIdentityConfig) { input.DB.FilePath = "other-store" }},
		{"invalid digest", func(input *config.DRWADeploymentIdentityConfig) { input.SHA256 = strings.Repeat("g", 64) }},
		{"missing public input", func(input *config.DRWADeploymentIdentityConfig) {
			input.Path = filepath.Join(filepath.Dir(input.Path), "absent")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := valid
			tc.change(&input)
			f.drwaDeploymentIdentity = &input
			got, err := f.readConfiguredDRWAIdentity()
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			require.Nil(t, got)
		})
	}
	f.drwaDeploymentIdentity = &valid

	noCore := &processComponentsFactory{drwaDeploymentIdentity: &valid}
	got, err := noCore.readConfiguredDRWAIdentity()
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Nil(t, got)

	t.Run("unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("file permission check requires an unprivileged user")
		}
		input := valid
		input.Path = filepath.Join(t.TempDir(), "identity")
		require.NoError(t, os.WriteFile(input.Path, identity.Raw(), 0000))
		refusing := &processComponentsFactory{drwaDeploymentIdentity: &input, coreData: f.coreData}
		got, err := refusing.readConfiguredDRWAIdentity()
		require.ErrorIs(t, err, os.ErrPermission)
		require.Nil(t, got)
	})

	path := f.coreData.PathHandler().DatabasePath()
	f.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{OriginalDatabasePath: path}
	header := &block.MetaBlock{}
	require.NoError(t, f.coreData.InternalMarshalizer().Unmarshal(header, identity.Header()))
	require.Equal(t, core.MetachainShardId, header.GetShardID())
	require.Equal(t, identity.GenesisEpoch(), header.GetEpoch())
	header.Nonce++
	unit, err := f.openFinalizedDRWAGenesis(identity, header)
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Nil(t, unit)
	require.NoError(t, checkAbsentDRWAIdentity(path))

	header.Nonce--
	unitPath, err := drwaIdentityPath(path)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(unitPath), 0700))
	sentinel := []byte("existing identity path")
	require.NoError(t, os.WriteFile(unitPath, sentinel, 0600))
	unit, err = f.openFinalizedDRWAGenesis(identity, header)
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Nil(t, unit)
	retained, err := os.ReadFile(unitPath)
	require.NoError(t, err)
	require.Equal(t, sentinel, retained)
}

type qualLaneDIdentityMarshalCore struct {
	*qualD18Core
	marshaller marshal.Marshalizer
}

func (c *qualLaneDIdentityMarshalCore) InternalMarshalizer() marshal.Marshalizer {
	return c.marshaller
}

func TestQualLaneDIdentityStartupRetainsHeaderEncodingError(t *testing.T) {
	f, identity := qualD18StartupFactory(t)
	path := f.coreData.PathHandler().DatabasePath()
	f.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{OriginalDatabasePath: path}
	header := &block.MetaBlock{}
	require.NoError(t, f.coreData.InternalMarshalizer().Unmarshal(header, identity.Header()))

	failure := errors.New("fixture header encoding failed")
	calls := 0
	f.coreData = &qualLaneDIdentityMarshalCore{
		qualD18Core: f.coreData.(*qualD18Core),
		marshaller: &marshallerMock.MarshalizerStub{MarshalCalled: func(value interface{}) ([]byte, error) {
			calls++
			require.Same(t, header, value)
			return nil, failure
		}},
	}

	unit, err := f.openFinalizedDRWAGenesis(identity, header)
	require.ErrorIs(t, err, failure)
	require.Nil(t, unit)
	require.Equal(t, 1, calls)
	require.NoError(t, checkAbsentDRWAIdentity(path))
}

func TestQualLaneDIdentityStoreRetainsFinalCloseFailure(t *testing.T) {
	_, identity := qualD18StartupFactory(t)
	db := &qualA77PendingIdentityDB{value: identity.Raw()}
	failure := errors.New("identity close failed")
	wrapped := &qualD18IdentityClose{drwaIdentityDB: db, close: func() error {
		db.closes++
		return failure
	}}
	owner := &drwaIdentityLifecycle{}
	owner.mutex.Lock()
	unit, err := owner.admitLocked(wrapped, identity, drwaIdentityMode{})
	owner.mutex.Unlock()
	require.NoError(t, err)
	require.Equal(t, identity.Domain(), unit.Domain())

	require.ErrorIs(t, unit.Close(), failure)
	require.Nil(t, unit.Domain())
	require.ErrorIs(t, unit.Close(), failure)
	require.Equal(t, 1, db.closes)

	path := t.TempDir()
	next, err := owner.open(path, qualA77IdentityParameters(), identity, drwaIdentityMode{})
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.ErrorIs(t, err, failure)
	require.Nil(t, next)
	require.NoError(t, checkAbsentDRWAIdentity(path))
	require.Zero(t, db.puts)
	require.Equal(t, identity.Raw(), db.value)
}

func TestQualLaneDInitialProgrammeGenesisMinimumModes(t *testing.T) {
	var ordinary processComponentsFactory
	var ordinaryArgs processGenesis.ArgsGenesisBlockCreator
	ordinary.setInitialProgrammeGenesisData(&ordinaryArgs)
	require.Nil(t, ordinaryArgs.DRWAMinimumGenesis)

	startup := &config.DRWAInitialProgrammeStartup{Persisted: true}
	factory := processComponentsFactory{drwaInitialProgrammeStartup: startup}
	var persistedArgs processGenesis.ArgsGenesisBlockCreator
	factory.setInitialProgrammeGenesisData(&persistedArgs)
	require.Nil(t, persistedArgs.DRWAMinimumGenesis)

	// The digest is an inert marker in detached arguments. No genesis is produced.
	startup.Persisted = false
	startup.Minimum.ProfileDigest[0] = 1
	expected := startup.Minimum
	var freshArgs processGenesis.ArgsGenesisBlockCreator
	factory.setInitialProgrammeGenesisData(&freshArgs)
	require.NotNil(t, freshArgs.DRWAMinimumGenesis)
	require.Equal(t, expected, *freshArgs.DRWAMinimumGenesis)
	startup.Minimum.ProfileDigest[0] = 2
	require.Equal(t, expected, *freshArgs.DRWAMinimumGenesis)
}
