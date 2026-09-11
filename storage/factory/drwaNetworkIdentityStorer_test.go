package factory

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/storage/mock"
	"github.com/multiversx/mx-chain-go/testscommon/nodeTypeProviderMock"
	"github.com/stretchr/testify/require"
)

func drwaIdentityStorageConfigForTest() config.StorageConfig {
	storageConfig := createMockStorageConfig("PrototypeNetworkIdentityStorageDB")
	storageConfig.DB.MaxBatchSize = 1
	return storageConfig
}

func seedLegacyDRWAIdentity(
	t *testing.T,
	databaseRoot string,
	storageConfig config.StorageConfig,
	shardDirectory string,
	key []byte,
	value []byte,
) string {
	t.Helper()
	path := filepath.Join(
		databaseRoot,
		storage.DefaultStaticDbString,
		shardDirectory,
		storageConfig.DB.FilePath,
	)
	unit, err := createDRWANetworkIdentityStorageUnit(storageConfig, path)
	require.NoError(t, err)
	require.NoError(t, unit.Put(key, value))
	require.NoError(t, unit.Close())
	return path
}

func TestDRWANetworkIdentityStorerDiscoversAllLegacyLocationsAndPreservesThem(t *testing.T) {
	databaseRoot := t.TempDir()
	pathManager, err := CreatePathManagerFromSinglePathString(databaseRoot)
	require.NoError(t, err)
	storageConfig := drwaIdentityStorageConfigForTest()
	key := []byte("identity-key")
	value := []byte("identity-envelope")
	legacyPaths := []string{
		seedLegacyDRWAIdentity(t, databaseRoot, storageConfig, "Shard_0", key, value),
		seedLegacyDRWAIdentity(t, databaseRoot, storageConfig, "Shard_2", key, value),
		seedLegacyDRWAIdentity(t, databaseRoot, storageConfig, "Shard_metachain", key, value),
	}

	storer, err := newDRWANetworkIdentityStorer(pathManager, storageConfig)
	require.NoError(t, err)
	candidates, err := storer.DRWANetworkIdentityCandidates(key)
	require.NoError(t, err)
	require.Equal(t, map[string][]byte{
		"legacy/Shard_0":         value,
		"legacy/Shard_2":         value,
		"legacy/Shard_metachain": value,
	}, candidates)
	candidates["legacy/Shard_0"][0] ^= 0xff
	secondRead, err := storer.DRWANetworkIdentityCandidates(key)
	require.NoError(t, err)
	require.Equal(t, value, secondRead["legacy/Shard_0"], "candidate bytes must never alias caller-owned memory")

	require.NoError(t, storer.Put(key, value))
	candidates, err = storer.DRWANetworkIdentityCandidates(key)
	require.NoError(t, err)
	require.Equal(t, value, candidates["global"])
	require.NoError(t, storer.DestroyUnit())

	for _, legacyPath := range legacyPaths {
		legacy, openErr := createDRWANetworkIdentityStorageUnit(storageConfig, legacyPath)
		require.NoError(t, openErr)
		loaded, getErr := legacy.Get(key)
		require.NoError(t, getErr)
		require.Equal(t, value, loaded)
		require.NoError(t, legacy.Close())
	}

	reopened, err := newDRWANetworkIdentityStorer(pathManager, storageConfig)
	require.NoError(t, err)
	_, err = reopened.Get(key)
	require.ErrorIs(t, err, storage.ErrKeyNotFound, "destroy affects only node-global active state")
	require.NoError(t, reopened.Close())
}

func TestDRWANetworkIdentityStorerUsesOneNodeGlobalPath(t *testing.T) {
	databaseRoot := t.TempDir()
	pathManager, err := CreatePathManagerFromSinglePathString(databaseRoot)
	require.NoError(t, err)
	storageConfig := drwaIdentityStorageConfigForTest()
	key := []byte("identity-key")
	value := []byte("identity-envelope")

	first, err := newDRWANetworkIdentityStorer(pathManager, storageConfig)
	require.NoError(t, err)
	require.NoError(t, first.Put(key, value))
	require.NoError(t, first.Close())

	expectedGlobalPath := filepath.Join(
		databaseRoot,
		storage.DefaultStaticDbString,
		drwaNetworkIdentityGlobalDirectory,
		storageConfig.DB.FilePath,
	)
	info, err := os.Stat(expectedGlobalPath)
	require.NoError(t, err)
	require.True(t, info.IsDir())

	second, err := newDRWANetworkIdentityStorer(pathManager, storageConfig)
	require.NoError(t, err)
	loaded, err := second.Get(key)
	require.NoError(t, err)
	require.Equal(t, value, loaded)
	require.NoError(t, second.Close())
}

func TestDRWANetworkIdentityStorerRejectsUnsafeLegacyPaths(t *testing.T) {
	databaseRoot := t.TempDir()
	pathManager, err := CreatePathManagerFromSinglePathString(databaseRoot)
	require.NoError(t, err)
	storageConfig := drwaIdentityStorageConfigForTest()
	staticRoot := filepath.Join(databaseRoot, storage.DefaultStaticDbString)
	require.NoError(t, os.MkdirAll(staticRoot, 0o700))
	require.NoError(t, os.Symlink(t.TempDir(), filepath.Join(staticRoot, "Shard_1")))

	storer, err := newDRWANetworkIdentityStorer(pathManager, storageConfig)
	require.Error(t, err)
	require.Nil(t, storer)
	require.ErrorContains(t, err, "invalid legacy DRWA network identity shard path")

	// The failed scan must close the newly opened global database, so a clean
	// retry against the same root can proceed after the unsafe path is removed.
	require.NoError(t, os.Remove(filepath.Join(staticRoot, "Shard_1")))
	storer, err = newDRWANetworkIdentityStorer(pathManager, storageConfig)
	require.NoError(t, err)
	require.NoError(t, storer.Close())
}

func TestDRWANetworkIdentityStorerRejectsConcurrentWriterAndAllowsReopen(t *testing.T) {
	databaseRoot := t.TempDir()
	pathManager, err := CreatePathManagerFromSinglePathString(databaseRoot)
	require.NoError(t, err)
	storageConfig := drwaIdentityStorageConfigForTest()

	first, err := newDRWANetworkIdentityStorer(pathManager, storageConfig)
	require.NoError(t, err)
	second, err := newDRWANetworkIdentityStorer(pathManager, storageConfig)
	require.Error(t, err)
	require.Nil(t, second)
	require.NoError(t, first.Close())

	second, err = newDRWANetworkIdentityStorer(pathManager, storageConfig)
	require.NoError(t, err)
	require.NoError(t, second.Close())
}

func TestStorageServiceFactoryReturnsLegacyCandidateAwareIdentityStorerOnlyForProcessService(t *testing.T) {
	chainModes := []struct {
		name   string
		selfID uint32
		create func(*StorageServiceFactory) (dataRetriever.StorageService, error)
	}{
		{name: "shard", selfID: 0, create: func(factory *StorageServiceFactory) (dataRetriever.StorageService, error) {
			return factory.CreateForShard()
		}},
		{name: "metachain", selfID: core.MetachainShardId, create: func(factory *StorageServiceFactory) (dataRetriever.StorageService, error) {
			return factory.CreateForMeta()
		}},
	}
	processModes := []struct {
		name        string
		nodeType    core.NodeType
		fullArchive bool
	}{
		{name: "validator", nodeType: core.NodeTypeValidator},
		{name: "observer", nodeType: core.NodeTypeObserver},
		{name: "full archive observer", nodeType: core.NodeTypeObserver, fullArchive: true},
	}
	for _, processMode := range processModes {
		for _, chainMode := range chainModes {
			t.Run(processMode.name+"/"+chainMode.name, func(t *testing.T) {
				args := createMockArgument(t)
				args.PrefsConfig.FullArchive = processMode.fullArchive
				if processMode.fullArchive {
					args.Config.StoragePruning.FullArchiveNumActivePersisters =
						args.Config.DbLookupExtensions.DbLookupMaxActivePersisters
				}
				args.ShardCoordinator.(*mock.ShardCoordinatorMock).SelfShardId = chainMode.selfID
				args.NodeTypeProvider = &nodeTypeProviderMock.NodeTypeProviderStub{
					GetTypeCalled: func() core.NodeType { return processMode.nodeType },
				}
				factory, err := NewStorageServiceFactory(args)
				require.NoError(t, err)
				service, err := chainMode.create(factory)
				require.NoError(t, err)
				storer, err := service.GetStorer(dataRetriever.DRWANetworkIdentityUnit)
				require.NoError(t, err)
				_, ok := storer.(interface {
					DRWANetworkIdentityCandidates([]byte) (map[string][]byte, error)
				})
				require.True(t, ok, "the process service must retain read-only predecessor discovery")
				require.NoError(t, service.CloseAll())
			})
		}
	}

	for _, storageType := range []StorageServiceType{BootstrapStorageService, ImportDBStorageService} {
		args := createMockArgument(t)
		args.StorageType = storageType
		factory, err := NewStorageServiceFactory(args)
		require.NoError(t, err)
		service, err := factory.CreateForShard()
		require.NoError(t, err)
		_, err = service.GetStorer(dataRetriever.DRWANetworkIdentityUnit)
		require.Error(t, err)
		require.NoError(t, service.CloseAll())
	}
}
