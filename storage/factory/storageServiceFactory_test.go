package factory

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/common/statistics"
	disabledStatistics "github.com/multiversx/mx-chain-go/common/statistics/disabled"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/storage/mock"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/nodeTypeProviderMock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createMockArgument(t *testing.T) StorageServiceFactoryArgs {
	pathMan, err := CreatePathManagerFromSinglePathString(t.TempDir())
	require.Nil(t, err)

	return StorageServiceFactoryArgs{
		Config: config.Config{
			StateTriesConfig: config.StateTriesConfig{},
			StoragePruning: config.StoragePruningConfig{
				Enabled:                    true,
				NumActivePersisters:        3,
				NumEpochsToKeep:            4,
				ObserverCleanOldEpochsData: true,
			},
			ShardHdrNonceHashStorage:   createMockStorageConfig("ShardHdrNonceHashStorage"),
			TxStorage:                  createMockStorageConfig("TxStorage"),
			UnsignedTransactionStorage: createMockStorageConfig("UnsignedTransactionStorage"),
			RewardTxStorage:            createMockStorageConfig("RewardTxStorage"),
			ReceiptsStorage:            createMockStorageConfig("ReceiptsStorage"),
			ScheduledSCRsStorage:       createMockStorageConfig("ScheduledSCRsStorage"),
			BootstrapStorage:           createMockStorageConfig("BootstrapStorage"),
			MiniBlocksStorage:          createMockStorageConfig("MiniBlocksStorage"),
			MetaBlockStorage:           createMockStorageConfig("MetaBlockStorage"),
			MetaHdrNonceHashStorage:    createMockStorageConfig("MetaHdrNonceHashStorage"),
			BlockHeaderStorage:         createMockStorageConfig("BlockHeaderStorage"),
			AccountsTrieStorage:        createMockStorageConfig("AccountsTrieStorage"),
			PeerAccountsTrieStorage:    createMockStorageConfig("PeerAccountsTrieStorage"),
			StatusMetricsStorage:       createMockStorageConfig("StatusMetricsStorage"),
			DRWANetworkIdentityStorage: func() config.StorageConfig {
				storageConfig := createMockStorageConfig("PrototypeNetworkIdentityStorage")
				storageConfig.DB.MaxBatchSize = 1
				return storageConfig
			}(),
			PeerBlockBodyStorage:     createMockStorageConfig("PeerBlockBodyStorage"),
			TrieEpochRootHashStorage: createMockStorageConfig("TrieEpochRootHashStorage"),
			ProofsStorage:            createMockStorageConfig("ProofsStorage"),
			ExecutionResultsStorage:  createMockStorageConfig("ExecutionResultsStorage"),
			DbLookupExtensions: config.DbLookupExtensionsConfig{
				Enabled:                            true,
				DbLookupMaxActivePersisters:        10,
				MiniblocksMetadataStorageConfig:    createMockStorageConfig("MiniblocksMetadataStorage"),
				MiniblockHashByTxHashStorageConfig: createMockStorageConfig("MiniblockHashByTxHashStorage"),
				EpochByHashStorageConfig:           createMockStorageConfig("EpochByHashStorage"),
				ResultsHashesByTxHashStorageConfig: createMockStorageConfig("ResultsHashesByTxHashStorage"),
				ESDTSuppliesStorageConfig:          createMockStorageConfig("ESDTSuppliesStorage"),
				RoundHashStorageConfig:             createMockStorageConfig("RoundHashStorage"),
			},
			LogsAndEvents: config.LogsAndEventsConfig{
				SaveInStorageEnabled: true,
				TxLogsStorage:        createMockStorageConfig("TxLogsStorage"),
			},
		},
		PrefsConfig: config.PreferencesConfig{},
		ShardCoordinator: &mock.ShardCoordinatorMock{
			NumShards: 3,
		},
		PathManager:        pathMan,
		EpochStartNotifier: &mock.EpochStartNotifierStub{},
		NodeTypeProvider: &nodeTypeProviderMock.NodeTypeProviderStub{
			GetTypeCalled: func() core.NodeType {
				return core.NodeTypeObserver
			},
		},
		StorageType:                   ProcessStorageService,
		CurrentEpoch:                  0,
		CreateTrieEpochRootHashStorer: true,
		ManagedPeersHolder:            &testscommon.ManagedPeersHolderStub{},
		StateStatsHandler:             disabledStatistics.NewStateStatistics(),
	}
}

func createMockStorageConfig(dbName string) config.StorageConfig {
	return config.StorageConfig{
		Cache: config.CacheConfig{
			Type:     "LRU",
			Capacity: 1000,
		},
		DB: config.DBConfig{
			FilePath:          dbName,
			Type:              "LvlDBSerial",
			BatchDelaySeconds: 5,
			MaxBatchSize:      100,
			MaxOpenFiles:      10,
		},
	}
}

func TestNewStorageServiceFactory(t *testing.T) {
	t.Parallel()

	t.Run("invalid StoragePruning.NumActivePersisters should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.StoragePruning.NumActivePersisters = 0
		storageServiceFactory, err := NewStorageServiceFactory(args)
		assert.Equal(t, storage.ErrInvalidNumberOfActivePersisters, err)
		assert.Nil(t, storageServiceFactory)
	})
	t.Run("wrong prototype network identity storage type should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.DRWANetworkIdentityStorage.DB.Type = string(storageunit.MemoryDB)
		storageServiceFactory, err := NewStorageServiceFactory(args)
		require.ErrorIs(t, err, errInvalidDRWANetworkIdentityStorage)
		require.Nil(t, storageServiceFactory)
	})
	t.Run("absent prototype network identity storage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.DRWANetworkIdentityStorage = config.StorageConfig{}
		storageServiceFactory, err := NewStorageServiceFactory(args)
		require.ErrorIs(t, err, errInvalidDRWANetworkIdentityStorage)
		require.Nil(t, storageServiceFactory)
	})
	t.Run("wrong prototype network identity storage batch size should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.DRWANetworkIdentityStorage.DB.MaxBatchSize = 2
		storageServiceFactory, err := NewStorageServiceFactory(args)
		require.ErrorIs(t, err, errInvalidDRWANetworkIdentityStorage)
		require.Nil(t, storageServiceFactory)
	})
	t.Run("zero prototype network identity storage batch delay should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.DRWANetworkIdentityStorage.DB.BatchDelaySeconds = 0
		storageServiceFactory, err := NewStorageServiceFactory(args)
		require.ErrorIs(t, err, errInvalidDRWANetworkIdentityStorage)
		require.Nil(t, storageServiceFactory)
	})
	t.Run("negative prototype network identity storage batch delay should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.DRWANetworkIdentityStorage.DB.BatchDelaySeconds = -1
		storageServiceFactory, err := NewStorageServiceFactory(args)
		require.ErrorIs(t, err, errInvalidDRWANetworkIdentityStorage)
		require.Nil(t, storageServiceFactory)
	})
	t.Run("empty prototype network identity database path should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.DRWANetworkIdentityStorage.DB.FilePath = ""
		storageServiceFactory, err := NewStorageServiceFactory(args)
		require.ErrorIs(t, err, errInvalidDRWANetworkIdentityStorage)
		require.Nil(t, storageServiceFactory)
	})
	t.Run("nil shard coordinator should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.ShardCoordinator = nil
		storageServiceFactory, err := NewStorageServiceFactory(args)
		assert.Equal(t, storage.ErrNilShardCoordinator, err)
		assert.Nil(t, storageServiceFactory)
	})
	t.Run("nil state statistics handler should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.StateStatsHandler = nil
		storageServiceFactory, err := NewStorageServiceFactory(args)
		assert.Equal(t, statistics.ErrNilStateStatsHandler, err)
		assert.Nil(t, storageServiceFactory)
	})
	t.Run("nil path manager should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.PathManager = nil
		storageServiceFactory, err := NewStorageServiceFactory(args)
		assert.Equal(t, storage.ErrNilPathManager, err)
		assert.Nil(t, storageServiceFactory)
	})
	t.Run("nil epoch start notifier should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.EpochStartNotifier = nil
		storageServiceFactory, err := NewStorageServiceFactory(args)
		assert.Equal(t, storage.ErrNilEpochStartNotifier, err)
		assert.Nil(t, storageServiceFactory)
	})
	t.Run("invalid number of epochs to save should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.StoragePruning.NumEpochsToKeep = 1
		storageServiceFactory, err := NewStorageServiceFactory(args)
		assert.Equal(t, storage.ErrInvalidNumberOfEpochsToSave, err)
		assert.Nil(t, storageServiceFactory)
	})
	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		storageServiceFactory, err := NewStorageServiceFactory(args)
		assert.Nil(t, err)
		assert.NotNil(t, storageServiceFactory)
	})
}

func TestStorageServiceFactory_CreateForShard(t *testing.T) {
	t.Parallel()

	expectedErrForCacheString := "not supported cache type"
	t.Run("wrong prototype network identity cache should error without fallback", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.DRWANetworkIdentityStorage.Cache.Type = ""
		storageServiceFactory, err := NewStorageServiceFactory(args)
		require.NoError(t, err)
		storageService, err := storageServiceFactory.CreateForShard()
		require.ErrorContains(t, err, expectedErrForCacheString+" for PrototypeNetworkIdentityStorage")
		require.Nil(t, storageService)
	})

	t.Run("wrong config for ShardHdrNonceHashStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.ShardHdrNonceHashStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for ShardHdrNonceHashStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for TxStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.TxStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for TxStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for UnsignedTransactionStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.UnsignedTransactionStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for UnsignedTransactionStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for RewardTxStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.RewardTxStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for RewardTxStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for ReceiptsStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.ReceiptsStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for ReceiptsStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for ScheduledSCRsStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.ScheduledSCRsStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for ScheduledSCRsStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for BootstrapStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.BootstrapStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for BootstrapStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for MiniBlocksStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.MiniBlocksStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for MiniBlocksStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for MetaBlockStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.MetaBlockStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for MetaBlockStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for MetaHdrNonceHashStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.MetaHdrNonceHashStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for MetaHdrNonceHashStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for BlockHeaderStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.BlockHeaderStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for BlockHeaderStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for AccountsTrieStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.AccountsTrieStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for AccountsTrieStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for PeerAccountsTrieStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.PeerAccountsTrieStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for PeerAccountsTrieStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for StatusMetricsStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.StatusMetricsStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for StatusMetricsStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for PeerBlockBodyStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.PeerBlockBodyStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for PeerBlockBodyStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for TrieEpochRootHashStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.TrieEpochRootHashStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for TrieEpochRootHashStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for DbLookupExtensions.MiniblocksMetadataStorageConfig should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.DbLookupExtensions.MiniblocksMetadataStorageConfig.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for DbLookupExtensions.MiniblocksMetadataStorageConfig", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for DbLookupExtensions.MiniblockHashByTxHashStorageConfig should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.DbLookupExtensions.MiniblockHashByTxHashStorageConfig.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for DbLookupExtensions.MiniblockHashByTxHashStorageConfig", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for DbLookupExtensions.EpochByHashStorageConfig should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.DbLookupExtensions.EpochByHashStorageConfig.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for DbLookupExtensions.EpochByHashStorageConfig", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for DbLookupExtensions.ResultsHashesByTxHashStorageConfig should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.DbLookupExtensions.ResultsHashesByTxHashStorageConfig.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for DbLookupExtensions.ResultsHashesByTxHashStorageConfig", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for DbLookupExtensions.ESDTSuppliesStorageConfig should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.DbLookupExtensions.ESDTSuppliesStorageConfig.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for DbLookupExtensions.ESDTSuppliesStorageConfig", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for DbLookupExtensions.RoundHashStorageConfig should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.DbLookupExtensions.RoundHashStorageConfig.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for DbLookupExtensions.RoundHashStorageConfig", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for LogsAndEvents.TxLogsStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.LogsAndEvents.TxLogsStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Equal(t, expectedErrForCacheString+" for LogsAndEvents.TxLogsStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Nil(t, err)
		assert.False(t, check.IfNil(storageService))
		allStorers := storageService.GetAllStorers()
		expectedStorers := 26
		assert.Equal(t, expectedStorers, len(allStorers))

		storer, _ := storageService.GetStorer(dataRetriever.UserAccountsUnit)
		assert.NotEqual(t, "*disabled.storer", fmt.Sprintf("%T", storer))

		storer, _ = storageService.GetStorer(dataRetriever.PeerAccountsUnit)
		assert.NotEqual(t, "*disabled.storer", fmt.Sprintf("%T", storer))

		storer, err = storageService.GetStorer(dataRetriever.DRWANetworkIdentityUnit)
		assert.NoError(t, err)
		assert.NotNil(t, storer)

		_ = storageService.CloseAll()
	})
	t.Run("should work without DbLookupExtensions", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.DbLookupExtensions.Enabled = false
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Nil(t, err)
		assert.False(t, check.IfNil(storageService))
		allStorers := storageService.GetAllStorers()
		numDBLookupExtensionUnits := 6
		expectedStorers := 26 - numDBLookupExtensionUnits
		assert.Equal(t, expectedStorers, len(allStorers))
		_ = storageService.CloseAll()
	})
	t.Run("should work without TrieEpochRootHashStorage", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.CreateTrieEpochRootHashStorer = false
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Nil(t, err)
		assert.False(t, check.IfNil(storageService))
		allStorers := storageService.GetAllStorers()
		expectedStorers := 26 // we still have a storer for trie epoch root hash
		assert.Equal(t, expectedStorers, len(allStorers))
		_ = storageService.CloseAll()
	})
	t.Run("should work for import-db", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.StorageType = ImportDBStorageService
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForShard()
		assert.Nil(t, err)
		assert.False(t, check.IfNil(storageService))
		allStorers := storageService.GetAllStorers()
		expectedStorers := 25
		assert.Equal(t, expectedStorers, len(allStorers))

		storer, _ := storageService.GetStorer(dataRetriever.UserAccountsUnit)
		assert.Equal(t, "*disabled.storer", fmt.Sprintf("%T", storer))

		storer, _ = storageService.GetStorer(dataRetriever.PeerAccountsUnit)
		assert.Equal(t, "*disabled.storer", fmt.Sprintf("%T", storer))

		_, err = storageService.GetStorer(dataRetriever.DRWANetworkIdentityUnit)
		assert.Error(t, err)

		_ = storageService.CloseAll()
	})
}

func TestStorageServiceFactory_CreateForMeta(t *testing.T) {
	t.Parallel()

	expectedErrForCacheString := "not supported cache type"

	t.Run("wrong config for ShardHdrNonceHashStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.ShardHdrNonceHashStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForMeta()
		assert.Equal(t, expectedErrForCacheString+" for ShardHdrNonceHashStorage on shard 0", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for AccountsTrieStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.AccountsTrieStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForMeta()
		assert.Equal(t, expectedErrForCacheString+" for AccountsTrieStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for DbLookupExtensions.RoundHashStorageConfig should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.DbLookupExtensions.RoundHashStorageConfig.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForMeta()
		assert.Equal(t, expectedErrForCacheString+" for DbLookupExtensions.RoundHashStorageConfig", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("wrong config for LogsAndEvents.TxLogsStorage should error", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.Config.LogsAndEvents.TxLogsStorage.Cache.Type = ""
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForMeta()
		assert.Equal(t, expectedErrForCacheString+" for LogsAndEvents.TxLogsStorage", err.Error())
		assert.True(t, check.IfNil(storageService))
	})
	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForMeta()
		assert.Nil(t, err)
		assert.False(t, check.IfNil(storageService))
		allStorers := storageService.GetAllStorers()
		missingStorers := 2 // PeerChangesUnit and ShardHdrNonceHashDataUnit
		numShardHdrStorage := 3
		expectedStorers := 26 - missingStorers + numShardHdrStorage
		assert.Equal(t, expectedStorers, len(allStorers))

		storer, _ := storageService.GetStorer(dataRetriever.UserAccountsUnit)
		assert.NotEqual(t, "*disabled.storer", fmt.Sprintf("%T", storer))

		storer, _ = storageService.GetStorer(dataRetriever.PeerAccountsUnit)
		assert.NotEqual(t, "*disabled.storer", fmt.Sprintf("%T", storer))

		storer, err = storageService.GetStorer(dataRetriever.DRWANetworkIdentityUnit)
		assert.NoError(t, err)
		assert.NotNil(t, storer)

		_ = storageService.CloseAll()
	})
	t.Run("should work for import-db", func(t *testing.T) {
		t.Parallel()

		args := createMockArgument(t)
		args.StorageType = ImportDBStorageService
		storageServiceFactory, _ := NewStorageServiceFactory(args)
		storageService, err := storageServiceFactory.CreateForMeta()
		assert.Nil(t, err)
		assert.False(t, check.IfNil(storageService))
		allStorers := storageService.GetAllStorers()
		missingStorers := 2 // PeerChangesUnit and ShardHdrNonceHashDataUnit
		numShardHdrStorage := 3
		expectedStorers := 25 - missingStorers + numShardHdrStorage
		assert.Equal(t, expectedStorers, len(allStorers))

		storer, _ := storageService.GetStorer(dataRetriever.UserAccountsUnit)
		assert.Equal(t, "*disabled.storer", fmt.Sprintf("%T", storer))

		storer, _ = storageService.GetStorer(dataRetriever.PeerAccountsUnit)
		assert.Equal(t, "*disabled.storer", fmt.Sprintf("%T", storer))

		_, err = storageService.GetStorer(dataRetriever.DRWANetworkIdentityUnit)
		assert.Error(t, err)

		_ = storageService.CloseAll()
	})
}

func TestStorageServiceFactory_PartialFailureClosesIdentityStoreAndAllowsSameRootRetry(t *testing.T) {
	tests := map[string]func(*StorageServiceFactory) (dataRetriever.StorageService, error){
		"shard": (*StorageServiceFactory).CreateForShard,
		"meta":  (*StorageServiceFactory).CreateForMeta,
	}
	for name, create := range tests {
		name, create := name, create
		t.Run(name, func(t *testing.T) {
			args := createMockArgument(t)
			args.Config.TrieEpochRootHashStorage.Cache.Type = ""
			firstFactory, err := NewStorageServiceFactory(args)
			require.NoError(t, err)
			service, err := create(firstFactory)
			require.Error(t, err)
			require.Nil(t, service)

			args.Config.TrieEpochRootHashStorage = createMockStorageConfig("TrieEpochRootHashStorage")
			secondFactory, err := NewStorageServiceFactory(args)
			require.NoError(t, err)
			service, err = create(secondFactory)
			require.NoError(t, err, "a partial first attempt must not retain a LevelDB lock")
			require.NoError(t, service.CloseAll())
		})
	}
}

func TestStorageServiceFactory_IdentityCloseReopenDestroyAndArchivedSiblingPreservation(t *testing.T) {
	args := createMockArgument(t)
	archiveRoot := t.TempDir()
	archiveSentinel := filepath.Join(archiveRoot, "preserved-generation.txt")
	require.NoError(t, os.WriteFile(archiveSentinel, []byte("preserve"), 0o600))
	key := []byte("identity-key")
	value := []byte("identity-value")

	firstFactory, err := NewStorageServiceFactory(args)
	require.NoError(t, err)
	first, err := firstFactory.CreateForShard()
	require.NoError(t, err)
	require.NoError(t, first.Put(dataRetriever.DRWANetworkIdentityUnit, key, value))
	require.NoError(t, first.CloseAll())

	secondFactory, err := NewStorageServiceFactory(args)
	require.NoError(t, err)
	second, err := secondFactory.CreateForShard()
	require.NoError(t, err)
	loaded, err := second.Get(dataRetriever.DRWANetworkIdentityUnit, key)
	require.NoError(t, err)
	require.Equal(t, value, loaded)
	require.NoError(t, second.Destroy())

	thirdFactory, err := NewStorageServiceFactory(args)
	require.NoError(t, err)
	third, err := thirdFactory.CreateForShard()
	require.NoError(t, err)
	_, err = third.Get(dataRetriever.DRWANetworkIdentityUnit, key)
	require.Error(t, err, "fresh-generation recreation must not silently restore destroyed active state")
	require.NoError(t, third.CloseAll())

	preserved, err := os.ReadFile(archiveSentinel)
	require.NoError(t, err)
	require.Equal(t, []byte("preserve"), preserved, "active-root lifecycle operations must not touch an archived sibling")
}

func TestStorageServiceFactory_DRWAIdentityStorageTypeMatrix(t *testing.T) {
	createMethods := map[string]func(*StorageServiceFactory) (dataRetriever.StorageService, error){
		"shard": (*StorageServiceFactory).CreateForShard,
		"meta":  (*StorageServiceFactory).CreateForMeta,
	}
	storageTypes := []StorageServiceType{
		ProcessStorageService,
		BootstrapStorageService,
		ImportDBStorageService,
	}

	for createName, create := range createMethods {
		createName, create := createName, create
		for _, storageType := range storageTypes {
			storageType := storageType
			t.Run(createName+"/"+string(storageType)+"/valid", func(t *testing.T) {
				args := createMockArgument(t)
				args.StorageType = storageType
				storageServiceFactory, err := NewStorageServiceFactory(args)
				require.NoError(t, err)
				storageService, err := create(storageServiceFactory)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, storageService.CloseAll()) })

				_, identityErr := storageService.GetStorer(dataRetriever.DRWANetworkIdentityUnit)
				if storageType == ProcessStorageService {
					require.NoError(t, identityErr, "process storage must contain the retained identity unit")
				} else {
					require.Error(t, identityErr, "%s storage must not construct the retained identity unit", storageType)
				}
			})

			t.Run(createName+"/"+string(storageType)+"/invalid-cache", func(t *testing.T) {
				args := createMockArgument(t)
				args.StorageType = storageType
				args.Config.DRWANetworkIdentityStorage.Cache.Type = ""
				storageServiceFactory, err := NewStorageServiceFactory(args)
				require.NoError(t, err)
				storageService, err := create(storageServiceFactory)
				if storageType == ProcessStorageService {
					require.ErrorContains(t, err, "not supported cache type for PrototypeNetworkIdentityStorage")
					require.Nil(t, storageService)
				} else {
					require.NoError(t, err, "%s must not consume the process-only identity cache configuration", storageType)
					require.NoError(t, storageService.CloseAll())
				}
			})
		}
	}

	invalidPersistenceConfigurations := map[string]func(*config.StorageConfig){
		"absent": func(storageConfig *config.StorageConfig) {
			*storageConfig = config.StorageConfig{}
		},
		"database-type": func(storageConfig *config.StorageConfig) {
			storageConfig.DB.Type = string(storageunit.MemoryDB)
		},
		"batch-size": func(storageConfig *config.StorageConfig) {
			storageConfig.DB.MaxBatchSize = 2
		},
		"batch-delay": func(storageConfig *config.StorageConfig) {
			storageConfig.DB.BatchDelaySeconds = 0
		},
		"database-path": func(storageConfig *config.StorageConfig) {
			storageConfig.DB.FilePath = ""
		},
	}
	for _, storageType := range storageTypes {
		storageType := storageType
		for mutationName, mutate := range invalidPersistenceConfigurations {
			mutationName, mutate := mutationName, mutate
			t.Run(string(storageType)+"/invalid-"+mutationName, func(t *testing.T) {
				args := createMockArgument(t)
				args.StorageType = storageType
				mutate(&args.Config.DRWANetworkIdentityStorage)
				storageServiceFactory, err := NewStorageServiceFactory(args)
				require.ErrorIs(t, err, errInvalidDRWANetworkIdentityStorage,
					"the retained-identity persistence contract is validated uniformly before service-type selection")
				require.Nil(t, storageServiceFactory)
			})
		}
	}
}
