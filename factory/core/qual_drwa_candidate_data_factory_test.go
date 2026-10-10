package core

import (
	"fmt"
	"os"
	"testing"

	nativeCore "github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/statistics"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	cryptoFactory "github.com/multiversx/mx-chain-go/factory/crypto"
	dataFactory "github.com/multiversx/mx-chain-go/factory/data"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/storage"
	factoryStub "github.com/multiversx/mx-chain-go/testscommon/factory"
	"github.com/multiversx/mx-chain-go/testscommon/statusHandler"
	"github.com/stretchr/testify/require"
)

// T09-M30: native loaded-snapshot assembly and orderly storer reopen only.
// Epoch/shard inputs and status facade are synthetic. NTP is disabled by the
// shared core args helper; native ephemeral keys stay in memory. This does not
// launch a node or prove deployment admission, crash durability or DRWA recovery.
func TestQualDRWACandidateDataFactory(t *testing.T) {
	for _, epoch := range []uint32{0, 3} {
		for _, shard := range []uint32{0, 1, 2, nativeCore.MetachainShardId} {
			t.Run(fmt.Sprintf("epoch_%d_shard_%d", epoch, shard), func(t *testing.T) {
				coreArgs := qualDRWACandidateCoreArgs(t)
				coreFactory, err := NewCoreComponentsFactory(coreArgs)
				require.NoError(t, err)
				coreHandler, err := NewManagedCoreComponents(coreFactory)
				require.NoError(t, err)
				require.NoError(t, coreHandler.Create())
				t.Cleanup(func() { require.NoError(t, coreHandler.Close()) })
				require.NoError(t, coreHandler.CheckSubcomponents())

				cryptoArgs := qualDRWACandidateCryptoArgs(t)
				cryptoArgs.CoreComponentsHolder = coreHandler
				cryptoNativeFactory, err := cryptoFactory.NewCryptoComponentsFactory(cryptoArgs)
				require.NoError(t, err)
				cryptoHandler, err := cryptoFactory.NewManagedCryptoComponents(cryptoNativeFactory)
				require.NoError(t, err)
				require.NoError(t, cryptoHandler.Create())
				t.Cleanup(func() { require.NoError(t, cryptoHandler.Close()) })
				require.NoError(t, cryptoHandler.CheckSubcomponents())
				coordinator, err := sharding.NewMultiShardCoordinator(3, shard)
				require.NoError(t, err)
				args := dataFactory.DataComponentsFactoryArgs{
					Config: coreArgs.Config, PrefsConfig: cryptoArgs.PrefsConfig.Preferences,
					ShardCoordinator: coordinator, Core: coreHandler, Crypto: cryptoHandler,
					StatusCore: &factoryStub.StatusCoreComponentsStub{
						AppStatusHandlerField:  &statusHandler.AppStatusHandlerStub{},
						StateStatsHandlerField: statistics.NewStateStatistics(),
					},
					CurrentEpoch: epoch, NodeProcessingMode: common.Normal,
				}
				// Invalid pruning count is rejected before native storage allocation.
				dbPath := coreHandler.PathHandler().DatabasePath()
				_, err = os.Stat(dbPath)
				require.True(t, os.IsNotExist(err))
				invalid := args
				invalid.Config.StoragePruning.NumActivePersisters = 0
				invalidFactory, err := dataFactory.NewDataComponentsFactory(invalid)
				require.NoError(t, err)
				components, err := invalidFactory.Create()
				require.ErrorIs(t, err, storage.ErrInvalidNumberOfActivePersisters)
				require.Nil(t, components)
				_, err = os.Stat(dbPath)
				require.True(t, os.IsNotExist(err))

				key, value := []byte("T09 public storage probe"), []byte("native orderly reopen")
				for _, reopen := range []bool{false, true} {
					factory, err := dataFactory.NewDataComponentsFactory(args)
					require.NoError(t, err)
					handler, err := dataFactory.NewManagedDataComponents(factory)
					require.NoError(t, err)
					t.Cleanup(func() { require.NoError(t, handler.Close()) })
					require.NoError(t, handler.Create())
					require.NoError(t, handler.CheckSubcomponents())
					require.NotNil(t, handler.Blockchain())
					require.NotNil(t, handler.Datapool())
					require.NotNil(t, handler.MiniBlocksProvider())
					storer, err := handler.StorageService().GetStorer(dataRetriever.MiniBlockUnit)
					require.NoError(t, err)
					if !reopen {
						require.NoError(t, storer.Put(key, value))
					}
					storer.ClearCache()
					got, err := storer.Get(key)
					require.NoError(t, err)
					require.Equal(t, value, got)
					require.NoError(t, handler.Close())
					require.Nil(t, handler.StorageService())
				}

			})
		}
	}
}
