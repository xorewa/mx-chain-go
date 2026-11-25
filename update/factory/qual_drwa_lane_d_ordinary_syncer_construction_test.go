package factory

import (
	"testing"
	"time"

	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/cache"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/hashingMocks"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	containers "github.com/multiversx/mx-chain-go/update/container"
	"github.com/multiversx/mx-chain-go/update/genesis"
	"github.com/multiversx/mx-chain-go/update/mock"
	"github.com/stretchr/testify/require"
)

// Construct ordinary adapters with existing in-memory mocks; do not start sync.
func TestQualOrdinaryAccountsSyncerFactoryConstruction(t *testing.T) {
	t.Parallel()

	args := ArgsNewAccountsDBSyncersContainerFactory{
		TrieCacher:                cache.NewCacherMock(),
		RequestHandler:            &testscommon.RequestHandlerStub{},
		ShardCoordinator:          &mock.CoordinatorStub{},
		Hasher:                    &hashingMocks.HasherMock{},
		Marshalizer:               marshallerMock.MarshalizerMock{},
		TrieStorageManager:        &storageManager.StorageManagerStub{},
		TimoutGettingTrieNode:     time.Second,
		MaxTrieLevelInMemory:      2,
		NumConcurrentTrieSyncers:  1,
		MaxHardCapForMissingNodes: 100,
		TrieSyncerVersion:         2,
		AddressPubKeyConverter:    &testscommon.PubkeyConverterStub{},
		EnableEpochsHandler:       &enableEpochsHandlerMock.EnableEpochsHandlerStub{},
	}
	factory, err := NewAccountsDBSContainerFactory(args)
	require.NoError(t, err)
	require.NotNil(t, factory)
	require.Same(t, args.RequestHandler, factory.requestHandler)
	require.Same(t, args.TrieStorageManager, factory.trieStorageManager)
	require.Equal(t, args.TimoutGettingTrieNode, factory.timeoutGettingTrieNode)
	require.Equal(t, args.NumConcurrentTrieSyncers, factory.numConcurrentTrieSyncers)
	require.Nil(t, factory.container)

	factory.container = containers.NewAccountsDBSyncersContainer()
	const shard = uint32(1)
	require.NoError(t, factory.createUserAccountsSyncer(shard))
	require.Equal(t, 1, factory.container.Len())
	adapter, err := factory.container.Get(genesis.CreateTrieIdentifier(shard, genesis.UserAccount))
	require.NoError(t, err)
	require.NotNil(t, adapter)
	require.False(t, adapter.IsInterfaceNil())
}
