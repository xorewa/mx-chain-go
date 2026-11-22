package resolvers_test

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/batch"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/dataRetriever/mock"
	"github.com/multiversx/mx-chain-go/dataRetriever/resolvers"
	"github.com/multiversx/mx-chain-go/p2p"
	"github.com/multiversx/mx-chain-go/testscommon/cache"
	"github.com/multiversx/mx-chain-go/testscommon/p2pmocks"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/stretchr/testify/require"
)

func TestQualG31MiniblockArrayBoundsBeforeLookup(t *testing.T) {
	args := createMockArgMiniblockResolver()
	reads, packs, sends := 0, 0, 0
	args.MiniBlockPool.(*cache.CacherStub).PeekCalled = func([]byte) (interface{}, bool) {
		reads++
		return nil, false
	}
	args.DataPacker = &mock.DataPackerStub{PackDataInChunksCalled: func([][]byte, int) ([][]byte, error) {
		packs++
		return nil, nil
	}}
	args.SenderResolver = &mock.TopicResolverSenderStub{SendCalled: func([]byte, core.PeerID, p2p.MessageHandler) error {
		sends++
		return nil
	}}
	resolver, err := resolvers.NewMiniblockResolver(args)
	require.NoError(t, err)
	encoded, err := args.Marshaller.Marshal(&batch.Batch{Data: [][]byte{make([]byte, common.HashSize), make([]byte, common.HashSize+1)}})
	require.NoError(t, err)
	id, err := resolver.ProcessReceivedMessage(createRequestMsg(dataRetriever.HashArrayType, encoded), fromConnectedPeerId, &p2pmocks.MessengerStub{})
	require.ErrorIs(t, err, dataRetriever.ErrBadRequest)
	require.Nil(t, id)
	require.Zero(t, reads)
	require.Zero(t, packs)
	require.Zero(t, sends)
}

func TestQualG31TrieArrayBoundsBeforeLookup(t *testing.T) {
	args := createMockArgTrieNodeResolver()
	reads, sends := 0, 0
	args.TrieDataGetter = &trieMock.TrieStub{GetSerializedNodeCalled: func([]byte) ([]byte, error) {
		reads++
		return nil, nil
	}}
	args.SenderResolver = &mock.TopicResolverSenderStub{SendCalled: func([]byte, core.PeerID, p2p.MessageHandler) error {
		sends++
		return nil
	}}
	resolver, err := resolvers.NewTrieNodeResolver(args)
	require.NoError(t, err)
	encoded, err := args.Marshaller.Marshal(&batch.Batch{Data: [][]byte{make([]byte, common.HashSize), make([]byte, common.HashSize+1)}})
	require.NoError(t, err)
	id, err := resolver.ProcessReceivedMessage(createRequestMsg(dataRetriever.HashArrayType, encoded), fromConnectedPeer, &p2pmocks.MessengerStub{})
	require.ErrorIs(t, err, dataRetriever.ErrBadRequest)
	require.Nil(t, id)
	require.Zero(t, reads)
	require.Zero(t, sends)
}
