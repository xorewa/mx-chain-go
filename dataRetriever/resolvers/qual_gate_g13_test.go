package resolvers_test

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/batch"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/dataRetriever/mock"
	"github.com/multiversx/mx-chain-go/dataRetriever/resolvers"
	"github.com/multiversx/mx-chain-go/p2p"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/p2pmocks"
	storageStubs "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/stretchr/testify/require"
)

func TestQualGateG13RejectBeforeLookupAndSend(t *testing.T) {
	marshalizer := &mock.MarshalizerMock{}
	badArray, err := marshalizer.Marshal(&batch.Batch{Data: [][]byte{make([]byte, 32), make([]byte, 33)}})
	require.NoError(t, err)
	many := make([][]byte, common.MaxHashesInRequest+1)
	for i := range many {
		many[i] = []byte{byte(i)}
	}
	manyArray, err := marshalizer.Marshal(&batch.Batch{Data: many})
	require.NoError(t, err)
	for _, c := range []struct {
		name  string
		kind  dataRetriever.RequestDataType
		value []byte
		deny  bool
	}{
		{"oversized_single", dataRetriever.HashType, make([]byte, 33), true},
		{"oversized_second_array_member", dataRetriever.HashArrayType, badArray, true},
		{"strict_array_count", dataRetriever.HashArrayType, manyArray, true},
		{"valid_single", dataRetriever.HashType, make([]byte, 32), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			args := createMockArgTxResolver()
			lookups, reads, sends := 0, 0, 0
			pool := testscommon.NewShardedDataStub()
			pool.SearchFirstDataCalled = func([]byte) (interface{}, bool) { lookups++; return &transaction.Transaction{Nonce: 1}, true }
			args.TxPool = pool
			args.TxStorage = &storageStubs.StorerStub{GetCalled: func([]byte) ([]byte, error) { reads++; return nil, nil }}
			args.SenderResolver = &mock.TopicResolverSenderStub{SendCalled: func([]byte, core.PeerID, p2p.MessageHandler) error { sends++; return nil }}
			r, err := resolvers.NewTxResolver(args)
			require.NoError(t, err)
			id, err := r.ProcessReceivedMessage(createRequestMsg(c.kind, c.value), connectedPeerId, &p2pmocks.MessengerStub{})
			if c.deny {
				require.ErrorIs(t, err, dataRetriever.ErrBadRequest)
				require.Nil(t, id)
				require.Zero(t, lookups, "validation before pool reads")
				require.Zero(t, reads, "validation before storage reads")
				require.Zero(t, sends, "validation before response publication")
			} else {
				require.NoError(t, err)
				require.Empty(t, id)
				require.Equal(t, 1, lookups)
				require.Zero(t, reads)
				require.Equal(t, 1, sends)
			}
		})
	}
}
