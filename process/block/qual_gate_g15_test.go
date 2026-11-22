package block

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	coreblock "github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/receipts"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/cache"
	dataMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	storageMock "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/stretchr/testify/require"
)

// qualG15Fixture enters the real base-processor and receipts-repository routes.
// Storer boundaries record ordered writes; pruning's real persisters are tested
// separately. No recorder models publication decisions or implements guards.
func qualG15Fixture(t *testing.T, meta bool, fail string) (*baseProcessor, data.HeaderHandler, *[]string, error) {
	t.Helper()
	events := []string{}
	sentinel := errors.New("G15 storage sentinel")
	hash := []byte("execution-header")
	mbHash := []byte("mini-block")
	const epoch uint32 = 17 // synthetic nonzero execution header epoch; not a deployment value
	base := &coreblock.BaseExecutionResult{HeaderHash: hash, HeaderEpoch: epoch}
	mbHeaders := []coreblock.MiniBlockHeader{{Hash: mbHash, SenderShardID: 0, ReceiverShardID: 0}}
	var result data.BaseExecutionResultHandler = &coreblock.ExecutionResult{BaseExecutionResult: base, MiniBlockHeaders: mbHeaders, ReceiptsHash: []byte("receipt-key")}
	if meta {
		result = &coreblock.MetaExecutionResult{ExecutionResult: &coreblock.BaseMetaExecutionResult{BaseExecutionResult: base}, MiniBlockHeaders: mbHeaders, ReceiptsHash: []byte("receipt-key")}
	}
	header := &testscommon.HeaderHandlerStub{
		IsHeaderV3Called:                  func() bool { return true },
		GetExecutionResultsHandlersCalled: func() []data.BaseExecutionResultHandler { return []data.BaseExecutionResultHandler{result} },
	}
	proto := &marshal.GogoProtoMarshalizer{}
	bp := getDefaultBaseProcessor()
	bp.marshalizer = &marshallerMock.MarshalizerStub{MarshalCalled: func(value interface{}) ([]byte, error) {
		if fail == "marshal" && value == result {
			return nil, sentinel
		}
		return proto.Marshal(value)
	}}
	write := func(stage string) error {
		events = append(events, stage)
		if fail == stage {
			return sentinel
		}
		return nil
	}
	bp.store = &storageMock.ChainStorerStub{GetStorerCalled: func(unit dataRetriever.UnitType) (storage.Storer, error) {
		if unit == dataRetriever.ExecutionResultsUnit && fail == "lookup" {
			return nil, sentinel
		}
		stage := ""
		switch unit {
		case dataRetriever.ReceiptsUnit:
			stage = "receipts"
		case dataRetriever.MiniBlockUnit:
			stage = "miniblocks"
		case dataRetriever.UnsignedTransactionUnit:
			stage = "intermediate"
		case dataRetriever.ExecutionResultsUnit:
			stage = "publish"
		default:
			t.Fatalf("unexpected storage unit %v", unit)
		}
		return &storageMock.StorerStub{
			PutCalled: func(key, value []byte) error {
				require.NotEmpty(t, value)
				require.NotEqual(t, "publish", stage)
				return write(stage)
			},
			PutInEpochCalled: func(key, value []byte, gotEpoch uint32) error {
				require.Equal(t, "publish", stage)
				require.Equal(t, hash, key)
				require.Equal(t, epoch, gotEpoch)
				require.NotEmpty(t, value)
				return write(stage)
			},
		}, nil
	}}
	repo, err := receipts.NewReceiptsRepository(receipts.ArgsNewReceiptsRepository{Marshaller: proto, Hasher: &testscommon.HasherStub{}, Store: bp.store})
	require.NoError(t, err)
	bp.receiptsRepository = repo
	bp.dataPool = &dataMock.PoolsHolderStub{
		ExecutedMiniBlocksCalled: func() storage.Cacher {
			return &cache.CacherStub{GetCalled: func(key []byte) (interface{}, bool) {
				if string(key) == string(hash) {
					return []*coreblock.MiniBlock{{TxHashes: [][]byte{[]byte("receipt-tx")}}}, true
				}
				require.Equal(t, mbHash, key)
				return []byte("cached-miniblock"), true
			}}
		},
		PostProcessTransactionsCalled: func() storage.Cacher {
			return &cache.CacherStub{GetCalled: func(key []byte) (interface{}, bool) {
				require.Equal(t, hash, key)
				return map[coreblock.Type]map[string]data.TransactionHandler{coreblock.SmartContractResultBlock: {"intermediate-tx": &transaction.Transaction{}}}, true
			}}
		},
	}
	return bp, header, &events, sentinel
}

func TestQualG15PublicationOrderAndEpoch(t *testing.T) {
	for _, meta := range []bool{false, true} {
		name := "shard"
		if meta {
			name = "meta"
		}
		t.Run(name, func(t *testing.T) {
			bp, h, events, _ := qualG15Fixture(t, meta, "")
			require.NoError(t, bp.saveExecutedData(h))
			require.Equal(t, []string{"receipts", "miniblocks", "intermediate", "publish"}, *events)
		})
	}
}

func TestQualG15NilResultBlocksPublication(t *testing.T) {
	var typedNil *coreblock.ExecutionResult
	for _, result := range []data.BaseExecutionResultHandler{nil, typedNil} {
		bp, h, events, _ := qualG15Fixture(t, false, "")
		h.(*testscommon.HeaderHandlerStub).GetExecutionResultsHandlersCalled = func() []data.BaseExecutionResultHandler { return []data.BaseExecutionResultHandler{result} }
		require.ErrorIs(t, bp.saveExecutedData(h), process.ErrNilExecutionResultHandler)
		require.Empty(t, *events)
		require.ErrorIs(t, bp.saveExecutionResult(result), process.ErrNilExecutionResultHandler)
		require.Empty(t, *events)
	}
	bp, h, events, _ := qualG15Fixture(t, false, "")
	valid := h.GetExecutionResultsHandlers()[0]
	h.(*testscommon.HeaderHandlerStub).GetExecutionResultsHandlersCalled = func() []data.BaseExecutionResultHandler { return []data.BaseExecutionResultHandler{valid, nil} }
	require.ErrorIs(t, bp.saveExecutedData(h), process.ErrNilExecutionResultHandler)
	require.Equal(t, []string{"receipts", "miniblocks", "intermediate", "publish"}, *events, "nil later result is not batch rollback")
}

func TestQualG15StorageErrorsBlockPublication(t *testing.T) {
	cases := []struct {
		stage string
		want  []string
	}{
		{"receipts", []string{"receipts"}}, {"miniblocks", []string{"receipts", "miniblocks"}},
		{"intermediate", []string{"receipts", "miniblocks", "intermediate"}},
		{"marshal", []string{"receipts", "miniblocks", "intermediate"}}, {"lookup", []string{"receipts", "miniblocks", "intermediate"}},
		{"publish", []string{"receipts", "miniblocks", "intermediate", "publish"}},
	}
	for _, tc := range cases {
		t.Run(tc.stage, func(t *testing.T) {
			bp, h, events, sentinel := qualG15Fixture(t, false, tc.stage)
			err := bp.saveExecutedData(h)
			if tc.stage == "receipts" {
				require.ErrorContains(t, err, sentinel.Error())
			} else {
				require.ErrorIs(t, err, sentinel)
			}
			require.Equal(t, tc.want, *events)
		})
	}
}
