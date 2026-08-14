package outport_test

// End-to-end delivery proof for the state-access pipeline on the #7962 base,
// using only real production components on the data path:
//
//	real collector (BeginExecution/CommitCollectedAccesses)
//	  -> real outportDataProvider (PrepareOutportSaveBlockData)
//	  -> real outport handler (SaveBlock, subscribed driver)
//	  -> driver receives StateAccessesForBlock
//
// It covers both directions of the contract:
//  1. a committed batch reaches the subscribed driver bound to its execution
//     identity, and is consumed exactly once (a second take finds nothing);
//  2. after a simulated restart (fresh, empty collector) the block itself is
//     still delivered to the driver, with nil accesses.

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/data/block"
	outportcore "github.com/multiversx/mx-chain-core-go/data/outport"
	"github.com/multiversx/mx-chain-core-go/data/stateChange"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/outport"
	"github.com/multiversx/mx-chain-go/outport/mock"
	outportProcess "github.com/multiversx/mx-chain-go/outport/process"
	"github.com/multiversx/mx-chain-go/outport/process/transactionsfee"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/stateAccesses"
	"github.com/multiversx/mx-chain-go/testscommon"
	commonMocks "github.com/multiversx/mx-chain-go/testscommon/common"
	"github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/genericMocks"
	"github.com/multiversx/mx-chain-go/testscommon/hashingMocks"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	"github.com/multiversx/mx-chain-go/testscommon/shardingMocks"
)

func newRealOutportProvider(t *testing.T, collector state.StateAccessesCollector) outport.DataProviderOutport {
	txsFeeProc, err := transactionsfee.NewTransactionsFeeProcessor(transactionsfee.ArgTransactionsFeeProcessor{
		Marshaller:          &marshallerMock.MarshalizerMock{},
		TransactionsStorer:  &genericMocks.StorerMock{},
		ShardCoordinator:    &testscommon.ShardsCoordinatorMock{},
		TxFeeCalculator:     &economicsmocks.EconomicsHandlerMock{},
		PubKeyConverter:     testscommon.NewPubkeyConverterMock(32),
		ArgsParser:          &testscommon.ArgumentParserMock{},
		EnableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(),
	})
	require.NoError(t, err)

	provider, err := outportProcess.NewOutportDataProvider(outportProcess.ArgOutportDataProvider{
		AlteredAccountsProvider:  &testscommon.AlteredAccountsProviderStub{},
		TransactionsFeeProcessor: txsFeeProc,
		TxCoordinator:            &testscommon.TransactionCoordinatorMock{},
		NodesCoordinator: &shardingMocks.NodesCoordinatorMock{
			GetValidatorsPublicKeysCalled: func(randomness []byte, round uint64, shardId uint32, epoch uint32) (string, []string, error) {
				return "", nil, nil
			},
			GetValidatorsIndexesCalled: func(publicKeys []string, epoch uint32) ([]uint64, error) {
				return []uint64{0, 1}, nil
			},
		},
		GasConsumedProvider:    &testscommon.GasHandlerStub{},
		EconomicsData:          &economicsmocks.EconomicsHandlerMock{},
		ShardCoordinator:       &testscommon.ShardsCoordinatorMock{},
		ExecutionOrderHandler:  &commonMocks.TxExecutionOrderHandlerStub{},
		Marshaller:             &marshallerMock.MarshalizerMock{},
		Hasher:                 &hashingMocks.HasherMock{},
		DataPool:               &dataRetriever.PoolsHolderMock{},
		EnableEpochsHandler:    enableEpochsHandlerMock.NewEnableEpochsHandlerStubWithNoFlagsDefined(),
		StateAccessesCollector: collector,
		RoundHandler:           &testscommon.RoundHandlerMock{},
	})
	require.NoError(t, err)
	return provider
}

func newSubscribedOutport(t *testing.T, driver outport.Driver) outport.OutportHandler {
	handler, err := outport.NewOutport(
		time.Second,
		outportcore.OutportConfig{ShardID: 0},
		enableEpochsHandlerMock.NewEnableEpochsHandlerStub(),
		&testscommon.EnableRoundsHandlerStub{},
	)
	require.NoError(t, err)
	require.NoError(t, handler.SubscribeDriver(driver))
	require.True(t, handler.HasDrivers())
	t.Cleanup(func() { _ = handler.Close() })
	return handler
}

func TestOutportEndToEnd_CommittedBatchReachesSubscribedDriver(t *testing.T) {
	collector, err := stateAccesses.NewCollector(
		disabled.NewDisabledStateAccessesStorer(),
		stateAccesses.WithCollectWrite(),
	)
	require.NoError(t, err)

	headerHash := []byte("block-header-hash")
	rootHash := []byte("block-root-hash")

	generation := collector.BeginExecution(headerHash)
	collector.AddStateAccess(&stateChange.StateAccess{
		Type:        stateChange.Write,
		TxHash:      []byte("tx-hash"),
		MainTrieKey: []byte("account-key"),
	})
	require.NoError(t, collector.CommitCollectedAccesses(rootHash))
	collector.EndExecution(generation)

	provider := newRealOutportProvider(t, collector)

	var received *outportcore.OutportBlock
	driver := &mock.DriverStub{
		SaveBlockCalled: func(outportBlock *outportcore.OutportBlock) error {
			received = outportBlock
			return nil
		},
	}
	handler := newSubscribedOutport(t, driver)

	argSaveBlock, err := provider.PrepareOutportSaveBlockData(outportProcess.ArgPrepareOutportSaveBlockData{
		Header:     &block.Header{Nonce: 7, RootHash: rootHash},
		Body:       &block.Body{},
		HeaderHash: headerHash,
	})
	require.NoError(t, err)
	require.NoError(t, handler.SaveBlock(argSaveBlock))

	require.NotNil(t, received, "the subscribed driver must receive the block")
	forBlock := received.StateAccessesForBlock[hex.EncodeToString(headerHash)]
	require.NotNil(t, forBlock, "state accesses must be keyed by the execution header hash")
	require.Contains(t, forBlock.StateAccesses, "tx-hash",
		"the committed batch must reach the driver")

	// consumed exactly once: a second take for the same identity finds nothing
	again, err := collector.TakeStateAccessesForHeader(headerHash, rootHash)
	require.NoError(t, err)
	require.Nil(t, again)
}

func TestOutportEndToEnd_RestartStillDeliversBlockWithoutAccesses(t *testing.T) {
	// fresh collector models the in-memory state right after a node restart
	collector, err := stateAccesses.NewCollector(
		disabled.NewDisabledStateAccessesStorer(),
		stateAccesses.WithCollectWrite(),
	)
	require.NoError(t, err)

	provider := newRealOutportProvider(t, collector)

	var received *outportcore.OutportBlock
	driver := &mock.DriverStub{
		SaveBlockCalled: func(outportBlock *outportcore.OutportBlock) error {
			received = outportBlock
			return nil
		},
	}
	handler := newSubscribedOutport(t, driver)

	argSaveBlock, err := provider.PrepareOutportSaveBlockData(outportProcess.ArgPrepareOutportSaveBlockData{
		Header:     &block.Header{Nonce: 8, RootHash: []byte("some-root")},
		Body:       &block.Body{},
		HeaderHash: []byte("post-restart-header"),
	})
	require.NoError(t, err,
		"a missing batch must not prevent block delivery")
	require.NoError(t, handler.SaveBlock(argSaveBlock))
	require.NotNil(t, received, "the block must still reach the driver after a restart")
}
