package drwa

// Copied, with renamed functions only, from the block package's own test
// fixtures (process/block/baseProcess_test.go and metablock_test.go), which a
// test of another package cannot import. They build the arguments of a real
// shard and a real metachain block processor around mocks. SP2-24 uses them to
// run DRWA time consumers inside a real ProcessBlockProposal pass.

import (
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/graceperiod"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/dataRetriever/blockchain"
	proofscache "github.com/multiversx/mx-chain-go/dataRetriever/dataPool/proofsCache"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/aotSelection"
	headersCache "github.com/multiversx/mx-chain-go/process/asyncExecution/cache"
	"github.com/multiversx/mx-chain-go/process/asyncExecution/executionManager"
	"github.com/multiversx/mx-chain-go/process/asyncExecution/executionTrack"
	blproc "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/process/block/bootstrapStorage"
	"github.com/multiversx/mx-chain-go/process/block/headerForBlock"
	"github.com/multiversx/mx-chain-go/process/coordinator"
	"github.com/multiversx/mx-chain-go/process/estimator"
	"github.com/multiversx/mx-chain-go/process/factory/containers"
	"github.com/multiversx/mx-chain-go/process/missingData"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/storage/database"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/cache"
	commonMocks "github.com/multiversx/mx-chain-go/testscommon/common"
	dataRetrieverMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/dblookupext"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	"github.com/multiversx/mx-chain-go/testscommon/factory"
	"github.com/multiversx/mx-chain-go/testscommon/hashingMocks"
	"github.com/multiversx/mx-chain-go/testscommon/mbSelection"
	"github.com/multiversx/mx-chain-go/testscommon/outport"
	"github.com/multiversx/mx-chain-go/testscommon/processMocks"
	"github.com/multiversx/mx-chain-go/testscommon/shardingMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	statusHandlerMock "github.com/multiversx/mx-chain-go/testscommon/statusHandler"
	storageStubs "github.com/multiversx/mx-chain-go/testscommon/storage"
	"sync/atomic"
	"time"
)

func qualSP224BlockCreateArgBaseProcessor(
	coreComponents *mock.CoreComponentsMock,
	dataComponents *mock.DataComponentsMock,
	bootstrapComponents *mock.BootstrapComponentsMock,
	statusComponents *mock.StatusComponentsMock,
) blproc.ArgBaseProcessor {
	nodesCoordinatorInstance := shardingMocks.NewNodesCoordinatorMock()
	argsHeaderValidator := blproc.ArgsHeaderValidator{
		Hasher:              &hashingMocks.HasherMock{},
		Marshalizer:         &mock.MarshalizerMock{},
		EnableEpochsHandler: &enableEpochsHandlerMock.EnableEpochsHandlerStub{},
	}
	headerValidator, _ := blproc.NewHeaderValidator(argsHeaderValidator)

	startHeaders := qualSP224BlockCreateGenesisBlocks(mock.NewOneShardCoordinatorMock())

	accountsDb := make(map[state.AccountsDbIdentifier]state.AccountsAdapter)
	accounts := &stateMock.AccountsStub{
		RootHashCalled: func() ([]byte, error) {
			return nil, nil
		},
		RecreateTrieIfNeededCalled: func(options common.RootHashHolder) error {
			return nil
		},
		CommitCalled: func() ([]byte, error) {
			return nil, nil
		},
	}
	accountsDb[state.UserAccountsState] = accounts

	statusCoreComponents := &factory.StatusCoreComponentsStub{
		AppStatusHandlerField: &statusHandlerMock.AppStatusHandlerStub{},
	}

	blockTracker := mock.NewBlockTrackerMock(bootstrapComponents.ShardCoordinator(), startHeaders)
	var headersForBlock blproc.HeadersForBlock = &testscommon.HeadersForBlockMock{}
	if !check.IfNil(coreComponents) && !check.IfNil(bootstrapComponents) && !check.IfNil(dataComponents) {
		headersForBlock, _ = headerForBlock.NewHeadersForBlock(headerForBlock.ArgHeadersForBlock{
			DataPool:              dataComponents.DataPool,
			RequestHandler:        &testscommon.RequestHandlerStub{},
			EnableEpochsHandler:   coreComponents.EnableEpochsHandler(),
			ShardCoordinator:      bootstrapComponents.ShardCoordinator(),
			BlockTracker:          blockTracker,
			TxCoordinator:         &testscommon.TransactionCoordinatorMock{},
			RoundHandler:          coreComponents.RoundHandler(),
			ProcessConfigsHandler: testscommon.GetProcessConfigsHandlerWithExtraDelayForRequestBlockInfo(100 * time.Millisecond),
			GenesisNonce:          0,
		})
	}

	var blockDataRequester process.BlockDataRequester
	var inclusionEstimator process.InclusionEstimator
	var execManager process.ExecutionManager
	var mbSelectionSession blproc.MiniBlocksSelectionSession
	var execResultsVerifier blproc.ExecutionResultsVerifier
	var missingDataResolver blproc.MissingDataResolver
	if check.IfNil(dataComponents) || check.IfNil(dataComponents.Datapool()) || check.IfNil(coreComponents) || check.IfNil(bootstrapComponents) {
		inclusionEstimator = &processMocks.InclusionEstimatorMock{}
		mbSelectionSession = &mbSelection.MiniBlockSelectionSessionStub{}
		execResultsVerifier = &processMocks.ExecutionResultsVerifierMock{}
		missingDataResolver = &processMocks.MissingDataResolverMock{}
	} else {
		preprocContainer := containers.NewPreProcessorsContainer()
		blockDataRequesterArgs := coordinator.BlockDataRequestArgs{
			RequestHandler:      &testscommon.RequestHandlerStub{},
			MiniBlockPool:       dataComponents.Datapool().MiniBlocks(),
			PreProcessors:       preprocContainer,
			ShardCoordinator:    bootstrapComponents.ShardCoordinator(),
			EnableEpochsHandler: coreComponents.EnableEpochsHandler(),
		}
		// second instance for proposal missing data fetching to avoid interferences
		blockDataRequester, _ = coordinator.NewBlockDataRequester(blockDataRequesterArgs)

		mbSelectionSession, _ = blproc.NewMiniBlocksSelectionSession(
			bootstrapComponents.ShardCoordinator().SelfId(),
			coreComponents.InternalMarshalizer(),
			coreComponents.Hasher(),
		)

		blocksCache := headersCache.NewHeaderBodyCache(config.HeaderBodyCacheConfig{})
		executionResultsTracker, _ := executionTrack.NewExecutionResultsTracker(disabled.NewDisabledStateAccessesCollector())
		_ = executionResultsTracker.SetLastNotarizedResult(&block.ExecutionResult{})
		execManager, _ = executionManager.NewExecutionManager(executionManager.ArgsExecutionManager{
			BlocksCache:             blocksCache,
			ExecutionResultsTracker: executionResultsTracker,
			BlockChain:              dataComponents.BlockChain,
			Headers:                 dataComponents.DataPool.Headers(),
			PostProcessTransactions: dataComponents.DataPool.PostProcessTransactions(),
			ExecutedMiniBlocks:      dataComponents.DataPool.ExecutedMiniBlocks(),
			StorageService:          dataComponents.StorageService(),
			Marshaller:              coreComponents.InternalMarshalizer(),
			ShardCoordinator:        bootstrapComponents.ShardCoordinator(),
		})
		execResultsVerifier, _ = blproc.NewExecutionResultsVerifier(dataComponents.BlockChain, execManager)
		inclusionEstimator, _ = estimator.NewExecutionResultInclusionEstimator(
			config.ExecutionResultInclusionEstimatorConfig{
				SafetyMargin:       110,
				MaxResultsPerBlock: 20,
			},
			coreComponents.RoundHandler(),
			&testscommon.ExecResSizeComputationStub{},
		)

		missingDataArgs := missingData.ResolverArgs{
			HeadersPool:         dataComponents.DataPool.Headers(),
			ProofsPool:          dataComponents.DataPool.Proofs(),
			RequestHandler:      &testscommon.RequestHandlerStub{},
			BlockDataRequester:  blockDataRequester,
			EnableEpochsHandler: coreComponents.EnableEpochsHandler(),
		}
		missingDataResolver, _ = missingData.NewMissingDataResolver(missingDataArgs)
	}

	return blproc.ArgBaseProcessor{
		CoreComponents:       coreComponents,
		DataComponents:       dataComponents,
		BootstrapComponents:  bootstrapComponents,
		StatusComponents:     statusComponents,
		StatusCoreComponents: statusCoreComponents,
		Config:               config.Config{},
		AccountsDB:           accountsDb,
		AccountsProposal:     accounts,
		ForkDetector:         &mock.ForkDetectorMock{},
		NodesCoordinator:     nodesCoordinatorInstance,
		FeeHandler:           &mock.FeeAccumulatorStub{},
		RequestHandler:       &testscommon.RequestHandlerStub{},
		BlockChainHook:       &testscommon.BlockChainHookStub{},
		TxCoordinator:        &testscommon.TransactionCoordinatorMock{},
		EpochStartTrigger:    &mock.EpochStartTriggerStub{},
		HeaderValidator:      headerValidator,
		BootStorer: &mock.BoostrapStorerMock{
			PutCalled: func(round int64, bootData bootstrapStorage.BootstrapData) error {
				return nil
			},
		},
		BlockTracker:                       blockTracker,
		MiniBlockTracker:                   &testscommon.MiniBlockTrackerStub{},
		BlockSizeThrottler:                 &mock.BlockSizeThrottlerStub{},
		Version:                            "softwareVersion",
		HistoryRepository:                  &dblookupext.HistoryRepositoryStub{},
		GasHandler:                         &mock.GasHandlerMock{},
		ScheduledTxsExecutionHandler:       &testscommon.ScheduledTxsExecutionStub{},
		OutportDataProvider:                &outport.OutportDataProviderStub{},
		ScheduledMiniBlocksEnableEpoch:     2,
		ProcessedMiniBlocksTracker:         &testscommon.ProcessedMiniBlocksTrackerStub{},
		ReceiptsRepository:                 &testscommon.ReceiptsRepositoryStub{},
		BlockProcessingCutoffHandler:       &testscommon.BlockProcessingCutoffStub{},
		ManagedPeersHolder:                 &testscommon.ManagedPeersHolderStub{},
		SentSignaturesTracker:              &testscommon.SentSignatureTrackerStub{},
		StateAccessesCollector:             disabled.NewDisabledStateAccessesCollector(),
		HeadersForBlock:                    headersForBlock,
		MiniBlocksSelectionSession:         mbSelectionSession,
		ExecutionResultsVerifier:           execResultsVerifier,
		MissingDataResolver:                missingDataResolver,
		ExecutionResultsInclusionEstimator: inclusionEstimator,
		GasComputation: &testscommon.GasComputationMock{
			AddIncomingMiniBlocksCalled: func(miniBlocks []data.MiniBlockHeaderHandler, transactions map[string][]data.TransactionHandler) (int, int, error) {
				return len(miniBlocks), 0, nil
			},
			AddOutgoingTransactionsCalled: func(txHashes [][]byte, transactions []data.TransactionHandler, isProposer bool) ([][]byte, []data.MiniBlockHeaderHandler, error) {
				return txHashes, nil, nil
			},
		},
		ExecutionManager:        execManager,
		TxExecutionOrderHandler: &commonMocks.TxExecutionOrderHandlerStub{},
		AOTSelector:             aotSelection.NewDisabledAOTSelector(),
	}
}

func qualSP224BlockCreateTestBlockchain() *testscommon.ChainHandlerStub {
	return &testscommon.ChainHandlerStub{
		GetGenesisHeaderCalled: func() data.HeaderHandler {
			return &block.Header{Nonce: 0}
		},
	}
}

func qualSP224BlockGenerateTestCache() storage.Cacher {
	c, _ := storageunit.NewCache(storageunit.CacheConfig{Type: storageunit.LRUCache, Capacity: 1000, Shards: 1, SizeInBytes: 0})
	return c
}

func qualSP224BlockGenerateTestUnit() storage.Storer {
	storer, _ := storageunit.NewStorageUnit(
		qualSP224BlockGenerateTestCache(),
		database.NewMemDB(),
	)

	return storer
}

func qualSP224BlockInitDataPool() *dataRetrieverMock.PoolsHolderStub {
	transactionsPool := testscommon.NewShardedDataCacheNotifierMock()
	unsignedTransactionsPool := testscommon.NewShardedDataCacheNotifierMock()
	rewardTransactionsPool := testscommon.NewShardedDataCacheNotifierMock()
	validatorsInfoPool := testscommon.NewShardedDataCacheNotifierMock()

	metablocksPool := cache.NewCacherStub()
	miniblocksPool := cache.NewCacherStub()
	headersPool := &mock.HeadersCacherStub{}
	proofsPool := proofscache.NewProofsPool(3, 100)
	executedMBs := cache.NewCacherStub()
	postProcessTxs := cache.NewCacherStub()
	directSentTxs := cache.NewCacherStub()

	sdp := &dataRetrieverMock.PoolsHolderStub{
		TransactionsCalled:         func() dataRetriever.ShardedDataCacherNotifier { return transactionsPool },
		UnsignedTransactionsCalled: func() dataRetriever.ShardedDataCacherNotifier { return unsignedTransactionsPool },
		RewardTransactionsCalled:   func() dataRetriever.ShardedDataCacherNotifier { return rewardTransactionsPool },
		ValidatorsInfoCalled:       func() dataRetriever.ShardedDataCacherNotifier { return validatorsInfoPool },
		MetaBlocksCalled: func() storage.Cacher {
			return metablocksPool
		},
		MiniBlocksCalled: func() storage.Cacher {
			return miniblocksPool
		},
		HeadersCalled: func() dataRetriever.HeadersPool {
			return headersPool
		},
		ProofsCalled: func() dataRetriever.ProofsPool {
			return proofsPool
		},
		ExecutedMiniBlocksCalled: func() storage.Cacher {
			return executedMBs
		},
		PostProcessTransactionsCalled: func() storage.Cacher {
			return postProcessTxs
		},
		DirectSentTransactionsCalled: func() storage.Cacher {
			return directSentTxs
		},
	}

	return sdp
}

func qualSP224BlockInitStore() *dataRetriever.ChainStorer {
	store := dataRetriever.NewChainStorer()
	store.AddStorer(dataRetriever.TransactionUnit, qualSP224BlockGenerateTestUnit())
	store.AddStorer(dataRetriever.UnsignedTransactionUnit, qualSP224BlockGenerateTestUnit())
	store.AddStorer(dataRetriever.MiniBlockUnit, qualSP224BlockGenerateTestUnit())
	store.AddStorer(dataRetriever.RewardTransactionUnit, qualSP224BlockGenerateTestUnit())
	store.AddStorer(dataRetriever.MetaBlockUnit, qualSP224BlockGenerateTestUnit())
	store.AddStorer(dataRetriever.PeerChangesUnit, qualSP224BlockGenerateTestUnit())
	store.AddStorer(dataRetriever.BlockHeaderUnit, qualSP224BlockGenerateTestUnit())
	store.AddStorer(dataRetriever.ShardHdrNonceHashDataUnit, qualSP224BlockGenerateTestUnit())
	store.AddStorer(dataRetriever.MetaHdrNonceHashDataUnit, qualSP224BlockGenerateTestUnit())
	store.AddStorer(dataRetriever.ReceiptsUnit, qualSP224BlockGenerateTestUnit())
	store.AddStorer(dataRetriever.TrieEpochRootHashUnit, qualSP224BlockGenerateTestUnit())
	store.AddStorer(dataRetriever.ScheduledSCRsUnit, qualSP224BlockGenerateTestUnit())
	return store
}

func qualSP224BlockCreateComponentHolderMocks() (
	*mock.CoreComponentsMock,
	*mock.DataComponentsMock,
	*mock.BootstrapComponentsMock,
	*mock.StatusComponentsMock,
) {
	blkc, _ := blockchain.NewBlockChain(&statusHandlerMock.AppStatusHandlerStub{})
	_ = blkc.SetGenesisHeader(&block.Header{Nonce: 0})

	gracePeriod, _ := graceperiod.NewEpochChangeGracePeriod([]config.EpochChangeGracePeriodByEpoch{{EnableEpoch: 0, GracePeriodInRounds: 1}})

	coreComponents := &mock.CoreComponentsMock{
		IntMarsh:                           &mock.MarshalizerMock{},
		Hash:                               &mock.HasherStub{},
		UInt64ByteSliceConv:                &mock.Uint64ByteSliceConverterMock{},
		StatusField:                        &statusHandlerMock.AppStatusHandlerStub{},
		RoundField:                         &mock.RoundHandlerMock{},
		ProcessStatusHandlerField:          &testscommon.ProcessStatusHandlerStub{},
		EpochNotifierField:                 &epochNotifier.EpochNotifierStub{},
		EnableEpochsHandlerField:           enableEpochsHandlerMock.NewEnableEpochsHandlerStub(),
		RoundNotifierField:                 &epochNotifier.RoundNotifierStub{},
		EnableRoundsHandlerField:           &testscommon.EnableRoundsHandlerStub{},
		EpochChangeGracePeriodHandlerField: gracePeriod,
		ProcessConfigsHandlerField:         testscommon.GetDefaultProcessConfigsHandler(),
		ClosingNodeStartedField:            &atomic.Bool{},
	}

	dataComponents := &mock.DataComponentsMock{
		Storage:    qualSP224BlockInitStore(),
		DataPool:   qualSP224BlockInitDataPool(),
		BlockChain: blkc,
	}

	boostrapComponents := &mock.BootstrapComponentsMock{
		Coordinator:          mock.NewOneShardCoordinatorMock(),
		HdrIntegrityVerifier: &mock.HeaderIntegrityVerifierStub{},
		VersionedHdrFactory: &testscommon.VersionedHeaderFactoryStub{
			CreateCalled: func(epoch uint32, _ uint64) data.HeaderHandler {
				return &block.Header{}
			},
		},
	}

	statusComponents := &mock.StatusComponentsMock{
		Outport: &outport.OutportStub{},
	}

	return coreComponents, dataComponents, boostrapComponents, statusComponents
}

func qualSP224BlockCreateMockArguments(
	coreComponents *mock.CoreComponentsMock,
	dataComponents *mock.DataComponentsMock,
	bootstrapComponents *mock.BootstrapComponentsMock,
	statusComponents *mock.StatusComponentsMock,
) blproc.ArgShardProcessor {
	return blproc.ArgShardProcessor{
		ArgBaseProcessor: qualSP224BlockCreateArgBaseProcessor(coreComponents, dataComponents, bootstrapComponents, statusComponents),
	}
}

func qualSP224BlockCreateMockComponentHolders() (
	*mock.CoreComponentsMock,
	*mock.DataComponentsMock,
	*mock.BootstrapComponentsMock,
	*mock.StatusComponentsMock,
) {
	mdp := qualSP224BlockInitDataPool()
	gracePeriod, _ := graceperiod.NewEpochChangeGracePeriod([]config.EpochChangeGracePeriodByEpoch{{EnableEpoch: 0, GracePeriodInRounds: 1}})
	coreComponents := &mock.CoreComponentsMock{
		IntMarsh:                           &mock.MarshalizerMock{},
		Hash:                               &mock.HasherStub{},
		UInt64ByteSliceConv:                &mock.Uint64ByteSliceConverterMock{},
		StatusField:                        &statusHandlerMock.AppStatusHandlerStub{},
		RoundField:                         &mock.RoundHandlerMock{RoundTimeDuration: time.Second},
		ProcessStatusHandlerField:          &testscommon.ProcessStatusHandlerStub{},
		EpochNotifierField:                 &epochNotifier.EpochNotifierStub{},
		EnableEpochsHandlerField:           enableEpochsHandlerMock.NewEnableEpochsHandlerStub(),
		RoundNotifierField:                 &epochNotifier.RoundNotifierStub{},
		EnableRoundsHandlerField:           &testscommon.EnableRoundsHandlerStub{},
		EpochChangeGracePeriodHandlerField: gracePeriod,
		ProcessConfigsHandlerField:         testscommon.GetDefaultProcessConfigsHandler(),
		ClosingNodeStartedField:            &atomic.Bool{},
	}

	dataComponents := &mock.DataComponentsMock{
		Storage:    &storageStubs.ChainStorerStub{},
		DataPool:   mdp,
		BlockChain: qualSP224BlockCreateTestBlockchain(),
	}
	boostrapComponents := &mock.BootstrapComponentsMock{
		Coordinator:          mock.NewOneShardCoordinatorMock(),
		HdrIntegrityVerifier: &mock.HeaderIntegrityVerifierStub{},
		VersionedHdrFactory: &testscommon.VersionedHeaderFactoryStub{
			CreateCalled: func(epoch uint32, _ uint64) data.HeaderHandler {
				return &block.MetaBlock{}
			},
		},
	}

	statusComponents := &mock.StatusComponentsMock{
		Outport: &outport.OutportStub{},
	}

	return coreComponents, dataComponents, boostrapComponents, statusComponents
}

func qualSP224BlockCreateMockMetaArguments(
	coreComponents *mock.CoreComponentsMock,
	dataComponents *mock.DataComponentsMock,
	bootstrapComponents *mock.BootstrapComponentsMock,
	statusComponents *mock.StatusComponentsMock,
) blproc.ArgMetaProcessor {

	argsHeaderValidator := blproc.ArgsHeaderValidator{
		Hasher:              &mock.HasherStub{},
		Marshalizer:         &mock.MarshalizerMock{},
		EnableEpochsHandler: coreComponents.EnableEpochsHandler(),
	}
	headerValidator, _ := blproc.NewHeaderValidator(argsHeaderValidator)

	startHeaders := qualSP224BlockCreateGenesisBlocks(bootstrapComponents.ShardCoordinator())
	accountsDb := make(map[state.AccountsDbIdentifier]state.AccountsAdapter)
	accounts := &stateMock.AccountsStub{
		CommitCalled: func() ([]byte, error) {
			return nil, nil
		},
		RootHashCalled: func() ([]byte, error) {
			return nil, nil
		},
		RecreateTrieIfNeededCalled: func(options common.RootHashHolder) error {
			return nil
		},
	}
	accountsDb[state.UserAccountsState] = accounts
	accountsDb[state.PeerAccountsState] = accounts
	statusCoreComponents := &factory.StatusCoreComponentsStub{
		AppStatusHandlerField: &statusHandlerMock.AppStatusHandlerStub{},
	}

	blockTracker := mock.NewBlockTrackerMock(bootstrapComponents.ShardCoordinator(), startHeaders)
	var headersForBlock blproc.HeadersForBlock = &testscommon.HeadersForBlockMock{}
	if !check.IfNil(coreComponents) && !check.IfNil(bootstrapComponents) && !check.IfNil(dataComponents) {
		headersForBlock, _ = headerForBlock.NewHeadersForBlock(headerForBlock.ArgHeadersForBlock{
			DataPool:              dataComponents.DataPool,
			RequestHandler:        &testscommon.RequestHandlerStub{},
			EnableEpochsHandler:   coreComponents.EnableEpochsHandler(),
			ShardCoordinator:      bootstrapComponents.ShardCoordinator(),
			BlockTracker:          blockTracker,
			TxCoordinator:         &testscommon.TransactionCoordinatorMock{},
			RoundHandler:          coreComponents.RoundHandler(),
			ProcessConfigsHandler: testscommon.GetProcessConfigsHandlerWithExtraDelayForRequestBlockInfo(100 * time.Millisecond),
			GenesisNonce:          0,
		})
	}

	preprocContainer := containers.NewPreProcessorsContainer()
	blockDataRequesterArgs := coordinator.BlockDataRequestArgs{
		RequestHandler:      &testscommon.RequestHandlerStub{},
		MiniBlockPool:       dataComponents.Datapool().MiniBlocks(),
		PreProcessors:       preprocContainer,
		ShardCoordinator:    bootstrapComponents.ShardCoordinator(),
		EnableEpochsHandler: coreComponents.EnableEpochsHandler(),
	}
	// second instance for proposal missing data fetching to avoid interferences
	proposalBlockDataRequester, _ := coordinator.NewBlockDataRequester(blockDataRequesterArgs)

	mbSelectionSession, _ := blproc.NewMiniBlocksSelectionSession(
		bootstrapComponents.ShardCoordinator().SelfId(),
		coreComponents.InternalMarshalizer(),
		coreComponents.Hasher(),
	)

	executionResultsTracker, _ := executionTrack.NewExecutionResultsTracker(disabled.NewDisabledStateAccessesCollector())
	execManager, _ := executionManager.NewExecutionManager(executionManager.ArgsExecutionManager{
		BlocksCache:             &processMocks.BlocksCacheMock{},
		ExecutionResultsTracker: executionResultsTracker,
		BlockChain:              dataComponents.BlockChain,
		Headers:                 dataComponents.DataPool.Headers(),
		PostProcessTransactions: dataComponents.DataPool.PostProcessTransactions(),
		ExecutedMiniBlocks:      dataComponents.DataPool.ExecutedMiniBlocks(),
		StorageService:          dataComponents.StorageService(),
		Marshaller:              coreComponents.InternalMarshalizer(),
		ShardCoordinator:        bootstrapComponents.ShardCoordinator(),
	})
	execResultsVerifier, _ := blproc.NewExecutionResultsVerifier(dataComponents.BlockChain, execManager)
	_ = executionResultsTracker.SetLastNotarizedResult(&block.ExecutionResult{})
	inclusionEstimator, _ := estimator.NewExecutionResultInclusionEstimator(
		config.ExecutionResultInclusionEstimatorConfig{
			SafetyMargin:       110,
			MaxResultsPerBlock: 20,
		},
		coreComponents.RoundHandler(),
		&testscommon.ExecResSizeComputationStub{},
	)

	missingDataArgs := missingData.ResolverArgs{
		HeadersPool:         dataComponents.DataPool.Headers(),
		ProofsPool:          dataComponents.DataPool.Proofs(),
		RequestHandler:      &testscommon.RequestHandlerStub{},
		BlockDataRequester:  proposalBlockDataRequester,
		EnableEpochsHandler: coreComponents.EnableEpochsHandler(),
	}
	missingDataResolver, _ := missingData.NewMissingDataResolver(missingDataArgs)

	argsGasConsumption := blproc.ArgsGasConsumption{
		EconomicsFee:                      &economicsmocks.EconomicsHandlerMock{},
		ShardCoordinator:                  bootstrapComponents.ShardCoordinator(),
		GasHandler:                        &mock.GasHandlerMock{},
		BlockCapacityOverestimationFactor: 200,
		PercentDecreaseLimitsStep:         10,
		BlockSizeComputation:              &testscommon.BlockSizeComputationStub{},
		BlockTracker:                      &mock.BlockTrackerMock{},
	}
	gasComputation, _ := blproc.NewGasConsumption(argsGasConsumption)

	shardInfoCreateDataArgs := blproc.ShardInfoCreateDataArgs{
		EnableEpochsHandler:      coreComponents.EnableEpochsHandler(),
		HeadersPool:              dataComponents.Datapool().Headers(),
		ProofsPool:               dataComponents.Datapool().Proofs(),
		PendingMiniBlocksHandler: &mock.PendingMiniBlocksHandlerStub{},
		BlockTracker:             blockTracker,
		Storage:                  dataComponents.StorageService(),
		Marshaller:               coreComponents.InternalMarshalizer(),
	}
	shardInfoCreator, _ := blproc.NewShardInfoCreateData(shardInfoCreateDataArgs)

	arguments := blproc.ArgMetaProcessor{
		ArgBaseProcessor: blproc.ArgBaseProcessor{
			CoreComponents:       coreComponents,
			DataComponents:       dataComponents,
			BootstrapComponents:  bootstrapComponents,
			StatusComponents:     statusComponents,
			StatusCoreComponents: statusCoreComponents,
			AccountsDB:           accountsDb,
			AccountsProposal:     accounts,
			ForkDetector:         &mock.ForkDetectorMock{},
			NodesCoordinator:     shardingMocks.NewNodesCoordinatorMock(),
			FeeHandler:           &mock.FeeAccumulatorStub{},
			RequestHandler:       &testscommon.RequestHandlerStub{},
			BlockChainHook:       &testscommon.BlockChainHookStub{},
			TxCoordinator:        &testscommon.TransactionCoordinatorMock{},
			EpochStartTrigger:    &mock.EpochStartTriggerStub{},
			HeaderValidator:      headerValidator,
			GasHandler:           &mock.GasHandlerMock{},
			BootStorer: &mock.BoostrapStorerMock{
				PutCalled: func(round int64, bootData bootstrapStorage.BootstrapData) error {
					return nil
				},
			},
			BlockTracker:                       blockTracker,
			MiniBlockTracker:                   &testscommon.MiniBlockTrackerStub{},
			BlockSizeThrottler:                 &mock.BlockSizeThrottlerStub{},
			HistoryRepository:                  &dblookupext.HistoryRepositoryStub{},
			ScheduledTxsExecutionHandler:       &testscommon.ScheduledTxsExecutionStub{},
			ProcessedMiniBlocksTracker:         &testscommon.ProcessedMiniBlocksTrackerStub{},
			ReceiptsRepository:                 &testscommon.ReceiptsRepositoryStub{},
			OutportDataProvider:                &outport.OutportDataProviderStub{},
			BlockProcessingCutoffHandler:       &testscommon.BlockProcessingCutoffStub{},
			ManagedPeersHolder:                 &testscommon.ManagedPeersHolderStub{},
			SentSignaturesTracker:              &testscommon.SentSignatureTrackerStub{},
			StateAccessesCollector:             disabled.NewDisabledStateAccessesCollector(),
			HeadersForBlock:                    headersForBlock,
			MiniBlocksSelectionSession:         mbSelectionSession,
			ExecutionResultsVerifier:           execResultsVerifier,
			MissingDataResolver:                missingDataResolver,
			ExecutionResultsInclusionEstimator: inclusionEstimator,
			GasComputation:                     gasComputation,
			ExecutionManager:                   execManager,
			TxExecutionOrderHandler:            &commonMocks.TxExecutionOrderHandlerStub{},
			AOTSelector:                        aotSelection.NewDisabledAOTSelector(),
		},
		SCToProtocol:                 &mock.SCToProtocolStub{},
		PendingMiniBlocksHandler:     &mock.PendingMiniBlocksHandlerStub{},
		EpochStartDataCreator:        &mock.EpochStartDataCreatorStub{},
		EpochEconomics:               &mock.EpochEconomicsStub{},
		EpochRewardsCreator:          &testscommon.RewardsCreatorStub{},
		EpochValidatorInfoCreator:    &testscommon.EpochValidatorInfoCreatorStub{},
		ValidatorStatisticsProcessor: &testscommon.ValidatorStatisticsProcessorStub{},
		EpochSystemSCProcessor:       &testscommon.EpochStartSystemSCStub{},
		ShardInfoCreator:             shardInfoCreator,
	}
	return arguments
}

func qualSP224BlockCreateGenesisBlocks(shardCoordinator sharding.Coordinator) map[uint32]data.HeaderHandler {
	genesisBlocks := make(map[uint32]data.HeaderHandler)
	for ShardID := uint32(0); ShardID < shardCoordinator.NumberOfShards(); ShardID++ {
		genesisBlocks[ShardID] = qualSP224BlockCreateGenesisBlock(ShardID)
	}

	genesisBlocks[core.MetachainShardId] = qualSP224BlockCreateGenesisMetaBlock()

	return genesisBlocks
}

func qualSP224BlockCreateGenesisBlock(ShardID uint32) *block.Header {
	rootHash := []byte("roothash")
	return &block.Header{
		Nonce:         0,
		Round:         0,
		Signature:     rootHash,
		RandSeed:      rootHash,
		PrevRandSeed:  rootHash,
		ShardID:       ShardID,
		PubKeysBitmap: rootHash,
		RootHash:      rootHash,
		PrevHash:      rootHash,
	}
}

func qualSP224BlockCreateGenesisMetaBlock() *block.MetaBlock {
	rootHash := []byte("roothash")
	return &block.MetaBlock{
		Nonce:         0,
		Round:         0,
		Signature:     rootHash,
		RandSeed:      rootHash,
		PrevRandSeed:  rootHash,
		PubKeysBitmap: rootHash,
		RootHash:      rootHash,
		PrevHash:      rootHash,
	}
}
