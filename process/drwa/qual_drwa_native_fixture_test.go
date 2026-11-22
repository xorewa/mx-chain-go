package drwa

// Qualification-only adaptation of the pinned native fixture; no business
// authority, production defaults, accepting provider or runtime launch. Only
// reached native VM/tx/builtin/guardian/storage construction is retained.
import (
	"bytes"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/core/pubkeyConverter"
	"github.com/multiversx/mx-chain-core-go/core/versioning"
	"github.com/multiversx/mx-chain-core-go/data"
	dataTransaction "github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing/keccak"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	ed25519SingleSig "github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/common/statistics"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/integrationTests/mock"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/block/postprocess"
	"github.com/multiversx/mx-chain-go/process/block/preprocess"
	"github.com/multiversx/mx-chain-go/process/coordinator"
	"github.com/multiversx/mx-chain-go/process/economics"
	"github.com/multiversx/mx-chain-go/process/factory/shard"
	"github.com/multiversx/mx-chain-go/process/guardian"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/process/smartContract/builtInFunctions"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks/counters"
	"github.com/multiversx/mx-chain-go/process/smartContract/processProxy"
	"github.com/multiversx/mx-chain-go/process/smartContract/scrCommon"
	"github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/process/transactionLog"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	accountFactory "github.com/multiversx/mx-chain-go/state/factory"
	"github.com/multiversx/mx-chain-go/state/iteratorChannelsProvider"
	"github.com/multiversx/mx-chain-go/state/lastSnapshotMarker"
	"github.com/multiversx/mx-chain-go/state/storagePruningManager"
	"github.com/multiversx/mx-chain-go/state/storagePruningManager/evictionWaitingList"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/chainParameters"
	dataRetrieverMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	testStorage "github.com/multiversx/mx-chain-go/testscommon/state"
	storageStubs "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/multiversx/mx-chain-go/txcache"
	"github.com/multiversx/mx-chain-go/vm/systemSmartContracts/defaults"
	logger "github.com/multiversx/mx-chain-logger-go"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	wasmConfig "github.com/multiversx/mx-chain-vm-go/config"
	"github.com/stretchr/testify/require"
	"math"
	"math/big"
	"strconv"
	"sync"
	"testing"
)

var qualNativeLog = logger.GetOrCreate("integrationtests")

const qualNativeGuardianDelay = uint32(2)
const qualNativeMinTransactionVersion = 1
const qualNativeDNSV2Address = "erd1qqqqqqqqqqqqqpgqcy67yanvwpepqmerkq6m8pgav0tlvgwxjmdq4hukxw"

var qualNativeDNSAddress = []byte{0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 137, 17, 46, 56, 127, 47, 62, 172, 4, 126, 190, 242, 221, 230, 209, 243, 105, 104, 242, 66, 49, 49}
var qualNativeAddressConverter, _ = pubkeyConverter.NewBech32PubkeyConverter(32, "erd")
var qualNativeHexConverter, _ = pubkeyConverter.NewHexPubkeyConverter(32)
var qualNativeTxSignHasher = keccak.NewKeccak()
var qualNativeTxSignMarshalizer = &marshal.JsonMarshalizer{}
var qualNativeAccountKeyGen = signing.NewKeyGenerator(ed25519.NewEd25519())
var qualNativeSingleSigner = &ed25519SingleSig.Ed25519Signer{}

type qualNativeVMContext struct {
	ChainHandler           *testscommon.ChainHandlerStub
	TxProcessor            process.TransactionProcessor
	ScProcessor            scrCommon.TestSmartContractProcessor
	Accounts               state.AccountsAdapter
	BlockchainHook         vmcommon.BlockchainHook
	VMContainer            process.VirtualMachinesContainer
	TxFeeHandler           process.TransactionFeeHandler
	ShardCoordinator       sharding.Coordinator
	ScForwarder            process.IntermediateTransactionHandler
	EconomicsData          process.EconomicsDataHandler
	Marshalizer            marshal.Marshalizer
	GasSchedule            core.GasScheduleNotifier
	EpochNotifier          process.EpochNotifier
	EnableEpochsHandler    common.EnableEpochsHandler
	GuardedAccountsHandler process.GuardedAccountHandler
	TxsLogsProcessor       process.TransactionLogProcessor
}
type qualNativeProcessorResult struct {
	TxProc             process.TransactionProcessor
	SCProc             scrCommon.TestSmartContractProcessor
	NativeSC           process.SmartContractProcessorFacade
	IntermediateTxProc process.IntermediateTransactionHandler
	EconomicsHandler   process.EconomicsDataHandler
	TxLogProc          process.TransactionLogProcessor
}

func (vmTestContext *qualNativeVMContext) Close() {
	_ = vmTestContext.VMContainer.Close()
}
func (vmTestContext *qualNativeVMContext) GetCompositeTestError() error {
	return vmTestContext.ScProcessor.GetCompositeTestError()
}
func (vmTestContext *qualNativeVMContext) GetGasRemaining() uint64 {
	return vmTestContext.ScProcessor.GetGasRemaining()
}
func (vmTestContext *qualNativeVMContext) GetIntermediateTransactions(tb testing.TB) []data.TransactionHandler {
	scForwarder := vmTestContext.ScForwarder
	mockIntermediate, ok := scForwarder.(*mock.IntermediateTransactionHandlerMock)
	require.True(tb, ok)

	return mockIntermediate.GetIntermediateTransactions()
}
func qualNativeCreateEconomicsData(enableEpochsConfig config.EnableEpochs, gasPriceModifier float64) (process.EconomicsDataHandler, error) {
	maxGasLimitPerBlock := strconv.FormatUint(math.MaxUint64-1, 10)
	minGasPrice := strconv.FormatUint(1, 10)
	minGasLimit := strconv.FormatUint(1, 10)
	testProtocolSustainabilityAddress := "erd1932eft30w753xyvme8d49qejgkjc09n5e49w4mwdjtm0neld797su0dlxp"

	realEpochNotifier := forking.NewGenericEpochNotifier()
	enableEpochsHandler, _ := enablers.NewEnableEpochsHandler(enableEpochsConfig, realEpochNotifier)

	argsNewEconomicsData := economics.ArgsNewEconomicsData{
		TxVersionChecker:   versioning.NewTxVersionChecker(qualNativeMinTransactionVersion),
		ChainParamsHandler: &chainParameters.ChainParametersHolderMock{},
		Economics: &config.EconomicsConfig{
			GlobalSettings: config.GlobalSettings{
				GenesisTotalSupply: "2000000000000000000000",
				MinimumInflation:   0,
				YearSettings: []*config.YearSetting{
					{
						Year:             0,
						MaximumInflation: 0.01,
					},
				},
			},
			RewardsSettings: config.RewardsSettings{
				RewardsConfigByEpoch: []config.EpochRewardSettings{
					{
						LeaderPercentage:                 0.1,
						ProtocolSustainabilityPercentage: 0.1,
						DeveloperPercentage:              0.1,
						ProtocolSustainabilityAddress:    testProtocolSustainabilityAddress,
						TopUpGradientPoint:               "100000",
						EcosystemGrowthPercentage:        0.0,
						EcosystemGrowthAddress:           testProtocolSustainabilityAddress,
						GrowthDividendPercentage:         0.0,
						GrowthDividendAddress:            testProtocolSustainabilityAddress,
					},
				},
			},
			FeeSettings: config.FeeSettings{
				GasLimitSettings: []config.GasLimitSetting{
					{
						MaxGasLimitPerBlock:         maxGasLimitPerBlock,
						MaxGasLimitPerMiniBlock:     maxGasLimitPerBlock,
						MaxGasLimitPerMetaBlock:     maxGasLimitPerBlock,
						MaxGasLimitPerMetaMiniBlock: maxGasLimitPerBlock,
						MaxGasLimitPerTx:            maxGasLimitPerBlock,
						MinGasLimit:                 minGasLimit,
						ExtraGasLimitGuardedTx:      "50000",
						MaxGasHigherFactorAccepted:  "10",
					},
				},
				MinGasPrice:            minGasPrice,
				GasPerDataByte:         "1",
				GasPriceModifier:       gasPriceModifier,
				MaxGasPriceSetGuardian: "2000000000",
			},
		},
		EpochNotifier:       realEpochNotifier,
		EnableEpochsHandler: enableEpochsHandler,
		PubkeyConverter:     &testscommon.PubkeyConverterStub{},
		ShardCoordinator:    &testscommon.ShardsCoordinatorMock{},
	}

	return economics.NewEconomicsData(argsNewEconomicsData)
}

func qualNativeCreateVMAndBlockchainHookAndDataPool(
	accnts state.AccountsAdapter,
	gasSchedule core.GasScheduleNotifier,
	vmConfig *config.VirtualMachineConfig,
	shardCoordinator sharding.Coordinator,
	wasmVMChangeLocker common.Locker,
	epochNotifierInstance process.EpochNotifier,
	enableEpochsHandler common.EnableEpochsHandler,
	chainHandler data.ChainHandler,
	guardedAccountHandler vmcommon.GuardedAccountHandler,
	nativeHeaderOnly ...bool,
) (process.VirtualMachinesContainer, *hooks.BlockChainHookImpl, dataRetriever.PoolsHolder) {
	if check.IfNil(gasSchedule) || gasSchedule.LatestGasSchedule() == nil {
		testGasSchedule := wasmConfig.MakeGasMapForTests()
		defaults.FillGasMapInternal(testGasSchedule, 1)
		gasSchedule = mock.NewGasScheduleNotifierMock(testGasSchedule)
	}

	dnsV2Decoded, _ := qualNativeAddressConverter.Decode(qualNativeDNSV2Address)

	argsBuiltIn := builtInFunctions.ArgsCreateBuiltInFunctionContainer{
		GasSchedule: gasSchedule,
		MapDNSAddresses: map[string]struct{}{
			string(qualNativeDNSAddress): {},
		},
		MapDNSV2Addresses: map[string]struct{}{
			string(dnsV2Decoded):         {},
			string(qualNativeDNSAddress): {},
		},
		Marshalizer:               integrationtests.TestMarshalizer,
		Accounts:                  accnts,
		ShardCoordinator:          shardCoordinator,
		EpochNotifier:             epochNotifierInstance,
		EnableEpochsHandler:       enableEpochsHandler,
		MaxNumNodesInTransferRole: 100,
		GuardedAccountHandler:     guardedAccountHandler,
	}
	argsBuiltIn.AutomaticCrawlerAddresses = qualNativeCrawlerAddresses(argsBuiltIn.ShardCoordinator)
	builtInFuncFactory, _ := builtInFunctions.CreateBuiltInFunctionsFactory(argsBuiltIn)

	esdtTransferParser, _ := parsers.NewESDTTransferParser(integrationtests.TestMarshalizer)
	counter, _ := counters.NewUsageCounter(esdtTransferParser, enableEpochsHandler)

	datapool := dataRetrieverMock.NewPoolsHolderMock()
	args := hooks.ArgBlockChainHook{
		Accounts:                 accnts,
		PubkeyConv:               qualNativeHexConverter,
		StorageService:           &storageStubs.ChainStorerStub{},
		BlockChain:               chainHandler,
		ShardCoordinator:         shardCoordinator,
		Marshalizer:              integrationtests.TestMarshalizer,
		Uint64Converter:          &mock.Uint64ByteSliceConverterMock{},
		BuiltInFunctions:         builtInFuncFactory.BuiltInFunctionContainer(),
		NFTStorageHandler:        builtInFuncFactory.NFTStorageHandler(),
		GlobalSettingsHandler:    builtInFuncFactory.ESDTGlobalSettingsHandler(),
		DataPool:                 datapool,
		CompiledSCPool:           datapool.SmartContracts(),
		NilCompiledSCStore:       true,
		ConfigSCStorage:          *qualNativeDefaultStorageConfig(),
		EpochNotifier:            epochNotifierInstance,
		EnableEpochsHandler:      enableEpochsHandler,
		GasSchedule:              gasSchedule,
		Counter:                  counter,
		MissingTrieNodesNotifier: &testscommon.MissingTrieNodesNotifierStub{},
		EpochStartTrigger:        &testscommon.EpochStartTriggerStub{},
		RoundHandler:             &testscommon.RoundHandlerMock{},
	}

	maxGasLimitPerBlock := uint64(0xFFFFFFFFFFFFFFFF)
	if len(nativeHeaderOnly) != 0 && nativeHeaderOnly[0] {
		args.Hasher = integrationtests.TestHasher
		args.DRWAHeaderTimeEnabled = func() bool { return true } // explicit synthetic activation only
	}
	blockChainHookImpl, hookErr := hooks.NewBlockChainHookImpl(args)
	if hookErr != nil {
		panic(hookErr)
	}
	if len(nativeHeaderOnly) != 0 && nativeHeaderOnly[0] {
		return nil, blockChainHookImpl, datapool
	}
	argsNewVMFactory := shard.ArgVMContainerFactory{
		Config:              *vmConfig,
		BlockGasLimit:       maxGasLimitPerBlock,
		GasSchedule:         gasSchedule,
		BlockChainHook:      blockChainHookImpl,
		BuiltInFunctions:    args.BuiltInFunctions,
		EpochNotifier:       epochNotifierInstance,
		EnableEpochsHandler: enableEpochsHandler,
		WasmVMChangeLocker:  wasmVMChangeLocker,
		ESDTTransferParser:  esdtTransferParser,
		Hasher:              integrationtests.TestHasher,
		PubKeyConverter:     qualNativeHexConverter,
	}
	vmFactory, err := shard.NewVMContainerFactory(argsNewVMFactory)
	if err != nil {
		qualNativeLog.LogIfError(err)
	}

	vmContainer, err := vmFactory.Create()
	if err != nil {
		panic(err)
	}

	blockChainHook, _ := vmFactory.BlockChainHookImpl().(*hooks.BlockChainHookImpl)
	_ = builtInFuncFactory.SetPayableHandler(blockChainHook)
	_ = builtInFuncFactory.SetBlockchainHook(blockChainHook)

	return vmContainer, blockChainHook, datapool
}

func qualNativeCreateDefaultVMConfig() *config.VirtualMachineConfig {
	return qualNativeCreateVMConfigWithVersion("*")
}

func qualNativeCreateVMConfigWithVersion(version string) *config.VirtualMachineConfig {
	return &config.VirtualMachineConfig{
		WasmVMVersions: []config.WasmVMVersionByEpoch{
			{
				StartEpoch: 0,
				Version:    version,
			},
		},
		TimeOutForSCExecutionInMilliseconds: 10000, // 10 seconds
		TransferAndExecuteByUserAddresses:   []string{"3132333435363738393031323334353637383930313233343536373839303234"},
	}
}

func qualNativeCreateTxProcessorWithOneSCExecutorWithVMs(
	accnts state.AccountsAdapter,
	vmContainer process.VirtualMachinesContainer,
	blockChainHook *hooks.BlockChainHookImpl,
	feeAccumulator process.TransactionFeeHandler,
	shardCoordinator sharding.Coordinator,
	enableEpochsConfig config.EnableEpochs,
	roundsConfig config.RoundConfig,
	wasmVMChangeLocker common.Locker,
	poolsHolder dataRetriever.PoolsHolder,
	epochNotifierInstance process.EpochNotifier,
	guardianChecker process.GuardianChecker,
	roundNotifierInstance process.RoundNotifier,
	chainHandler data.ChainHandler,
	gasPriceModifier float64,
	realNativeProxy ...bool,
) (*qualNativeProcessorResult, error) {
	if check.IfNil(poolsHolder) {
		poolsHolder = dataRetrieverMock.NewPoolsHolderMock()
	}

	enableEpochsHandler, _ := enablers.NewEnableEpochsHandler(enableEpochsConfig, epochNotifierInstance)

	enableRoundsHandler, _ := enablers.NewEnableRoundsHandler(roundsConfig, roundNotifierInstance)

	esdtTransferParser, _ := parsers.NewESDTTransferParser(integrationtests.TestMarshalizer)
	argsTxTypeHandler := coordinator.ArgNewTxTypeHandler{
		PubkeyConverter:     qualNativeHexConverter,
		ShardCoordinator:    shardCoordinator,
		BuiltInFunctions:    blockChainHook.GetBuiltinFunctionsContainer(),
		ArgumentParser:      parsers.NewCallArgsParser(),
		ESDTTransferParser:  esdtTransferParser,
		EnableEpochsHandler: enableEpochsHandler,
	}
	txTypeHandler, _ := coordinator.NewTxTypeHandler(argsTxTypeHandler)

	gasSchedule := make(map[string]map[string]uint64)
	defaults.FillGasMapInternal(gasSchedule, 1)
	economicsData, err := qualNativeCreateEconomicsData(enableEpochsConfig, gasPriceModifier)
	if err != nil {
		return nil, err
	}

	gasComp, err := preprocess.NewGasComputation(economicsData, txTypeHandler, enableEpochsHandler)
	if err != nil {
		return nil, err
	}

	logProc, _ := transactionLog.NewTxLogProcessor(transactionLog.ArgTxLogProcessor{
		SaveInStorageEnabled: false,
		Marshalizer:          integrationtests.TestMarshalizer,
	})

	intermediateTxHandler := &mock.IntermediateTransactionHandlerMock{}
	argsNewSCProcessor := scrCommon.ArgsNewSmartContractProcessor{
		VmContainer:         vmContainer,
		ArgsParser:          smartContract.NewArgumentParser(),
		Hasher:              integrationtests.TestHasher,
		Marshalizer:         integrationtests.TestMarshalizer,
		AccountsDB:          accnts,
		BlockChainHook:      blockChainHook,
		BuiltInFunctions:    blockChainHook.GetBuiltinFunctionsContainer(),
		PubkeyConv:          qualNativeHexConverter,
		ShardCoordinator:    shardCoordinator,
		ScrForwarder:        intermediateTxHandler,
		BadTxForwarder:      intermediateTxHandler,
		TxFeeHandler:        feeAccumulator,
		EconomicsFee:        economicsData,
		TxTypeHandler:       txTypeHandler,
		GasHandler:          gasComp,
		GasSchedule:         mock.NewGasScheduleNotifierMock(gasSchedule),
		TxLogsProcessor:     logProc,
		EnableRoundsHandler: enableRoundsHandler,
		EnableEpochsHandler: enableEpochsHandler,
		WasmVMChangeLocker:  wasmVMChangeLocker,
		VMOutputCacher:      txcache.NewDisabledCache(),
	}

	var scProcessorProxy process.SmartContractProcessorFacade
	var testProxy scrCommon.TestSmartContractProcessor
	if len(realNativeProxy) != 0 && realNativeProxy[0] {
		real, createErr := processProxy.NewSmartContractProcessorProxy(argsNewSCProcessor, epochNotifierInstance)
		if createErr != nil {
			return nil, createErr
		}
		scProcessorProxy = real
	} else {
		test, createErr := processProxy.NewTestSmartContractProcessorProxy(argsNewSCProcessor, epochNotifierInstance)
		if createErr != nil {
			return nil, createErr
		}
		scProcessorProxy = test
		testProxy = test
	}

	argsNewTxProcessor := transaction.ArgsNewTxProcessor{
		Accounts:            accnts,
		Hasher:              integrationtests.TestHasher,
		PubkeyConv:          qualNativeHexConverter,
		Marshalizer:         integrationtests.TestMarshalizer,
		SignMarshalizer:     integrationtests.TestMarshalizer,
		ShardCoordinator:    shardCoordinator,
		ScProcessor:         scProcessorProxy,
		TxFeeHandler:        feeAccumulator,
		TxTypeHandler:       txTypeHandler,
		EconomicsFee:        economicsData,
		ReceiptForwarder:    intermediateTxHandler,
		BadTxForwarder:      intermediateTxHandler,
		ArgsParser:          smartContract.NewArgumentParser(),
		ScrForwarder:        intermediateTxHandler,
		EnableRoundsHandler: enableRoundsHandler,
		EnableEpochsHandler: enableEpochsHandler,
		TxVersionChecker:    versioning.NewTxVersionChecker(qualNativeMinTransactionVersion),
		GuardianChecker:     guardianChecker,
		TxLogsProcessor:     logProc,
	}
	txProcessor, err := transaction.NewTxProcessor(argsNewTxProcessor)
	if err != nil {
		return nil, err
	}

	return &qualNativeProcessorResult{TxProc: txProcessor, SCProc: testProxy, NativeSC: scProcessorProxy, IntermediateTxProc: intermediateTxHandler, EconomicsHandler: economicsData, TxLogProc: logProc}, nil
}

func qualNativeCreatePreparedTxProcessorWithVMConfigWithShardCoordinatorDBAndGasAndRoundConfig(
	enableEpochsConfig config.EnableEpochs,
	shardCoordinator sharding.Coordinator,
	db storage.Storer,
	gasScheduleNotifier core.GasScheduleNotifier,
	roundsConfig config.RoundConfig,
	vmConfig *config.VirtualMachineConfig,
	gasPriceModifier float64,
) (*qualNativeVMContext, error) {
	feeAccumulator := postprocess.NewFeeAccumulator()
	epochNotifierInstance := forking.NewGenericEpochNotifier()
	enableEpochsHandler, _ := enablers.NewEnableEpochsHandler(enableEpochsConfig, epochNotifierInstance)
	accounts := integrationtests.CreateAccountsDB(db, enableEpochsHandler)
	wasmVMChangeLocker := &sync.RWMutex{}

	roundNotifierInstance := forking.NewGenericRoundNotifier()
	chainHandler := &testscommon.ChainHandlerStub{}

	var err error
	guardedAccountHandler, err := guardian.NewGuardedAccount(integrationtests.TestMarshalizer, epochNotifierInstance, qualNativeGuardianDelay)
	if err != nil {
		return nil, err
	}

	vmContainer, blockchainHook, pool := qualNativeCreateVMAndBlockchainHookAndDataPool(
		accounts,
		gasScheduleNotifier,
		vmConfig,
		shardCoordinator,
		wasmVMChangeLocker,
		epochNotifierInstance,
		enableEpochsHandler,
		chainHandler,
		guardedAccountHandler,
	)
	res, err := qualNativeCreateTxProcessorWithOneSCExecutorWithVMs(
		accounts,
		vmContainer,
		blockchainHook,
		feeAccumulator,
		shardCoordinator,
		enableEpochsConfig,
		roundsConfig,
		wasmVMChangeLocker,
		pool,
		epochNotifierInstance,
		guardedAccountHandler,
		roundNotifierInstance,
		chainHandler,
		gasPriceModifier,
	)
	if err != nil {
		return nil, err
	}

	return &qualNativeVMContext{
		TxProcessor:            res.TxProc,
		ScProcessor:            res.SCProc,
		Accounts:               accounts,
		BlockchainHook:         blockchainHook,
		VMContainer:            vmContainer,
		TxFeeHandler:           feeAccumulator,
		ScForwarder:            res.IntermediateTxProc,
		ShardCoordinator:       shardCoordinator,
		EconomicsData:          res.EconomicsHandler,
		TxsLogsProcessor:       res.TxLogProc,
		GasSchedule:            gasScheduleNotifier,
		EpochNotifier:          epochNotifierInstance,
		EnableEpochsHandler:    enableEpochsHandler,
		ChainHandler:           chainHandler,
		Marshalizer:            integrationtests.TestMarshalizer,
		GuardedAccountsHandler: guardedAccountHandler,
	}, nil
}

func qualNativeCreateTransaction(
	nonce uint64,
	value *big.Int,
	sndAddress []byte,
	rcvAddress []byte,
	gasprice uint64,
	gasLimit uint64,
	data []byte,
) *dataTransaction.Transaction {
	return &dataTransaction.Transaction{
		Nonce:    nonce,
		Value:    big.NewInt(0).Set(value),
		RcvAddr:  rcvAddress,
		SndAddr:  sndAddress,
		GasPrice: gasprice,
		GasLimit: gasLimit,
		Data:     data,
	}
}

func qualNativeCreateMockGasScheduleNotifier() *mock.GasScheduleNotifierMock {
	return qualNativeCreateMockGasScheduleNotifierWithCustomGasSchedule(func(gasMap wasmConfig.GasScheduleMap) {})
}

func qualNativeCreateMockGasScheduleNotifierWithCustomGasSchedule(updateGasSchedule func(gasMap wasmConfig.GasScheduleMap)) *mock.GasScheduleNotifierMock {
	testGasSchedule := wasmConfig.MakeGasMapForTests()
	defaults.FillGasMapInternal(testGasSchedule, 1)
	updateGasSchedule(testGasSchedule)
	return mock.NewGasScheduleNotifierMock(testGasSchedule)
}

func qualNativeDefaultStorageConfig() *config.StorageConfig {
	return &config.StorageConfig{
		Cache: config.CacheConfig{
			Name:     "SmartContractsStorage",
			Type:     "LRU",
			Capacity: 100,
		},
		DB: config.DBConfig{
			FilePath:          "SmartContractsStorage",
			Type:              "LvlDBSerial",
			BatchDelaySeconds: 2,
			MaxBatchSize:      100,
		},
	}
}

func qualNativeContext(epochs config.EnableEpochs, coordinator sharding.Coordinator, modifier float64) (*qualNativeVMContext, error) {
	return qualNativeCreatePreparedTxProcessorWithVMConfigWithShardCoordinatorDBAndGasAndRoundConfig(epochs, coordinator, integrationtests.CreateMemUnit(), qualNativeCreateMockGasScheduleNotifier(), testscommon.GetDefaultRoundsConfig(), qualNativeCreateDefaultVMConfig(), modifier)
}
func qualNativeCrawlerAddresses(c sharding.Coordinator) [][]byte {
	out := make([][]byte, c.NumberOfShards())
	for i := uint32(0); i < c.NumberOfShards(); i++ {
		a := bytes.Repeat([]byte{1}, 32)
		a[31] = byte(i)
		out[i] = a
	}
	return out
}
func qualNativeDiskManager(store storage.Storer) (common.StorageManager, storage.Storer) {
	a := storageStubs.GetStorageManagerArgs()
	a.MainStorer = store
	a.Marshalizer = integrationtests.TestMarshalizer
	a.Hasher = integrationtests.TestHasher
	m, _ := trie.NewTrieStorageManager(a)
	return m, store
}
func qualNativeDiskAccounts(manager common.StorageManager, flags common.EnableEpochsHandler) (*state.AccountsDB, common.Trie) {
	tr, _ := trie.NewTrie(manager, integrationtests.TestMarshalizer, integrationtests.TestHasher, flags, 5)
	ewl, _ := evictionWaitingList.NewMemoryEvictionWaitingList(evictionWaitingList.MemoryEvictionWaitingListArgs{RootHashesSize: 100, HashesSize: 10000})
	af, _ := accountFactory.NewAccountCreator(accountFactory.ArgsAccountCreator{Hasher: integrationtests.TestHasher, Marshaller: integrationtests.TestMarshalizer, EnableEpochsHandler: flags, StateAccessesCollector: stateDisabled.NewDisabledStateAccessesCollector()})
	spm, _ := storagePruningManager.NewStoragePruningManager(ewl, 10)
	sm, _ := state.NewSnapshotsManager(state.ArgsNewSnapshotsManager{ProcessingMode: common.Normal, Marshaller: integrationtests.TestMarshalizer, AddressConverter: &testscommon.PubkeyConverterMock{}, ProcessStatusHandler: &testscommon.ProcessStatusHandlerStub{}, StateMetrics: &testStorage.StateMetricsStub{}, AccountFactory: af, ChannelsProvider: iteratorChannelsProvider.NewUserStateIteratorChannelsProvider(), LastSnapshotMarker: lastSnapshotMarker.NewLastSnapshotMarker(), StateStatsHandler: statistics.NewStateStatistics()})
	_ = sm.SetSyncer(&mock.AccountsDBSyncerStub{})
	db, _ := state.NewAccountsDB(state.ArgsAccountsDB{Trie: tr, Hasher: integrationtests.TestHasher, Marshaller: integrationtests.TestMarshalizer, AccountFactory: af, StoragePruningManager: spm, AddressConverter: &testscommon.PubkeyConverterMock{}, SnapshotsManager: sm, StateAccessesCollector: stateDisabled.NewDisabledStateAccessesCollector()})
	return db, tr
}
