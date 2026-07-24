//go:build !race

package process

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	wasmConfig "github.com/multiversx/mx-chain-vm-go/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/genesis"
	"github.com/multiversx/mx-chain-go/genesis/mock"
	"github.com/multiversx/mx-chain-go/genesis/parsing"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/sharding/nodesCoordinator"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/accounts"
	factoryState "github.com/multiversx/mx-chain-go/state/factory"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/testscommon"
	commonMocks "github.com/multiversx/mx-chain-go/testscommon/common"
	dataRetrieverMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/dblookupext"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/genericMocks"
	"github.com/multiversx/mx-chain-go/testscommon/hashingMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	storageCommon "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/multiversx/mx-chain-go/update"
	updateMock "github.com/multiversx/mx-chain-go/update/mock"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/systemSmartContracts/defaults"
)

type drwaAuthorizedCallerRecordForTest struct {
	Version uint64 `json:"version"`
	Address []byte `json:"address"`
}

type drwaRecoveryGovernanceRecordForTest struct {
	Version     uint64   `json:"version"`
	Threshold   uint32   `json:"threshold"`
	Signers     [][]byte `json:"signers"`
	ProposalTTL uint64   `json:"proposal_ttl"`
	MaxSigners  uint32   `json:"max_signers"`
}

var nodePrice = big.NewInt(5000)

func TestSetInitialDataInHeaderHeaderV3ShouldIgnoreRemovedFeeFields(t *testing.T) {
	t.Parallel()

	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
	header := &block.HeaderV3{}

	err := setInitialDataInHeader(header, arg, 0, 0, 0, []byte("root-hash"))

	require.NoError(t, err)
	require.Equal(t, arg.Core.ChainID(), string(header.GetChainID()))
	require.Equal(t, uint64(0), header.GetNonce())
	require.NotNil(t, header.LastExecutionResult)
	require.Equal(t, []byte("root-hash"), header.LastExecutionResult.GetExecutionResult().GetRootHash())
}

// TODO improve code coverage of this package
func createMockArgument(
	t *testing.T,
	genesisFilename string,
	initialNodes genesis.InitialNodesHandler,
	entireSupply *big.Int,
) ArgsGenesisBlockCreator {

	storageManagerArgs := storageCommon.GetStorageManagerArgs()
	storageManager, _ := trie.CreateTrieStorageManager(storageManagerArgs, storageCommon.GetStorageManagerOptions())

	trieStorageManagers := make(map[string]common.StorageManager)
	trieStorageManagers[dataRetriever.UserAccountsUnit.String()] = storageManager
	trieStorageManagers[dataRetriever.PeerAccountsUnit.String()] = storageManager

	arg := ArgsGenesisBlockCreator{
		GenesisTime:   0,
		StartEpochNum: 0,
		Core: &mock.CoreComponentsMock{
			IntMarsh:                 &mock.MarshalizerMock{},
			TxMarsh:                  &mock.MarshalizerMock{},
			Hash:                     &hashingMocks.HasherMock{},
			UInt64ByteSliceConv:      &mock.Uint64ByteSliceConverterMock{},
			AddrPubKeyConv:           testscommon.NewPubkeyConverterMock(32),
			Chain:                    "chainID",
			TxVersionCheck:           &testscommon.TxVersionCheckerStub{},
			MinTxVersion:             1,
			EnableEpochsHandlerField: &enableEpochsHandlerMock.EnableEpochsHandlerStub{},
			EconomicsDataField:       &economicsmocks.EconomicsHandlerMock{},
		},
		Data: &mock.DataComponentsMock{
			Storage: &storageCommon.ChainStorerStub{
				GetStorerCalled: func(unitType dataRetriever.UnitType) (storage.Storer, error) {
					return genericMocks.NewStorerMock(), nil
				},
			},
			Blkc:     &testscommon.ChainHandlerStub{},
			DataPool: dataRetrieverMock.NewPoolsHolderMock(),
		},
		InitialNodesSetup: &mock.InitialNodesSetupHandlerStub{},
		TxLogsProcessor:   &mock.TxLogProcessorMock{},
		VirtualMachineConfig: config.VirtualMachineConfig{
			WasmVMVersions: []config.WasmVMVersionByEpoch{
				{StartEpoch: 0, Version: "*"},
			},
			TransferAndExecuteByUserAddresses: []string{"3132333435363738393031323334353637383930313233343536373839303234"},
		},
		HardForkConfig: config.HardforkConfig{
			ImportKeysStorageConfig: config.StorageConfig{
				Cache: config.CacheConfig{
					Type:     "LRU",
					Capacity: 1000,
					Shards:   1,
				},
				DB: config.DBConfig{
					Type:              "MemoryDB",
					BatchDelaySeconds: 1,
					MaxBatchSize:      1,
					MaxOpenFiles:      10,
				},
			},
			ImportStateStorageConfig: config.StorageConfig{
				Cache: config.CacheConfig{
					Type:     "LRU",
					Capacity: 1000,
					Shards:   1,
				},
				DB: config.DBConfig{
					Type:              "MemoryDB",
					BatchDelaySeconds: 1,
					MaxBatchSize:      1,
					MaxOpenFiles:      10,
				},
			},
		},
		SystemSCConfig: config.SystemSmartContractsConfig{
			ESDTSystemSCConfig: config.ESDTSystemSCConfig{
				BaseIssuingCost: "5000000000000000000000",
				OwnerAddress:    "erd1932eft30w753xyvme8d49qejgkjc09n5e49w4mwdjtm0neld797su0dlxp",
			},
			GovernanceSystemSCConfig: config.GovernanceSystemSCConfig{
				V1: config.GovernanceSystemSCConfigV1{
					ProposalCost: "500",
				},
				Active: config.GovernanceSystemSCConfigActive{
					ProposalCost:     "500",
					MinQuorum:        0.5,
					MinPassThreshold: 0.5,
					MinVetoThreshold: 0.5,
					LostProposalFee:  "1",
				},
				OwnerAddress:                 "3132333435363738393031323334353637383930313233343536373839303234",
				MaxVotingDelayPeriodInEpochs: 30,
			},
			StakingSystemSCConfig: config.StakingSystemSCConfig{
				GenesisNodePrice:                     nodePrice.Text(10),
				UnJailValue:                          "10",
				MinStepValue:                         "10",
				MinStakeValue:                        "1",
				UnBondPeriod:                         1,
				UnBondPeriodSupernova:                2,
				NumRoundsWithoutBleed:                1,
				MaximumPercentageToBleed:             1,
				BleedPercentagePerRound:              1,
				MaxNumberOfNodesForStake:             10,
				ActivateBLSPubKeyMessageVerification: false,
				MinUnstakeTokensValue:                "1",
				StakeLimitPercentage:                 100.0,
				NodeLimitPercentage:                  100.0,
			},
			DelegationManagerSystemSCConfig: config.DelegationManagerSystemSCConfig{
				MinCreationDeposit:  "100",
				MinStakeAmount:      "100",
				ConfigChangeAddress: "3132333435363738393031323334353637383930313233343536373839303234",
			},
			DelegationSystemSCConfig: config.DelegationSystemSCConfig{
				MinServiceFee: 0,
				MaxServiceFee: 100,
			},
			SoftAuctionConfig: config.SoftAuctionConfig{
				TopUpStep:             "10",
				MinTopUp:              "1",
				MaxTopUp:              "32000000",
				MaxNumberOfIterations: 100000,
			},
		},
		TrieStorageManagers: trieStorageManagers,
		BlockSignKeyGen:     &mock.KeyGenMock{},
		GenesisNodePrice:    nodePrice,
		EpochConfig: config.EpochConfig{
			EnableEpochs: config.EnableEpochs{
				DRWAEnforcementEnableEpoch:        unreachableEpoch,
				SCDeployEnableEpoch:               unreachableEpoch,
				CleanUpInformativeSCRsEnableEpoch: unreachableEpoch,
				SCProcessorV2EnableEpoch:          unreachableEpoch,
				StakeLimitsEnableEpoch:            10,
			},
		},
		FeeSettings: config.FeeSettings{
			BlockCapacityOverestimationFactor: 200,
			PercentDecreaseLimitsStep:         10,
		},
		RoundConfig:             testscommon.GetDefaultRoundsConfig(),
		HeaderVersionConfigs:    testscommon.GetDefaultHeaderVersionConfig(),
		HistoryRepository:       &dblookupext.HistoryRepositoryStub{},
		TxExecutionOrderHandler: &commonMocks.TxExecutionOrderHandlerStub{},
		versionedHeaderFactory: &testscommon.VersionedHeaderFactoryStub{
			CreateCalled: func(epoch uint32, _ uint64) data.HeaderHandler {
				return &block.Header{}
			},
		},
		TxCacheSelectionConfig: config.TxCacheSelectionConfig{
			SelectionGasBandwidthIncreasePercent:          400,
			SelectionGasBandwidthIncreaseScheduledPercent: 260,
			SelectionGasRequested:                         10_000_000_000,
			SelectionMaxNumTxs:                            30000,
			SelectionLoopDurationCheckInterval:            10,
		},
	}

	arg.ShardCoordinator = &mock.ShardCoordinatorMock{
		NumOfShards: 2,
		SelfShardId: 0,
	}

	argsAccCreator := factoryState.ArgsAccountCreator{
		Hasher:                 &hashingMocks.HasherMock{},
		Marshaller:             &mock.MarshalizerMock{},
		EnableEpochsHandler:    &enableEpochsHandlerMock.EnableEpochsHandlerStub{},
		StateAccessesCollector: &stateMock.StateAccessesCollectorStub{},
	}
	accCreator, err := factoryState.NewAccountCreator(argsAccCreator)
	require.Nil(t, err)

	arg.Accounts, err = createAccountAdapter(
		&mock.MarshalizerMock{},
		&hashingMocks.HasherMock{},
		accCreator,
		trieStorageManagers[dataRetriever.UserAccountsUnit.String()],
		&testscommon.PubkeyConverterMock{},
		&enableEpochsHandlerMock.EnableEpochsHandlerStub{},
	)
	require.Nil(t, err)
	arg.AccountsProposal = arg.Accounts

	arg.ValidatorAccounts = &stateMock.AccountsStub{
		RootHashCalled: func() ([]byte, error) {
			return make([]byte, 0), nil
		},
		CommitCalled: func() ([]byte, error) {
			return make([]byte, 0), nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error {
			return nil
		},
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return accounts.NewPeerAccount(address)
		},
	}

	gasMap := wasmConfig.MakeGasMapForTests()
	defaults.FillGasMapInternal(gasMap, 1)
	arg.GasSchedule = testscommon.NewGasScheduleNotifierMock(gasMap)
	ted := &economicsmocks.EconomicsHandlerMock{
		GenesisTotalSupplyCalled: func() *big.Int {
			return entireSupply
		},
		MaxGasLimitPerBlockCalled: func(shardID uint32) uint64 {
			return math.MaxInt64
		},
	}
	arg.Economics = ted

	args := genesis.AccountsParserArgs{
		GenesisFilePath: genesisFilename,
		EntireSupply:    arg.Economics.GenesisTotalSupply(),
		MinterAddress:   "",
		PubkeyConverter: arg.Core.AddressPubKeyConverter(),
		KeyGenerator:    &mock.KeyGeneratorStub{},
		Hasher:          &hashingMocks.HasherMock{},
		Marshalizer:     &mock.MarshalizerMock{},
	}

	arg.AccountsParser, err = parsing.NewAccountsParser(args)
	require.Nil(t, err)

	arg.SmartContractParser, err = parsing.NewSmartContractsParser(
		"testdata/smartcontracts.json",
		arg.Core.AddressPubKeyConverter(),
		&mock.KeyGeneratorStub{},
	)
	require.Nil(t, err)

	arg.InitialNodesSetup = initialNodes

	return arg
}

func TestNewGenesisBlockCreator(t *testing.T) {
	t.Parallel()

	t.Run("nil Accounts should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.Accounts = nil

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, process.ErrNilAccountsAdapter))
		require.Nil(t, gbc)
	})
	t.Run("nil Core should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.Core = nil

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, process.ErrNilCoreComponentsHolder))
		require.Nil(t, gbc)
	})
	t.Run("nil Data should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.Data = nil

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, process.ErrNilDataComponentsHolder))
		require.Nil(t, gbc)
	})
	t.Run("nil AddressPubKeyConverter should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.Core = &mock.CoreComponentsMock{
			AddrPubKeyConv:     nil,
			EconomicsDataField: &economicsmocks.EconomicsHandlerMock{},
		}

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, process.ErrNilPubkeyConverter))
		require.Nil(t, gbc)
	})
	t.Run("nil InitialNodesSetup should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.InitialNodesSetup = nil

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, process.ErrNilNodesSetup))
		require.Nil(t, gbc)
	})
	t.Run("nil Economics should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.Economics = nil

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, process.ErrNilEconomicsData))
		require.Nil(t, gbc)
	})
	t.Run("nil ShardCoordinator should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.ShardCoordinator = nil

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, process.ErrNilShardCoordinator))
		require.Nil(t, gbc)
	})
	t.Run("nil StorageService should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.Data = &mock.DataComponentsMock{
			Storage: nil,
		}

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, process.ErrNilStore))
		require.Nil(t, gbc)
	})
	t.Run("nil InternalMarshalizer should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.Core = &mock.CoreComponentsMock{
			AddrPubKeyConv: testscommon.NewPubkeyConverterMock(32),
			IntMarsh:       nil,
		}

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, process.ErrNilMarshalizer))
		require.Nil(t, gbc)
	})
	t.Run("nil Hasher should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.Core = &mock.CoreComponentsMock{
			AddrPubKeyConv: testscommon.NewPubkeyConverterMock(32),
			IntMarsh:       &mock.MarshalizerMock{},
			Hash:           nil,
		}

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, process.ErrNilHasher))
		require.Nil(t, gbc)
	})
	t.Run("nil DataPool should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.Data = &mock.DataComponentsMock{
			Storage:  &storageCommon.ChainStorerStub{},
			DataPool: nil,
		}

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, process.ErrNilPoolsHolder))
		require.Nil(t, gbc)
	})
	t.Run("nil AccountsParser should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.AccountsParser = nil

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, genesis.ErrNilAccountsParser))
		require.Nil(t, gbc)
	})
	t.Run("nil GasSchedule should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.GasSchedule = nil

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, process.ErrNilGasSchedule))
		require.Nil(t, gbc)
	})
	t.Run("nil SmartContractParser should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.SmartContractParser = nil

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, genesis.ErrNilSmartContractParser))
		require.Nil(t, gbc)
	})
	t.Run("nil TrieStorageManagers should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.TrieStorageManagers = nil

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, genesis.ErrNilTrieStorageManager))
		require.Nil(t, gbc)
	})
	t.Run("invalid GenesisNodePrice should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.SystemSCConfig.StakingSystemSCConfig.GenesisNodePrice = "0"

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, genesis.ErrInvalidInitialNodePrice))
		require.Nil(t, gbc)
	})
	t.Run("nil HistoryRepository should error", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		arg.HistoryRepository = nil

		gbc, err := NewGenesisBlockCreator(arg)
		require.True(t, errors.Is(err, process.ErrNilHistoryRepository))
		require.Nil(t, gbc)
	})
	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
		gbc, err := NewGenesisBlockCreator(arg)
		require.NoError(t, err)
		require.NotNil(t, gbc)
	})
}

func TestSetupDRWAAuthorizedCallers_DisabledDoesNothing(t *testing.T) {
	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))

	err := setupDRWAAuthorizedCallers(arg)
	require.NoError(t, err)
}

func TestSetupDRWAAuthorizedCallers_InvalidKeyManagementModel(t *testing.T) {
	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
	arg.DRWAConfig = config.DRWAConfig{
		Enabled:            true,
		KeyManagementModel: "single_key",
	}

	err := setupDRWAAuthorizedCallers(arg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid DRWA key management model")
}

func TestSetupDRWAAuthorizedCallers_MissingRequiredDomain(t *testing.T) {
	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
	arg.DRWAConfig = config.DRWAConfig{
		Enabled:            true,
		KeyManagementModel: drwaKeyManagementModelMultisig3of5Contract,
		AuthorizedCallers: config.DRWAAuthorizedCallersConfig{
			PolicyRegistry:   "0x1111111111111111111111111111111111111111111111111111111111111111",
			AssetManager:     "0x2222222222222222222222222222222222222222222222222222222222222222",
			IdentityRegistry: "0x3333333333333333333333333333333333333333333333333333333333333333",
			Attestation:      "0x4444444444444444444444444444444444444444444444444444444444444444",
			RecoveryAdmin:    "0x5555555555555555555555555555555555555555555555555555555555555555",
		},
	}

	err := setupDRWAAuthorizedCallers(arg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing DRWA authorized caller for domain auth_admin")
}

func TestSetupDRWAAuthorizedCallers_ProvisionedToSystemAccount(t *testing.T) {
	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
	arg.DRWAConfig = config.DRWAConfig{
		Enabled:            true,
		KeyManagementModel: drwaKeyManagementModelMultisig3of5Contract,
		AuthorizedCallers: config.DRWAAuthorizedCallersConfig{
			AuthAdmin:        "0x1111111111111111111111111111111111111111111111111111111111111111",
			PolicyRegistry:   "0x2222222222222222222222222222222222222222222222222222222222222222",
			AssetManager:     "0x3333333333333333333333333333333333333333333333333333333333333333",
			IdentityRegistry: "0x4444444444444444444444444444444444444444444444444444444444444444",
			Attestation:      "0x5555555555555555555555555555555555555555555555555555555555555555",
			RecoveryAdmin:    "0x6666666666666666666666666666666666666666666666666666666666666666",
		},
	}

	err := setupDRWAAuthorizedCallers(arg)
	require.NoError(t, err)

	systemAccount, err := arg.Accounts.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)

	rawValue, _, err := systemAccount.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue([]byte("drwa:auth:auth_admin"))
	require.NoError(t, err)
	require.NotEmpty(t, rawValue)

	record := &drwaAuthorizedCallerRecordForTest{}
	require.NoError(t, json.Unmarshal(rawValue, record))
	require.Equal(t, uint64(1), record.Version)

	expectedAddr, err := hooks.NormalizeDRWAAuthorizedCallerAddress(arg.DRWAConfig.AuthorizedCallers.AuthAdmin)
	require.NoError(t, err)
	require.Equal(t, expectedAddr, record.Address)
}

func TestSetupDRWARecoveryGovernance_ProvisionedToSystemAccount(t *testing.T) {
	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
	initializeDRWASystemAccountForRecoveryGovernanceTest(t, arg)
	arg.DRWAConfig = config.DRWAConfig{
		Enabled: true,
		RecoveryGovernance: []config.DRWARecoveryGovernanceConfig{
			{
				TokenID:     "RWA-abcdef",
				Threshold:   2,
				Signers:     []string{"0x1111111111111111111111111111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333333333333333333333333333"},
				ProposalTTL: 2400,
				MaxSigners:  5,
			},
		},
	}

	err := setupDRWARecoveryGovernance(arg)
	require.NoError(t, err)

	systemAccount, err := arg.Accounts.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	key := []byte("DRWA_GOV_" + hex.EncodeToString([]byte("RWA-abcdef")))
	rawValue, _, err := systemAccount.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(key)
	require.NoError(t, err)
	require.NotEmpty(t, rawValue)

	record := &drwaRecoveryGovernanceRecordForTest{}
	require.NoError(t, json.Unmarshal(rawValue, record))
	require.Equal(t, uint64(1), record.Version)
	require.Equal(t, uint32(2), record.Threshold)
	require.Equal(t, uint64(2400), record.ProposalTTL)
	require.Equal(t, uint32(5), record.MaxSigners)
	require.Len(t, record.Signers, 3)

	expectedSigner, err := hooks.NormalizeDRWAAuthorizedCallerAddress(arg.DRWAConfig.RecoveryGovernance[0].Signers[0])
	require.NoError(t, err)
	require.Equal(t, expectedSigner, record.Signers[0])

	// Bootstrap is write-once: it must not become a post-genesis config
	// replacement path.
	require.Error(t, setupDRWARecoveryGovernance(arg))
	rawValue, _, err = systemAccount.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(key)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(rawValue, record))
	require.Equal(t, uint64(1), record.Version)
}

func TestSetupDRWARecoveryGovernance_RejectsInvalidConfiguration(t *testing.T) {
	validSigner := "0x1111111111111111111111111111111111111111111111111111111111111111"
	testCases := []struct {
		name       string
		governance []config.DRWARecoveryGovernanceConfig
		expected   string
	}{
		{
			name: "duplicate token ID",
			governance: []config.DRWARecoveryGovernanceConfig{
				{TokenID: "RWA-abcdef", Threshold: 2, Signers: []string{validSigner, "0x2222222222222222222222222222222222222222222222222222222222222222"}, ProposalTTL: 1, MaxSigners: 2},
				{TokenID: "RWA-abcdef", Threshold: 2, Signers: []string{validSigner, "0x3333333333333333333333333333333333333333333333333333333333333333"}, ProposalTTL: 1, MaxSigners: 2},
			},
			expected: "duplicate DRWA recovery governance token ID",
		},
		{
			name: "invalid signer",
			governance: []config.DRWARecoveryGovernanceConfig{
				{TokenID: "RWA-abcdef", Threshold: 2, Signers: []string{validSigner, "not-an-address"}, ProposalTTL: 1, MaxSigners: 2},
			},
			expected: "invalid DRWA recovery governance signer",
		},
		{
			name: "invalid quorum",
			governance: []config.DRWARecoveryGovernanceConfig{
				{TokenID: "RWA-abcdef", Threshold: 1, Signers: []string{validSigner}, ProposalTTL: 1, MaxSigners: 1},
			},
			expected: "invalid DRWA recovery governance config",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
			initializeDRWASystemAccountForRecoveryGovernanceTest(t, arg)
			arg.DRWAConfig = config.DRWAConfig{Enabled: true, RecoveryGovernance: testCase.governance}

			err := setupDRWARecoveryGovernance(arg)
			require.Error(t, err)
			require.Contains(t, err.Error(), testCase.expected)
		})
	}
}

func TestSetupDRWARecoveryGovernance_InvalidBatchDoesNotProvisionAnyToken(t *testing.T) {
	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
	initializeDRWASystemAccountForRecoveryGovernanceTest(t, arg)
	arg.DRWAConfig = config.DRWAConfig{
		Enabled: true,
		RecoveryGovernance: []config.DRWARecoveryGovernanceConfig{
			{
				TokenID:     "RWA-valid",
				Threshold:   2,
				Signers:     []string{"0x1111111111111111111111111111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222222222222222222222222222"},
				ProposalTTL: 1,
				MaxSigners:  2,
			},
			{
				TokenID:     "RWA-invalid",
				Threshold:   1,
				Signers:     []string{"0x3333333333333333333333333333333333333333333333333333333333333333"},
				ProposalTTL: 1,
				MaxSigners:  1,
			},
		},
	}

	require.Error(t, setupDRWARecoveryGovernance(arg))
	systemAccount, err := arg.Accounts.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	key := []byte("DRWA_GOV_" + hex.EncodeToString([]byte("RWA-valid")))
	rawValue, _, err := systemAccount.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(key)
	require.NoError(t, err)
	require.Empty(t, rawValue)
}

func TestSetupDRWARecoveryGovernance_DisabledOrUnconfiguredDoesNothing(t *testing.T) {
	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
	arg.DRWAConfig = config.DRWAConfig{
		Enabled: false,
		RecoveryGovernance: []config.DRWARecoveryGovernanceConfig{
			{TokenID: "RWA-abcdef", Threshold: 2, Signers: []string{"not-an-address"}, ProposalTTL: 1, MaxSigners: 2},
		},
	}

	require.NoError(t, setupDRWARecoveryGovernance(arg))
	arg.DRWAConfig = config.DRWAConfig{Enabled: true}
	require.NoError(t, setupDRWARecoveryGovernance(arg))
}

func initializeDRWASystemAccountForRecoveryGovernanceTest(t *testing.T, arg ArgsGenesisBlockCreator) {
	t.Helper()
	require.NoError(t, hooks.ProvisionDRWAAuthorizedCaller(arg.Accounts, "auth_admin", bytes.Repeat([]byte{0x11}, 32), 1))
}

func TestGenesisBlockCreator_CreateGenesisBlocksFailsForInvalidDRWAConfig(t *testing.T) {
	testCases := []struct {
		name     string
		config   config.DRWAConfig
		expected string
	}{
		{
			name: "invalid key management model",
			config: config.DRWAConfig{
				Enabled:            true,
				KeyManagementModel: "single_key",
			},
			expected: "invalid DRWA key management model",
		},
		{
			name: "missing authorized caller",
			config: config.DRWAConfig{
				Enabled:            true,
				KeyManagementModel: drwaKeyManagementModelMultisig3of5Contract,
				AuthorizedCallers: config.DRWAAuthorizedCallersConfig{
					PolicyRegistry:   "0x1111111111111111111111111111111111111111111111111111111111111111",
					AssetManager:     "0x2222222222222222222222222222222222222222222222222222222222222222",
					IdentityRegistry: "0x3333333333333333333333333333333333333333333333333333333333333333",
					Attestation:      "0x4444444444444444444444444444444444444444444444444444444444444444",
					RecoveryAdmin:    "0x5555555555555555555555555555555555555555555555555555555555555555",
				},
			},
			expected: "missing DRWA authorized caller for domain auth_admin",
		},
		{
			name:     "genesis enforcement with DRWA disabled",
			config:   config.DRWAConfig{Enabled: false},
			expected: "DRWA enforcement is enabled at genesis but DRWA caller provisioning is disabled",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
			arg.DRWAConfig = testCase.config
			arg.EpochConfig.EnableEpochs.DRWAEnforcementEnableEpoch = 0
			creator, err := NewGenesisBlockCreator(arg)
			require.NoError(t, err)

			_, err = creator.CreateGenesisBlocks()
			require.Error(t, err)
			require.Contains(t, err.Error(), testCase.expected)
		})
	}
}

func TestGenesisBlockCreator_CreateGenesisBlocksAcceptsValidDRWAConfig(t *testing.T) {
	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
	arg.DRWAConfig = config.DRWAConfig{
		Enabled:            true,
		KeyManagementModel: drwaKeyManagementModelMultisig3of5Contract,
		AuthorizedCallers: config.DRWAAuthorizedCallersConfig{
			AuthAdmin:        "0x1111111111111111111111111111111111111111111111111111111111111111",
			PolicyRegistry:   "0x2222222222222222222222222222222222222222222222222222222222222222",
			AssetManager:     "0x3333333333333333333333333333333333333333333333333333333333333333",
			IdentityRegistry: "0x4444444444444444444444444444444444444444444444444444444444444444",
			Attestation:      "0x5555555555555555555555555555555555555555555555555555555555555555",
			RecoveryAdmin:    "0x6666666666666666666666666666666666666666666666666666666666666666",
		},
	}
	creator, err := NewGenesisBlockCreator(arg)
	require.NoError(t, err)

	blocks, err := creator.CreateGenesisBlocks()
	require.NoError(t, err)
	require.NotEmpty(t, blocks)
}

func TestGenesisBlockCreator_CreateGenesisBlockAfterHardForkShouldCreateSCResultingAddresses(t *testing.T) {
	scAddressBytes, _ := hex.DecodeString("00000000000000000500761b8c4a25d3979359223208b412285f635e71300102")
	initialNodesSetup := &mock.InitialNodesHandlerStub{
		InitialNodesInfoCalled: func() (map[uint32][]nodesCoordinator.GenesisNodeInfoHandler, map[uint32][]nodesCoordinator.GenesisNodeInfoHandler) {
			return map[uint32][]nodesCoordinator.GenesisNodeInfoHandler{
				0: {
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: scAddressBytes,
						PubKeyBytesValue:  bytes.Repeat([]byte{1}, 96),
					},
				},
				1: {
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: scAddressBytes,
						PubKeyBytesValue:  bytes.Repeat([]byte{3}, 96),
					},
				},
			}, make(map[uint32][]nodesCoordinator.GenesisNodeInfoHandler)
		},
		MinNumberOfNodesCalled: func() uint32 {
			return 1
		},
	}
	arg := createMockArgument(
		t,
		"testdata/genesisTest1.json",
		initialNodesSetup,
		big.NewInt(22000),
	)
	gbc, err := NewGenesisBlockCreator(arg)
	require.Nil(t, err)

	blocks, err := gbc.CreateGenesisBlocks()
	assert.Nil(t, err)
	assert.Equal(t, 3, len(blocks))

	mapAddressesWithDeploy, err := arg.SmartContractParser.GetDeployedSCAddresses(genesis.DNSType)
	assert.Nil(t, err)
	assert.Equal(t, len(mapAddressesWithDeploy), core.MaxNumShards)

	newArgs := createMockArgument(
		t,
		"testdata/genesisTest1.json",
		initialNodesSetup,
		big.NewInt(22000),
	)
	hardForkGbc, err := NewGenesisBlockCreator(newArgs)
	assert.Nil(t, err)
	err = hardForkGbc.computeDNSAddresses(gbc.arg.EpochConfig.EnableEpochs)
	assert.Nil(t, err)

	mapAfterHardForkAddresses, err := newArgs.SmartContractParser.GetDeployedSCAddresses(genesis.DNSType)
	assert.Nil(t, err)
	assert.Equal(t, len(mapAfterHardForkAddresses), core.MaxNumShards)
	for address := range mapAddressesWithDeploy {
		_, ok := mapAfterHardForkAddresses[address]
		assert.True(t, ok)
	}
}

func TestGenesisBlockCreator_CreateGenesisBlocksJustDelegationShouldWorkAndDNS(t *testing.T) {
	scAddressBytes, _ := hex.DecodeString("00000000000000000500761b8c4a25d3979359223208b412285f635e71300102")
	stakedAddr, _ := hex.DecodeString("b00102030405060708090001020304050607080900010203040506070809000b")
	initialNodesSetup := &mock.InitialNodesHandlerStub{
		InitialNodesInfoCalled: func() (map[uint32][]nodesCoordinator.GenesisNodeInfoHandler, map[uint32][]nodesCoordinator.GenesisNodeInfoHandler) {
			return map[uint32][]nodesCoordinator.GenesisNodeInfoHandler{
				0: {
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: scAddressBytes,
						PubKeyBytesValue:  bytes.Repeat([]byte{1}, 96),
					},
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: stakedAddr,
						PubKeyBytesValue:  bytes.Repeat([]byte{2}, 96),
					},
				},
				1: {
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: scAddressBytes,
						PubKeyBytesValue:  bytes.Repeat([]byte{3}, 96),
					},
				},
			}, make(map[uint32][]nodesCoordinator.GenesisNodeInfoHandler)
		},
		MinNumberOfNodesCalled: func() uint32 {
			return 1
		},
	}
	arg := createMockArgument(
		t,
		"testdata/genesisTest1.json",
		initialNodesSetup,
		big.NewInt(22000),
	)

	gbc, err := NewGenesisBlockCreator(arg)
	require.Nil(t, err)

	blocks, err := gbc.CreateGenesisBlocks()

	assert.Nil(t, err)
	assert.Equal(t, 3, len(blocks))
}

func TestGenesisBlockCreator_CreateGenesisBlocksStakingAndDelegationShouldWorkAndDNS(t *testing.T) {
	scAddressBytes, _ := hex.DecodeString("00000000000000000500761b8c4a25d3979359223208b412285f635e71300102")
	stakedAddr, _ := hex.DecodeString("b00102030405060708090001020304050607080900010203040506070809000b")
	stakedAddr2, _ := hex.DecodeString("d00102030405060708090001020304050607080900010203040506070809000d")
	initialNodesSetup := &mock.InitialNodesHandlerStub{
		InitialNodesInfoCalled: func() (map[uint32][]nodesCoordinator.GenesisNodeInfoHandler, map[uint32][]nodesCoordinator.GenesisNodeInfoHandler) {
			return map[uint32][]nodesCoordinator.GenesisNodeInfoHandler{
				0: {
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: scAddressBytes,
						PubKeyBytesValue:  bytes.Repeat([]byte{1}, 96),
					},
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: stakedAddr,
						PubKeyBytesValue:  bytes.Repeat([]byte{2}, 96),
					},
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: scAddressBytes,
						PubKeyBytesValue:  bytes.Repeat([]byte{3}, 96),
					},
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: stakedAddr2,
						PubKeyBytesValue:  bytes.Repeat([]byte{8}, 96),
					},
				},
				1: {
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: scAddressBytes,
						PubKeyBytesValue:  bytes.Repeat([]byte{4}, 96),
					},
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: scAddressBytes,
						PubKeyBytesValue:  bytes.Repeat([]byte{5}, 96),
					},
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: stakedAddr2,
						PubKeyBytesValue:  bytes.Repeat([]byte{6}, 96),
					},
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: stakedAddr2,
						PubKeyBytesValue:  bytes.Repeat([]byte{7}, 96),
					},
				},
			}, make(map[uint32][]nodesCoordinator.GenesisNodeInfoHandler)
		},
		MinNumberOfNodesCalled: func() uint32 {
			return 1
		},
	}
	arg := createMockArgument(
		t,
		"testdata/genesisTest2.json",
		initialNodesSetup,
		big.NewInt(47000),
	)
	arg.ShardCoordinator, _ = sharding.NewMultiShardCoordinator(2, 1)
	gbc, err := NewGenesisBlockCreator(arg)
	require.Nil(t, err)

	blocks, err := gbc.CreateGenesisBlocks()

	assert.Nil(t, err)
	assert.Equal(t, 3, len(blocks))

	_, err = arg.Accounts.Commit()
	require.Nil(t, err)

	t.Run("backwards compatibility on nonces: for a shard != 0, all accounts not having a delegation value would "+
		"have caused an artificial increase in their accounts nonce", func(t *testing.T) {
		accnt, errGet := arg.Accounts.GetExistingAccount(stakedAddr)
		require.Nil(t, errGet)
		assert.Equal(t, uint64(2), accnt.GetNonce())
	})
}

func TestGenesisBlockCreator_GetIndexingDataShouldWork(t *testing.T) {
	scAddressBytes, _ := hex.DecodeString("00000000000000000500761b8c4a25d3979359223208b412285f635e71300102")
	stakedAddr, _ := hex.DecodeString("b00102030405060708090001020304050607080900010203040506070809000b")
	stakedAddr2, _ := hex.DecodeString("d00102030405060708090001020304050607080900010203040506070809000d")
	initialGenesisNodes := map[uint32][]nodesCoordinator.GenesisNodeInfoHandler{
		0: {
			&mock.GenesisNodeInfoHandlerMock{
				AddressBytesValue: scAddressBytes,
				PubKeyBytesValue:  bytes.Repeat([]byte{1}, 96),
			},
			&mock.GenesisNodeInfoHandlerMock{
				AddressBytesValue: stakedAddr,
				PubKeyBytesValue:  bytes.Repeat([]byte{2}, 96),
			},
			&mock.GenesisNodeInfoHandlerMock{
				AddressBytesValue: scAddressBytes,
				PubKeyBytesValue:  bytes.Repeat([]byte{3}, 96),
			},
			&mock.GenesisNodeInfoHandlerMock{
				AddressBytesValue: stakedAddr2,
				PubKeyBytesValue:  bytes.Repeat([]byte{8}, 96),
			},
		},
		1: {
			&mock.GenesisNodeInfoHandlerMock{
				AddressBytesValue: scAddressBytes,
				PubKeyBytesValue:  bytes.Repeat([]byte{4}, 96),
			},
			&mock.GenesisNodeInfoHandlerMock{
				AddressBytesValue: scAddressBytes,
				PubKeyBytesValue:  bytes.Repeat([]byte{5}, 96),
			},
			&mock.GenesisNodeInfoHandlerMock{
				AddressBytesValue: stakedAddr2,
				PubKeyBytesValue:  bytes.Repeat([]byte{6}, 96),
			},
			&mock.GenesisNodeInfoHandlerMock{
				AddressBytesValue: stakedAddr2,
				PubKeyBytesValue:  bytes.Repeat([]byte{7}, 96),
			},
		},
	}
	initialNodesSetup := &mock.InitialNodesHandlerStub{
		InitialNodesInfoCalled: func() (map[uint32][]nodesCoordinator.GenesisNodeInfoHandler, map[uint32][]nodesCoordinator.GenesisNodeInfoHandler) {
			return initialGenesisNodes, make(map[uint32][]nodesCoordinator.GenesisNodeInfoHandler)
		},
		MinNumberOfNodesCalled: func() uint32 {
			return 1
		},
	}
	arg := createMockArgument(
		t,
		"testdata/genesisTest2.json",
		initialNodesSetup,
		big.NewInt(47000),
	)
	gbc, err := NewGenesisBlockCreator(arg)
	require.Nil(t, err)

	blocks, err := gbc.CreateGenesisBlocks()
	assert.Nil(t, err)
	assert.Equal(t, 3, len(blocks))

	indexingData := gbc.GetIndexingData()

	numDNSTypeScTxs := 256
	numDefaultTypeScTxs := 1
	numSystemSC := 4

	numInitialNodes := 0
	for k := range initialGenesisNodes {
		numInitialNodes += len(initialGenesisNodes[k])
	}

	reqNumDeployInitialScTxs := numDNSTypeScTxs + numDefaultTypeScTxs
	reqNumScrs := getRequiredNumScrsTxs(indexingData, 0)
	reqNumDelegationTxs := 4
	assert.Equal(t, reqNumDeployInitialScTxs, len(indexingData[0].DeployInitialScTxs))
	assert.Equal(t, 0, len(indexingData[0].DeploySystemScTxs))
	assert.Equal(t, reqNumDelegationTxs, len(indexingData[0].DelegationTxs))
	assert.Equal(t, 0, len(indexingData[0].StakingTxs))
	assert.Equal(t, reqNumScrs, len(indexingData[0].ScrsTxs))

	reqNumDeployInitialScTxs = numDNSTypeScTxs
	reqNumScrs = getRequiredNumScrsTxs(indexingData, 1)
	assert.Equal(t, reqNumDeployInitialScTxs, len(indexingData[1].DeployInitialScTxs))
	assert.Equal(t, 0, len(indexingData[1].DeploySystemScTxs))
	assert.Equal(t, 0, len(indexingData[1].DelegationTxs))
	assert.Equal(t, 0, len(indexingData[1].StakingTxs))
	assert.Equal(t, reqNumScrs, len(indexingData[1].ScrsTxs))

	reqNumScrs = getRequiredNumScrsTxs(indexingData, core.MetachainShardId)
	assert.Equal(t, 0, len(indexingData[core.MetachainShardId].DeployInitialScTxs))
	assert.Equal(t, numSystemSC, len(indexingData[core.MetachainShardId].DeploySystemScTxs))
	assert.Equal(t, 0, len(indexingData[core.MetachainShardId].DelegationTxs))
	assert.Equal(t, numInitialNodes, len(indexingData[core.MetachainShardId].StakingTxs))
	assert.Equal(t, reqNumScrs, len(indexingData[core.MetachainShardId].ScrsTxs))
}

func getRequiredNumScrsTxs(idata map[uint32]*genesis.IndexingData, shardId uint32) int {
	n := 2 * (len(idata[shardId].DeployInitialScTxs) + len(idata[shardId].DelegationTxs))
	n += getRequiredNumDeploySystemScrsTxs(idata[shardId].DeploySystemScTxs)
	n += 3 * len(idata[shardId].StakingTxs)
	return n
}

func getRequiredNumDeploySystemScrsTxs(deploySystemScTxs []data.TransactionHandler) int {
	numScrs := 0
	for _, tx := range deploySystemScTxs {
		if bytes.Equal(tx.GetSndAddr(), vm.ValidatorSCAddress) || bytes.Equal(tx.GetSndAddr(), vm.StakingSCAddress) {
			numScrs++
			continue
		}

		numScrs += 2
	}

	return numScrs
}

func TestCreateArgsGenesisBlockCreator_ShouldErrWhenGetNewArgForShardFails(t *testing.T) {
	scAddressBytes, _ := hex.DecodeString("00000000000000000500761b8c4a25d3979359223208b412285f635e71300102")
	shardIDs := []uint32{0, 1}
	mapArgsGenesisBlockCreator := make(map[uint32]ArgsGenesisBlockCreator)
	initialNodesSetup := createDummyNodesHandler(scAddressBytes)
	arg := createMockArgument(
		t,
		"testdata/genesisTest1.json",
		initialNodesSetup,
		big.NewInt(22000),
	)

	arg.ShardCoordinator = &mock.ShardCoordinatorMock{SelfShardId: 1}
	arg.TrieStorageManagers = make(map[string]common.StorageManager)
	gbc, err := NewGenesisBlockCreator(arg)
	require.Nil(t, err)

	err = gbc.createArgsGenesisBlockCreator(shardIDs, mapArgsGenesisBlockCreator)
	assert.True(t, errors.Is(err, trie.ErrNilTrieStorage))
}

func TestCreateArgsGenesisBlockCreator_ShouldWork(t *testing.T) {
	shardIDs := []uint32{0, 1}
	mapArgsGenesisBlockCreator := make(map[uint32]ArgsGenesisBlockCreator)
	scAddressBytes, _ := hex.DecodeString("00000000000000000500761b8c4a25d3979359223208b412285f635e71300102")
	initialNodesSetup := &mock.InitialNodesHandlerStub{
		InitialNodesInfoCalled: func() (map[uint32][]nodesCoordinator.GenesisNodeInfoHandler, map[uint32][]nodesCoordinator.GenesisNodeInfoHandler) {
			return map[uint32][]nodesCoordinator.GenesisNodeInfoHandler{
				0: {
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: scAddressBytes,
						PubKeyBytesValue:  bytes.Repeat([]byte{1}, 96),
					},
				},
				1: {
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: scAddressBytes,
						PubKeyBytesValue:  bytes.Repeat([]byte{3}, 96),
					},
				},
			}, make(map[uint32][]nodesCoordinator.GenesisNodeInfoHandler)
		},
		MinNumberOfNodesCalled: func() uint32 {
			return 1
		},
	}
	arg := createMockArgument(
		t,
		"testdata/genesisTest1.json",
		initialNodesSetup,
		big.NewInt(22000),
	)
	gbc, err := NewGenesisBlockCreator(arg)
	require.Nil(t, err)

	err = gbc.createArgsGenesisBlockCreator(shardIDs, mapArgsGenesisBlockCreator)
	assert.Nil(t, err)
	require.Equal(t, 2, len(mapArgsGenesisBlockCreator))
	assert.Equal(t, uint32(0), mapArgsGenesisBlockCreator[0].ShardCoordinator.SelfId())
	assert.Equal(t, uint32(1), mapArgsGenesisBlockCreator[1].ShardCoordinator.SelfId())
}

func TestCreateHardForkBlockProcessors_ShouldWork(t *testing.T) {
	selfShardID := uint32(0)
	shardIDs := []uint32{1, core.MetachainShardId}
	mapArgsGenesisBlockCreator := make(map[uint32]ArgsGenesisBlockCreator)
	mapHardForkBlockProcessor := make(map[uint32]update.HardForkBlockProcessor)
	scAddressBytes, _ := hex.DecodeString("00000000000000000500761b8c4a25d3979359223208b412285f635e71300102")
	initialNodesSetup := &mock.InitialNodesHandlerStub{
		InitialNodesInfoCalled: func() (map[uint32][]nodesCoordinator.GenesisNodeInfoHandler, map[uint32][]nodesCoordinator.GenesisNodeInfoHandler) {
			return map[uint32][]nodesCoordinator.GenesisNodeInfoHandler{
				0: {
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: scAddressBytes,
						PubKeyBytesValue:  bytes.Repeat([]byte{1}, 96),
					},
				},
				1: {
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: scAddressBytes,
						PubKeyBytesValue:  bytes.Repeat([]byte{3}, 96),
					},
				},
			}, make(map[uint32][]nodesCoordinator.GenesisNodeInfoHandler)
		},
		MinNumberOfNodesCalled: func() uint32 {
			return 1
		},
	}
	arg := createMockArgument(
		t,
		"testdata/genesisTest1.json",
		initialNodesSetup,
		big.NewInt(22000),
	)
	arg.importHandler = &updateMock.ImportHandlerStub{
		GetAccountsDBForShardCalled: func(shardID uint32) state.AccountsAdapter {
			return &stateMock.AccountsStub{}
		},
	}
	gbc, err := NewGenesisBlockCreator(arg)
	require.Nil(t, err)

	_ = gbc.createArgsGenesisBlockCreator(shardIDs, mapArgsGenesisBlockCreator)

	err = createHardForkBlockProcessors(selfShardID, shardIDs, mapArgsGenesisBlockCreator, mapHardForkBlockProcessor)
	assert.Nil(t, err)
	require.Equal(t, 2, len(mapHardForkBlockProcessor))
}

func createDummyNodesHandler(scAddressBytes []byte) genesis.InitialNodesHandler {
	return &mock.InitialNodesHandlerStub{
		InitialNodesInfoCalled: func() (map[uint32][]nodesCoordinator.GenesisNodeInfoHandler, map[uint32][]nodesCoordinator.GenesisNodeInfoHandler) {
			return map[uint32][]nodesCoordinator.GenesisNodeInfoHandler{
				0: {
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: scAddressBytes,
						PubKeyBytesValue:  bytes.Repeat([]byte{1}, 96),
					},
				},
				1: {
					&mock.GenesisNodeInfoHandlerMock{
						AddressBytesValue: scAddressBytes,
						PubKeyBytesValue:  bytes.Repeat([]byte{3}, 96),
					},
				},
			}, make(map[uint32][]nodesCoordinator.GenesisNodeInfoHandler)
		},
		MinNumberOfNodesCalled: func() uint32 {
			return 1
		},
	}
}

func TestCreateArgsGenesisBlockCreator_ShouldWorkAndCreateEmpty(t *testing.T) {
	t.Parallel()

	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
	arg.StartEpochNum = 1
	gbc, err := NewGenesisBlockCreator(arg)
	require.NoError(t, err)
	require.NotNil(t, gbc)

	blocks, err := gbc.CreateGenesisBlocks()
	assert.Nil(t, err)
	assert.Equal(t, 3, len(blocks))
	for _, blockInstance := range blocks {
		assert.Zero(t, blockInstance.GetNonce())
		assert.Zero(t, blockInstance.GetRound())
		assert.Zero(t, blockInstance.GetEpoch())
	}
}
