package process

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/genesis"
	genesisData "github.com/multiversx/mx-chain-go/genesis/data"
	"github.com/multiversx/mx-chain-go/genesis/mock"
	nodeProcess "github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/drwa"
	shardFactory "github.com/multiversx/mx-chain-go/process/factory/shard"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/testscommon"
	dataMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/hashingMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	storageMock "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/multiversx/mx-chain-go/vm/systemSmartContracts/defaults"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	wasmConfig "github.com/multiversx/mx-chain-vm-go/config"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CGenesisCreatorChecksOriginalGenesisFirst(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured bool
		evidence   bool
		start      uint32
		hardFork   bool
		want       error
	}{
		{"ordinary", false, false, 17, false, nodeProcess.ErrNilAccountsAdapter},
		{"original", true, true, 17, false, nodeProcess.ErrNilAccountsAdapter},
		{"missing_programme", true, false, 17, false, drwa.ErrInitialProgrammeLimits},
		{"later_start", true, true, 18, false, drwa.ErrDeploymentIdentity},
		{"hard_fork", true, true, 17, true, drwa.ErrDeploymentIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arg := ArgsGenesisBlockCreator{GenesisEpoch: 17, StartEpochNum: tc.start}
			arg.HardForkConfig.AfterHardFork = tc.hardFork
			arg.HardForkConfig.StartEpoch = 17
			if tc.configured {
				arg.DRWAMinimumGenesis = &config.DRWAMinimumGenesis{}
			}
			if tc.evidence {
				// Admission tests only the presence of programme inputs.
				arg.DRWAInitialProgrammes = []drwa.InitialProgrammeEvidence{{}}
			}
			creator, err := NewGenesisBlockCreator(arg)
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, creator)
		})
	}
}

func TestQualSP281CGenesisOperandsBindOnlySelectedMetachainAccounts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		self       uint32
		target     uint32
		configured bool
	}{
		{"local_meta", core.MetachainShardId, core.MetachainShardId, true},
		{"remote_meta", 0, core.MetachainShardId, true},
		{"local_shard", 0, 0, true},
		{"remote_shard", core.MetachainShardId, 0, true},
		{"ordinary_meta", 0, core.MetachainShardId, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accounts := &stateMock.AccountsStub{}
			data := &mock.DataComponentsMock{}
			arg := ArgsGenesisBlockCreator{
				Accounts: accounts, AccountsProposal: accounts, Data: data,
				Core: &mock.CoreComponentsMock{
					IntMarsh: &marshal.GogoProtoMarshalizer{}, Hash: blake2b.NewBlake2b(),
					AddrPubKeyConv:           testscommon.NewPubkeyConverterMock(32),
					EnableEpochsHandlerField: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(),
				},
				ShardCoordinator:     &mock.ShardCoordinatorMock{NumOfShards: 2, SelfShardId: tc.self},
				HeaderVersionConfigs: testscommon.GetDefaultHeaderVersionConfig(),
				TrieStorageManagers: map[string]common.StorageManager{
					dataRetriever.UserAccountsUnit.String(): &storageManager.StorageManagerStub{},
				},
			}
			if tc.configured {
				arg.DRWAMinimumGenesis = &config.DRWAMinimumGenesis{}
			}
			creator := &genesisBlockCreator{arg: arg}
			got, err := creator.getNewArgForShard(tc.target)
			require.NoError(t, err)
			require.Equal(t, tc.target, got.ShardCoordinator.SelfId())
			require.NotSame(t, data, got.Data)
			if tc.self == tc.target {
				require.Same(t, accounts, got.Accounts)
			} else {
				require.NotSame(t, accounts, got.Accounts)
				t.Cleanup(func() { require.NoError(t, got.Accounts.Close()) })
			}
			require.Same(t, got.Accounts, got.AccountsProposal)
			if tc.configured && tc.target == core.MetachainShardId {
				require.Same(t, got.Accounts, got.drwaGenesisAccounts)
			} else {
				require.Nil(t, got.drwaGenesisAccounts)
			}
			require.Nil(t, creator.arg.drwaGenesisAccounts)
			require.Same(t, accounts, creator.arg.Accounts)
		})
	}
}

// Observe the hook's constructor consuming the exact core hasher. The VM
// factories also validate hashers, so observe this before hook registration.
type qualSP281CGenesisHasher struct {
	hashingMocks.HasherMock
	inspected bool
}

func (h *qualSP281CGenesisHasher) IsInterfaceNil() bool {
	h.inspected = true
	return false
}

func qualSP281CGenesisHookOperands(t *testing.T, shardID uint32) (ArgsGenesisBlockCreator, *int) {
	t.Helper()
	hasher := &qualSP281CGenesisHasher{}
	hooksRegistered := 0
	gasMap := wasmConfig.MakeGasMapForTests()
	defaults.FillGasMapInternal(gasMap, 1)
	gas := testscommon.NewGasScheduleNotifierMock(gasMap)
	gas.RegisterNotifyHandlerCalled = func(handler core.GasScheduleSubscribeHandler) {
		if _, isHook := handler.(*hooks.BlockChainHookImpl); isHook {
			require.True(t, hasher.inspected)
			hooksRegistered++
		}
	}
	return ArgsGenesisBlockCreator{
		Accounts: &stateMock.AccountsStub{},
		Core: &mock.CoreComponentsMock{
			IntMarsh: &mock.MarshalizerMock{}, Hash: hasher,
			AddrPubKeyConv:      testscommon.NewPubkeyConverterMock(32),
			UInt64ByteSliceConv: &mock.Uint64ByteSliceConverterMock{},
		},
		Data: &mock.DataComponentsMock{
			Storage: &storageMock.ChainStorerStub{},
			Blkc:    &testscommon.ChainHandlerStub{}, DataPool: dataMock.NewPoolsHolderMock(),
		},
		ShardCoordinator: &mock.ShardCoordinatorMock{NumOfShards: 2, SelfShardId: shardID},
		BlockSignKeyGen:  &mock.KeyGenMock{}, GasSchedule: gas,
	}, &hooksRegistered
}

func TestQualSP281CGenesisDNSAddressesUseHookAndPreserveShardSuffix(t *testing.T) {
	arg, registrations := qualSP281CGenesisHookOperands(t, 0)
	other := &genesisData.InitialSmartContract{Type: "delegation"}
	dns := &genesisData.InitialSmartContract{Type: genesis.DNSType}
	vmType := []byte{5, 0}
	dns.SetVmTypeBytes(vmType)
	arg.SmartContractParser = &mock.SmartContractParserStub{
		InitialSmartContractsCalled: func() []genesis.InitialSmartContractHandler {
			return []genesis.InitialSmartContractHandler{other, dns}
		},
	}
	creator := &genesisBlockCreator{arg: arg}
	require.NoError(t, creator.computeDNSAddresses(createGenesisConfig(config.EnableEpochs{})))
	require.Equal(t, 1, *registrations)
	require.Empty(t, other.AddressesBytes())
	require.Empty(t, other.Addresses())
	require.Len(t, dns.AddressesBytes(), core.MaxNumShards)
	require.Len(t, dns.Addresses(), core.MaxNumShards)
	for i, address := range dns.AddressesBytes() {
		require.Len(t, address, 32)
		require.Equal(t, make([]byte, 8), address[:8])
		require.Equal(t, vmType, address[8:10])
		require.Equal(t, []byte{0, byte(i)}, address[30:])
		require.Equal(t, hex.EncodeToString(address), dns.Addresses()[i])
	}
}

func TestQualSP281CGenesisDNSRefusesInvalidVMTypeAndSkipsAbsentDNS(t *testing.T) {
	enable := createGenesisConfig(config.EnableEpochs{})

	t.Run("absent_dns", func(t *testing.T) {
		other := &genesisData.InitialSmartContract{Type: "delegation"}
		arg, registrations := qualSP281CGenesisHookOperands(t, 0)
		arg.SmartContractParser = &mock.SmartContractParserStub{
			InitialSmartContractsCalled: func() []genesis.InitialSmartContractHandler {
				return []genesis.InitialSmartContractHandler{other}
			},
		}
		creator := &genesisBlockCreator{arg: arg}
		require.NoError(t, creator.computeDNSAddresses(enable))
		require.Zero(t, *registrations)
		require.Empty(t, other.AddressesBytes())
		require.Empty(t, other.Addresses())
	})

	t.Run("invalid_vm_type", func(t *testing.T) {
		dns := &genesisData.InitialSmartContract{Type: genesis.DNSType}
		dns.SetVmTypeBytes([]byte{5})
		arg, registrations := qualSP281CGenesisHookOperands(t, 0)
		arg.SmartContractParser = &mock.SmartContractParserStub{
			InitialSmartContractsCalled: func() []genesis.InitialSmartContractHandler {
				return []genesis.InitialSmartContractHandler{dns}
			},
		}
		creator := &genesisBlockCreator{arg: arg}
		require.ErrorIs(t, creator.computeDNSAddresses(enable), hooks.ErrVMTypeLengthIsNotCorrect)
		require.Equal(t, 1, *registrations)
		require.Empty(t, dns.AddressesBytes())
		require.Empty(t, dns.Addresses())
	})
}

func TestQualSP281CGenesisProcessorHooksReceiveHasherBeforeVMCreation(t *testing.T) {
	enable := createGenesisConfig(config.EnableEpochs{})
	rounds := createGenesisRoundConfig(testscommon.GetDefaultRoundsConfig())

	t.Run("meta", func(t *testing.T) {
		arg, registrations := qualSP281CGenesisHookOperands(t, core.MetachainShardId)
		// Missing economics rejects factory construction before CreateForGenesis.
		processors, err := createProcessorsForMetaGenesisBlock(arg, enable, rounds)
		require.ErrorIs(t, err, nodeProcess.ErrNilEconomicsData)
		require.Nil(t, processors)
		require.Equal(t, 1, *registrations)
	})

	t.Run("shard", func(t *testing.T) {
		arg, registrations := qualSP281CGenesisHookOperands(t, 0)
		// No WASM version schedule rejects factory construction before Create.
		processors, err := createProcessorsForShardGenesisBlock(arg, enable, rounds)
		require.ErrorIs(t, err, shardFactory.ErrEmptyVersionsByEpochsList)
		require.Nil(t, processors)
		require.Equal(t, 1, *registrations)
	})
}

type qualSP281CGenesisSaveFailure struct {
	*qualStageAMetaAccounts
	err   error
	saves int
}

func (a *qualSP281CGenesisSaveFailure) SaveAccount(vmcommon.AccountHandler) error {
	a.saves++
	return a.err
}

func TestQualSP281CMetaGenesisDeniesBeforeCommit(t *testing.T) {
	m := &marshal.GogoProtoMarshalizer{}
	h := blake2b.NewBlake2b()
	limits := qualStageALimits()
	evidence, err := drwa.DecodeInitialProgrammeEvidence(qualStageARaw(t), "synthetic", "pin", limits, m, h)
	require.NoError(t, err)

	t.Run("missing_core", func(t *testing.T) {
		accounts := &stateMock.AccountsStub{}
		arg := ArgsGenesisBlockCreator{
			Accounts: accounts, drwaGenesisAccounts: accounts,
			DRWAMinimumGenesis:    &config.DRWAMinimumGenesis{},
			DRWAInitialProgrammes: []drwa.InitialProgrammeEvidence{evidence},
		}
		header, hashes, indexing, err := CreateMetaGenesisBlock(arg, nil, nil, nil)
		require.ErrorIs(t, err, nodeProcess.ErrNilCoreComponentsHolder)
		require.Nil(t, header)
		require.Nil(t, hashes)
		require.Nil(t, indexing)
	})

	t.Run("dirty_prestate", func(t *testing.T) {
		accounts := &stateMock.AccountsStub{
			JournalLenCalled: func() int { return 1 },
			RootHashCalled: func() ([]byte, error) {
				t.Fatal("dirty prestate reached the root read")
				return nil, nil
			},
		}
		arg := ArgsGenesisBlockCreator{
			Accounts: accounts, Core: &mock.CoreComponentsMock{IntMarsh: m, Hash: h},
			GenesisEpoch: 17, StartEpochNum: 17,
			DRWAInitialProgrammes:      []drwa.InitialProgrammeEvidence{evidence},
			DRWAInitialProgrammeLimits: limits,
		}
		header, hashes, indexing, err := CreateMetaGenesisBlock(arg, nil, nil, nil)
		require.ErrorIs(t, err, drwa.ErrUncommittedState)
		require.Nil(t, header)
		require.Nil(t, hashes)
		require.Nil(t, indexing)
	})

	t.Run("stage_save_fails", func(t *testing.T) {
		db := qualStageAGenesisDB(t)
		before, err := db.RootHash()
		require.NoError(t, err)
		before = bytes.Clone(before)
		saveErr := errors.New("synthetic genesis save error")
		accounts := &qualSP281CGenesisSaveFailure{
			qualStageAMetaAccounts: &qualStageAMetaAccounts{AccountsAdapter: db},
			err:                    saveErr,
		}
		arg := ArgsGenesisBlockCreator{
			Accounts: accounts, Core: &mock.CoreComponentsMock{IntMarsh: m, Hash: h},
			GenesisEpoch: 17, StartEpochNum: 17,
			DRWAInitialProgrammes:      []drwa.InitialProgrammeEvidence{evidence},
			DRWAInitialProgrammeLimits: limits,
		}
		header, hashes, indexing, err := CreateMetaGenesisBlock(arg, nil, nil, nil)
		require.ErrorIs(t, err, saveErr)
		require.Nil(t, header)
		require.Nil(t, hashes)
		require.Nil(t, indexing)
		require.Equal(t, 1, accounts.saves)
		require.Zero(t, accounts.commits)
		require.Equal(t, []int{0}, accounts.rollbacks)
		require.Zero(t, db.JournalLen())
		after, err := db.RootHash()
		require.NoError(t, err)
		require.Equal(t, before, after)
	})
}
