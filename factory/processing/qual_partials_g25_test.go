package processing

import (
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/factory"
	factoryMock "github.com/multiversx/mx-chain-go/factory/mock"
	"github.com/multiversx/mx-chain-go/process"
	drwaTime "github.com/multiversx/mx-chain-go/process/drwa/headertime"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	dataMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	"github.com/multiversx/mx-chain-go/testscommon/genesisMocks"
	"github.com/multiversx/mx-chain-go/testscommon/shardingMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	storageMock "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
	"reflect"
	"sync"
	"testing"
)

type qualG25Bootstrap struct {
	factory.BootstrapComponentsHolder
	coordinator sharding.Coordinator
}

func (b *qualG25Bootstrap) ShardCoordinator() sharding.Coordinator { return b.coordinator }

// Exercise the processing factory's real VM-factory and hook constructors with
// dependency stubs. No bootstrap/data factory, VM Create, executor or node is run.
// The inherited memory-store and VM-version configuration is an R7 fixture.
func TestQualPartialsG25FactoryDependencies(t *testing.T) {
	for _, chain := range []string{"meta", "shard"} {
		t.Run(chain, func(t *testing.T) {
			flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
			pcf := &processComponentsFactory{
				coreData: &factoryMock.CoreComponentsMock{
					Hash: blake2b.NewBlake2b(), IntMarsh: &marshal.GogoProtoMarshalizer{},
					UInt64ByteSliceConv: &processMock.Uint64ByteSliceConverterMock{}, AddrPubKeyConv: testscommon.NewPubkeyConverterMock(32),
					EpochChangeNotifier: &epochNotifier.EpochNotifierStub{}, EnableEpochsHandlerField: flags,
					RoundHandlerField: &testscommon.RoundHandlerMock{}, EconomicsHandler: &economicsmocks.EconomicsHandlerMock{},
					NodesConfig: &genesisMocks.NodesSetupStub{}, RatingHandler: &testscommon.RaterMock{}, EnableRoundsHandlerField: &testscommon.EnableRoundsHandlerStub{},
				},
				data:                &factoryMock.DataComponentsMock{Storage: &storageMock.ChainStorerStub{}, Blkc: &testscommon.ChainHandlerStub{}, DataPool: &dataMock.PoolsHolderStub{}},
				bootstrapComponents: &qualG25Bootstrap{coordinator: &testscommon.ShardsCoordinatorMock{}},
				crypto:              &factoryMock.CryptoComponentsMock{MsgSigVerifier: &processMock.MessageSignVerifierMock{}},
				nodesCoordinator:    &shardingMocks.NodesCoordinatorMock{}, systemSCConfig: &config.SystemSmartContractsConfig{},
				gasSchedule: testscommon.NewGasScheduleNotifierMock(map[string]map[string]uint64{}),
				config:      testscommon.GetGeneralConfig(), flagsConfig: config.ContextFlagsConfig{WorkingDir: t.TempDir()},
				state: &factoryMock.StateComponentsHolderStub{AccountsAdapterCalled: func() state.AccountsAdapter { return &stateMock.AccountsStub{} }, PeerAccountsCalled: func() state.AccountsAdapter { return &stateMock.AccountsStub{} }},
			}
			// Synthetic allowlist matches the fixture converter; no deployment address.
			pcf.config.VirtualMachine.Execution.TransferAndExecuteByUserAddresses = []string{"0101010101010101010101010101010101010101010101010101010101010101"}
			users, peers := &stateMock.AccountsStub{}, &stateMock.AccountsStub{}
			builtins := builtInFunctions.NewBuiltInFunctionContainer()
			nft, global := &testscommon.SimpleNFTStorageHandlerStub{}, &testscommon.ESDTGlobalSettingsHandlerStub{}
			makeFactory := func(user, peer state.AccountsAdapter) (process.VirtualMachinesContainerFactory, error) {
				if chain == "meta" {
					return pcf.createVMFactoryMeta(user, peer, builtins, pcf.config.SmartContractsStorage, nft, global, &testscommon.EpochStartTriggerStub{})
				}
				return pcf.createVMFactoryShard(user, &testscommon.MissingTrieNodesNotifierStub{}, builtins, &testscommon.ESDTTransferParserStub{}, &sync.RWMutex{}, pcf.config.SmartContractsStorage, nft, global, &testscommon.EpochStartTriggerStub{})
			}
			fac, err := makeFactory(users, peers)
			require.NoError(t, err)
			require.NotNil(t, fac)
			t.Cleanup(func() { require.NoError(t, fac.BlockChainHookImpl().Close()) })
			// Observe constructor dependency identity without creating a VM. The
			// downstream createSystemVM source trace remains separate from execution.
			if chain == "meta" {
				actual := reflect.ValueOf(fac).Elem()
				require.Equal(t, reflect.ValueOf(users).Pointer(), actual.FieldByName("userAccountsDB").Elem().Pointer())
				require.Equal(t, reflect.ValueOf(peers).Pointer(), actual.FieldByName("validatorAccountsDB").Elem().Pointer())
			}
			hook := fac.BlockChainHookImpl().(*hooks.BlockChainHookImpl)
			require.Same(t, users, hook.GetAccountsAdapter())
			_, err = hook.EvaluatedHeaderTimeContext()
			require.ErrorIs(t, err, drwaTime.ErrInactiveHeaderTime, "configured hasher reaches typed view; activation is still omitted")
			missing, err := makeFactory(nil, peers)
			require.ErrorIs(t, err, process.ErrNilAccountsAdapter)
			require.Nil(t, missing)
			if chain == "meta" {
				missing, err = makeFactory(users, nil)
				require.ErrorIs(t, err, vm.ErrNilValidatorAccountsDB)
				require.Nil(t, missing)
			} else {
				pcf.coreData.(*factoryMock.CoreComponentsMock).EnableEpochsHandlerField = nil
				missing, err = makeFactory(users, peers)
				require.ErrorIs(t, err, process.ErrNilEnableEpochsHandler)
				require.Nil(t, missing)
			}
		})
	}
}
