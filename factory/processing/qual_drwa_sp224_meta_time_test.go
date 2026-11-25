package processing

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	factoryMock "github.com/multiversx/mx-chain-go/factory/mock"
	drwaTime "github.com/multiversx/mx-chain-go/process/drwa/headertime"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/multiversx/mx-chain-go/testscommon"
	dataMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	"github.com/multiversx/mx-chain-go/testscommon/genesisMocks"
	"github.com/multiversx/mx-chain-go/testscommon/shardingMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	storageMock "github.com/multiversx/mx-chain-go/testscommon/storage"
)

// A real configuration candidate and hook, with inert constructor dependencies.
// Keep the first installer unused. Reentry refusal distinguishes a live
// evaluation owner from the ordinary fallback without acquiring a time lease.
func TestQualSP224MetaFactoryTimeIsolation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured bool
		proposal   bool
		epoch      uint32
		round      uint64
		reentryErr error
	}{
		{name: "unconfigured_proposal", proposal: true, epoch: 12, round: 440},
		{name: "configured_simulator", configured: true, epoch: 12, round: 440},
		{name: "before_enforcement_epoch", configured: true, proposal: true, epoch: 11, round: 440},
		{name: "before_supernova_round", configured: true, proposal: true, epoch: 12, round: 439},
		{name: "exact_proposal_activation", configured: true, proposal: true, epoch: 12, round: 440, reentryErr: drwaTime.ErrInactiveHeaderTime},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
			flags.IsFlagEnabledInEpochCalled = func(flag core.EnableEpochFlag, epoch uint32) bool {
				return flag != common.SupernovaFlag || epoch >= 10
			}
			pcf := &processComponentsFactory{
				coreData: &factoryMock.CoreComponentsMock{
					Hash: blake2b.NewBlake2b(), IntMarsh: &marshal.GogoProtoMarshalizer{},
					AddrPubKeyConv:           testscommon.NewPubkeyConverterMock(32),
					UInt64ByteSliceConv:      &processMock.Uint64ByteSliceConverterMock{},
					EpochChangeNotifier:      &epochNotifier.EpochNotifierStub{},
					EnableEpochsHandlerField: flags,
					EnableRoundsHandlerField: &testscommon.EnableRoundsHandlerStub{},
					RoundHandlerField:        &testscommon.RoundHandlerMock{}, EconomicsHandler: &economicsmocks.EconomicsHandlerMock{},
					NodesConfig: &genesisMocks.NodesSetupStub{}, RatingHandler: &testscommon.RaterMock{},
				},
				data: &factoryMock.DataComponentsMock{
					Storage: &storageMock.ChainStorerStub{}, Blkc: &testscommon.ChainHandlerStub{},
					DataPool: &dataMock.PoolsHolderStub{},
				},
				bootstrapComponents: &qualG25Bootstrap{coordinator: &testscommon.ShardsCoordinatorMock{CurrentShard: core.MetachainShardId}},
				crypto:              &factoryMock.CryptoComponentsMock{MsgSigVerifier: &processMock.MessageSignVerifierMock{}},
				nodesCoordinator:    &shardingMocks.NodesCoordinatorMock{}, systemSCConfig: &config.SystemSmartContractsConfig{},
				gasSchedule: testscommon.NewGasScheduleNotifierMock(map[string]map[string]uint64{}),
				flagsConfig: config.ContextFlagsConfig{WorkingDir: t.TempDir()},
			}
			if tc.configured {
				pcf.drwaConfigurationCandidate, _, _ = qualS1OverlayCandidate(t, 12)
			}

			var enabledAt func(uint32, uint64) bool
			if tc.proposal {
				var err error
				enabledAt, err = pcf.drwaHeaderTimeEnabledAt()
				require.NoError(t, err)
			}
			storage := config.StorageConfig{
				Cache: config.CacheConfig{Capacity: 10, Type: string(storageunit.LRUCache)},
				DB:    config.DBConfig{FilePath: "compiled", Type: string(storageunit.MemoryDB), MaxBatchSize: 1, MaxOpenFiles: 10},
			}
			factory, err := pcf.createVMFactoryMeta(
				&stateMock.AccountsStub{},
				&stateMock.AccountsStub{},
				vmBuiltins.NewBuiltInFunctionContainer(),
				storage,
				&testscommon.SimpleNFTStorageHandlerStub{},
				&testscommon.ESDTGlobalSettingsHandlerStub{},
				&testscommon.EpochStartTriggerStub{},
				enabledAt,
			)
			require.NoError(t, err)
			hook, ok := factory.BlockChainHookImpl().(*hooks.BlockChainHookImpl)
			require.True(t, ok)
			t.Cleanup(func() { require.NoError(t, hook.Close()) })

			header := &block.MetaBlockV3{Epoch: tc.epoch, Round: tc.round, TimestampMs: 1234567}
			require.NoError(t, hook.SetEpochStartHeader(&block.MetaBlockV3{Epoch: tc.epoch}))
			install, end, err := hook.BeginDRWAHeaderEvaluationForHeader(header)
			require.NoError(t, err)
			t.Cleanup(end)
			secondInstall, secondEnd, err := hook.BeginDRWAHeaderEvaluationForHeader(header)
			require.ErrorIs(t, err, tc.reentryErr)
			if tc.reentryErr != nil {
				require.Nil(t, secondInstall)
				require.Nil(t, secondEnd)
			} else {
				require.NotNil(t, secondInstall)
				secondEnd()
			}

			context, err := hook.EvaluatedHeaderTimeContext()
			require.ErrorIs(t, err, drwaTime.ErrInactiveHeaderTime)
			require.Nil(t, context)
			require.ErrorIs(t, install(nil), hooks.ErrNilCurrentHeader)
			end()

			require.NoError(t, hook.SetCurrentHeader(header))
			require.EqualValues(t, 1234567, hook.CurrentTimeStampMs())
			context, err = hook.EvaluatedHeaderTimeContext()
			require.ErrorIs(t, err, drwaTime.ErrInactiveHeaderTime)
			require.Nil(t, context)
		})
	}
}
