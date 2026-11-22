package processing

import (
	"encoding/json"
	"fmt"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	factoryCore "github.com/multiversx/mx-chain-go/factory/core"
	componentmock "github.com/multiversx/mx-chain-go/factory/mock"
	"github.com/multiversx/mx-chain-go/process"
	processmock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/multiversx/mx-chain-go/testscommon"
	poolmock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	epochs "github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	factorymock "github.com/multiversx/mx-chain-go/testscommon/factory"
	"github.com/multiversx/mx-chain-go/testscommon/mainFactoryMocks"
	statemock "github.com/multiversx/mx-chain-go/testscommon/state"
	storagemock "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestQualS1FactoryCandidateActivation(t *testing.T) {
	pcf := &processComponentsFactory{}
	absent, err := pcf.drwaHeaderTimeEnabledAt()
	require.NoError(t, err)
	require.Nil(t, absent)
	enforcement := uint32(12)
	flags := epochs.NewEnableEpochsHandlerStub()
	flags.IsFlagEnabledInEpochCalled = func(flag core.EnableEpochFlag, epoch uint32) bool { return flag == common.SupernovaFlag && epoch >= 10 }
	rounds := &testscommon.EnableRoundsHandlerStub{IsFlagEnabledInRoundCalled: func(flag common.EnableRoundFlag, round uint64) bool {
		return flag == common.SupernovaRoundFlag && round >= 22
	}}
	coreData := &factorymock.CoreComponentsHolderStub{EnableEpochsHandlerCalled: func() common.EnableEpochsHandler { return flags }, EnableRoundsHandlerCalled: func() common.EnableRoundsHandler { return rounds }}
	pcf.coreData = coreData
	pcf.drwaConfigurationCandidate, _, _ = qualS1OverlayCandidate(t, enforcement)
	predicate, err := pcf.drwaHeaderTimeEnabledAt()
	require.NoError(t, err)
	for _, tc := range []struct {
		epoch uint32
		round uint64
		want  bool
	}{{1, 440, false}, {2, 440, false}, {12, 439, false}, {12, 440, true}, {13, 441, true}} {
		require.Equal(t, tc.want, predicate(tc.epoch, tc.round))
	}
	enforcement = 99 // no retained mutable config alias
	require.True(t, predicate(12, 440))
	// Explicit zero remains a present overlay coordinate; with native
	// Supernova at epoch 2 it must now fail E05, rather than bypass admission.
	_, effective, overlay := qualS1OverlayCandidate(t, 12)
	require.NoError(t, os.WriteFile(overlay, []byte("DRWAEnforcementEnableEpoch = 0\n"), 0600))
	zeroCandidate, err := factoryCore.NewDRWAConfigurationCandidateFromOverlay(effective, overlay, factoryCore.DRWAConfigurationSupport{ProcessorV1: true, RelayedV3: true})
	require.ErrorContains(t, err, string(common.SupernovaFlag))
	require.Nil(t, zeroCandidate)
	require.NotNil(t, pcf.drwaConfigurationCandidate)
	// Preserve the inherited positive-zero case on a coherent native zero tuple.
	zeroEffective := qualS1ZeroActivationConfigs(t)
	pcf.drwaConfigurationCandidate, err = factoryCore.NewDRWAConfigurationCandidateFromOverlay(zeroEffective, overlay, factoryCore.DRWAConfigurationSupport{ProcessorV1: true, RelayedV3: true})
	require.NoError(t, err)
	predicate, err = pcf.drwaHeaderTimeEnabledAt()
	require.NoError(t, err)
	require.NotNil(t, predicate)
	require.True(t, predicate(10, 22))
	coreData.EnableEpochsHandlerCalled = func() common.EnableEpochsHandler { return nil }
	_, err = pcf.drwaHeaderTimeEnabledAt()
	require.ErrorIs(t, err, process.ErrNilEnableEpochsHandler)
	coreData.EnableEpochsHandlerCalled = func() common.EnableEpochsHandler { return flags }
	coreData.EnableRoundsHandlerCalled = func() common.EnableRoundsHandler { return nil }
	_, err = pcf.drwaHeaderTimeEnabledAt()
	require.ErrorIs(t, err, process.ErrNilEnableRoundsHandler)
}

// Actual processing factory -> shard VM factory -> actual hook; no VM engine
// is launched. Coordinates and MemoryDB are qualification fixtures only.
func TestQualS1ActualShardFactoryInstallsCandidateTime(t *testing.T) {
	for _, present := range []bool{false, true} {
		pcf := &processComponentsFactory{}
		enforcement := uint32(10)
		if present {
			pcf.drwaConfigurationCandidate, _, _ = qualS1OverlayCandidate(t, enforcement)
		}
		pcf.config.VirtualMachine.Execution.WasmVMVersions = []config.WasmVMVersionByEpoch{{StartEpoch: 0, Version: "v1.5"}}
		pcf.config.VirtualMachine.Execution.TransferAndExecuteByUserAddresses = []string{"0000000000000000000000000000000000000000000000000000000000000000"}
		pcf.flagsConfig.WorkingDir = t.TempDir()
		flags := epochs.NewEnableEpochsHandlerStub()
		flags.IsFlagEnabledInEpochCalled = func(flag core.EnableEpochFlag, epoch uint32) bool { return flag != common.SupernovaFlag || epoch >= 10 }
		rounds := &testscommon.EnableRoundsHandlerStub{IsFlagEnabledInRoundCalled: func(flag common.EnableRoundFlag, round uint64) bool {
			return flag == common.SupernovaRoundFlag && round >= 22
		}}
		pcf.coreData = &componentmock.CoreComponentsMock{
			IntMarsh: &marshal.GogoProtoMarshalizer{}, Hash: blake2b.NewBlake2b(), AddrPubKeyConv: testscommon.NewPubkeyConverterMock(32),
			UInt64ByteSliceConv:      &processmock.Uint64ByteSliceConverterMock{},
			EnableEpochsHandlerField: flags, EnableRoundsHandlerField: rounds,
			EpochChangeNotifier: &epochNotifier.EpochNotifierStub{}, RoundHandlerField: &testscommon.RoundHandlerMock{}, EconomicsHandler: &economicsmocks.EconomicsHandlerMock{},
		}
		pool := poolmock.NewPoolsHolderMock()
		t.Cleanup(func() { require.NoError(t, pool.Close()) })
		pcf.data = &qualS1DataComponents{DataComponentsHolderStub: &mainFactoryMocks.DataComponentsHolderStub{
			BlockchainCalled:     func() data.ChainHandler { return &testscommon.ChainHandlerStub{} },
			StorageServiceCalled: func() dataRetriever.StorageService { return &storagemock.ChainStorerStub{} },
			DatapoolCalled:       func() dataRetriever.PoolsHolder { return pool },
		}}
		pcf.bootstrapComponents = &mainFactoryMocks.BootstrapComponentsStub{ShCoordinator: processmock.NewOneShardCoordinatorMock()}
		pcf.gasSchedule = testscommon.NewGasScheduleNotifierMock(make(map[string]map[string]uint64))
		storage := config.StorageConfig{Cache: config.CacheConfig{Capacity: 10, Type: string(storageunit.LRUCache)}, DB: config.DBConfig{FilePath: "compiled", Type: string(storageunit.MemoryDB), MaxBatchSize: 1, MaxOpenFiles: 10}}
		vmFactory, err := pcf.createVMFactoryShard(&statemock.AccountsStub{}, &testscommon.MissingTrieNodesNotifierStub{}, builtInFunctions.NewBuiltInFunctionContainer(), &testscommon.ESDTTransferParserStub{}, &sync.RWMutex{}, storage, &testscommon.SimpleNFTStorageHandlerStub{}, &testscommon.ESDTGlobalSettingsHandlerStub{}, &testscommon.EpochStartTriggerStub{})
		require.NoError(t, err)
		hook, ok := vmFactory.BlockChainHookImpl().(*hooks.BlockChainHookImpl)
		require.True(t, ok)
		t.Cleanup(func() { require.NoError(t, hook.Close()) })
		require.NoError(t, hook.SetEpochStartHeader(&block.HeaderV3{Epoch: 10}))
		// Freeze config ownership at factory construction.
		enforcement = 99
		header := &block.HeaderV3{Epoch: 10, Round: 440, TimestampMs: 1234567}
		install, end, err := hook.BeginDRWAHeaderEvaluationForHeader(header)
		require.NoError(t, err)
		require.NoError(t, install(header))
		ctx, err := hook.EvaluatedHeaderTimeContext()
		if present {
			require.NoError(t, err)
			ms, e := ctx.Milliseconds()
			require.NoError(t, e)
			require.EqualValues(t, 1234567, ms)
		} else {
			require.Error(t, err)
			require.Nil(t, ctx)
		}
		end()
	}
}

// Adapt the existing fixture's obsolete setter signature to the current holder.
type qualS1DataComponents struct {
	*mainFactoryMocks.DataComponentsHolderStub
}

func (d *qualS1DataComponents) SetBlockchain(chain data.ChainHandler) error {
	d.DataComponentsHolderStub.SetBlockchain(chain)
	return nil
}

func TestQualS1EnforcementUsesNativeLoader(t *testing.T) {
	raw, err := os.ReadFile("../../cmd/node/config/config.toml")
	require.NoError(t, err)
	for _, value := range []string{"absent", "0", "12"} {
		candidate := raw
		if value != "absent" {
			candidate = append([]byte("DRWAEnforcementEnableEpoch = "+value+"\n"), raw...)
		}
		path := filepath.Join(t.TempDir(), "drwa.toml")
		require.NoError(t, os.WriteFile(path, candidate, 0600))
		var loaded struct {
			DRWAEnforcementEnableEpoch *uint32 `json:",omitempty"`
		}
		e := core.LoadTomlFile(&loaded, path)
		require.NoError(t, e)
		if value == "absent" {
			require.Nil(t, loaded.DRWAEnforcementEnableEpoch)
			encoded, e := json.Marshal(loaded)
			require.NoError(t, e)
			require.False(t, strings.Contains(string(encoded), "DRWAEnforcementEnableEpoch"))
		} else {
			require.NotNil(t, loaded.DRWAEnforcementEnableEpoch)
			want := uint32(0)
			if value == "12" {
				want = 12
			}
			require.Equal(t, want, *loaded.DRWAEnforcementEnableEpoch)
		}
	}
}

func qualS1EffectiveConfigs(t *testing.T) *config.Configs {
	t.Helper()
	configs := &config.Configs{}
	var err error
	configs.GeneralConfig, err = common.LoadMainConfig("../../cmd/node/config/config.toml")
	require.NoError(t, err)
	configs.EpochConfig, err = common.LoadEpochConfig("../../cmd/node/config/enableEpochs.toml")
	require.NoError(t, err)
	configs.RoundConfig, err = common.LoadRoundConfig("../../cmd/node/config/enableRounds.toml")
	require.NoError(t, err)
	configs.EconomicsConfig, err = common.LoadEconomicsConfig("../../cmd/node/config/economics.toml")
	require.NoError(t, err)
	configs.RatingsConfig, err = common.LoadRatingsConfig("../../cmd/node/config/ratings.toml")
	require.NoError(t, err)
	return configs
}
func qualS1OverlayCandidate(t *testing.T, enforcement uint32) (*factoryCore.DRWAConfigurationCandidate, *config.Configs, string) {
	t.Helper()
	configs := qualS1EffectiveConfigs(t)
	overlay := filepath.Join(t.TempDir(), "drwa.toml")
	require.NoError(t, os.WriteFile(overlay, []byte(fmt.Sprintf("DRWAEnforcementEnableEpoch = %d\n", enforcement)), 0600))
	candidate, err := factoryCore.NewDRWAConfigurationCandidateFromOverlay(configs, overlay, factoryCore.DRWAConfigurationSupport{ProcessorV1: true, RelayedV3: true})
	require.NoError(t, err)
	return candidate, configs, overlay
}

// Valid-domain explicit-zero control: the native tuple permits Supernova
// from epoch/round zero. This is a qualification snapshot, never a default.
func qualS1ZeroActivationConfigs(t *testing.T) *config.Configs {
	t.Helper()
	c := qualS1EffectiveConfigs(t)
	flags := reflect.ValueOf(&c.EpochConfig.EnableEpochs).Elem()
	for i := 0; i < flags.NumField(); i++ {
		if flags.Field(i).Kind() == reflect.Uint32 {
			flags.Field(i).SetUint(0)
		}
	}
	entry := c.RoundConfig.RoundActivations["SupernovaEnableRound"]
	entry.Round = "0"
	c.RoundConfig.RoundActivations["SupernovaEnableRound"] = entry
	g := &c.GeneralConfig.GeneralSettings
	cp := g.ChainParametersByEpoch[len(g.ChainParametersByEpoch)-1]
	cp.EnableEpoch = 0
	g.ChainParametersByEpoch = []config.ChainParametersByEpochConfig{cp}
	grace := g.EpochChangeGracePeriodByEpoch[len(g.EpochChangeGracePeriodByEpoch)-1]
	grace.EnableEpoch = 0
	g.EpochChangeGracePeriodByEpoch = []config.EpochChangeGracePeriodByEpoch{grace}
	processEpoch := g.ProcessConfigsByEpoch[len(g.ProcessConfigsByEpoch)-1]
	processEpoch.EnableEpoch = 0
	g.ProcessConfigsByEpoch = []config.ProcessConfigByEpoch{processEpoch}
	startEpoch := g.EpochStartConfigsByEpoch[len(g.EpochStartConfigsByEpoch)-1]
	startEpoch.EnableEpoch = 0
	g.EpochStartConfigsByEpoch = []config.EpochStartConfigByEpoch{startEpoch}
	consensusEpoch := g.ConsensusConfigsByEpoch[len(g.ConsensusConfigsByEpoch)-1]
	consensusEpoch.EnableEpoch = 0
	g.ConsensusConfigsByEpoch = []config.ConsensusConfigByEpoch{consensusEpoch}
	processRound := g.ProcessConfigsByRound[len(g.ProcessConfigsByRound)-1]
	processRound.EnableRound = 0
	g.ProcessConfigsByRound = []config.ProcessConfigByRound{processRound}
	startRound := g.EpochStartConfigsByRound[len(g.EpochStartConfigsByRound)-1]
	startRound.EnableRound = 0
	g.EpochStartConfigsByRound = []config.EpochStartConfigByRound{startRound}
	consensusRound := g.ConsensusConfigsByRound[len(g.ConsensusConfigsByRound)-1]
	consensusRound.EnableRound = 0
	g.ConsensusConfigsByRound = []config.ConsensusConfigByRound{consensusRound}
	antiflood := c.GeneralConfig.Antiflood.ConfigsByRound[len(c.GeneralConfig.Antiflood.ConfigsByRound)-1]
	antiflood.Round = 0
	c.GeneralConfig.Antiflood.ConfigsByRound = []config.AntifloodConfigByRound{antiflood}
	gas := c.EconomicsConfig.FeeSettings.GasLimitSettings[len(c.EconomicsConfig.FeeSettings.GasLimitSettings)-1]
	gas.EnableEpoch = 0
	c.EconomicsConfig.FeeSettings.GasLimitSettings = []config.GasLimitSetting{gas}
	shard := c.RatingsConfig.ShardChain.RatingStepsByEpoch[len(c.RatingsConfig.ShardChain.RatingStepsByEpoch)-1]
	shard.EnableEpoch = 0
	c.RatingsConfig.ShardChain.RatingStepsByEpoch = []config.RatingSteps{shard}
	meta := c.RatingsConfig.MetaChain.RatingStepsByEpoch[len(c.RatingsConfig.MetaChain.RatingStepsByEpoch)-1]
	meta.EnableEpoch = 0
	c.RatingsConfig.MetaChain.RatingStepsByEpoch = []config.RatingSteps{meta}
	var versions []config.VersionByEpochs
	for _, v := range c.GeneralConfig.Versions.VersionsByEpochs {
		if v.Version == "3" {
			v.StartEpoch = 0
			v.StartRound = 0
			versions = append(versions, v)
		}
	}
	require.Len(t, versions, 1)
	c.GeneralConfig.Versions.VersionsByEpochs = versions
	return c
}
