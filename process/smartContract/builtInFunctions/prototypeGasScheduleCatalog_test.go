package builtInFunctions

import (
	"math"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/testscommon"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

type prototypeConfiguredGasScheduleStub struct {
	*testscommon.GasScheduleNotifierMock
	versions []common.PrototypeDRWAGasScheduleVersion
}

func TestCreateBuiltInFunctionsFactorySealsConcreteNotifierCatalog(t *testing.T) {
	t.Parallel()

	notifier, err := forking.NewGasScheduleNotifier(forking.ArgsNewGasScheduleNotifier{
		GasScheduleConfig: config.GasScheduleConfig{
			GasScheduleByEpochs: []config.GasScheduleByEpochs{
				{StartEpoch: 0, FileName: "gasScheduleV1.toml"},
				{StartEpoch: 2, FileName: "gasScheduleV2.toml"},
			},
		},
		ConfigDir:          "../../../cmd/node/config/gasSchedules",
		EpochNotifier:      forking.NewGenericEpochNotifier(),
		WasmVMChangeLocker: &sync.RWMutex{},
	})
	require.NoError(t, err)
	args := createMockArguments()
	args.GasSchedule = notifier

	builtInFactory, err := CreateBuiltInFunctionsFactory(args)
	require.NoError(t, err)
	prototypeFactory, ok := builtInFactory.(*prototypeGuardedBuiltInFunctionFactory)
	require.True(t, ok)
	_, err = prototypeFactory.PrototypeGasScheduleCatalogIdentity()
	require.NoError(t, err)
	currentIdentity, err := prototypeFactory.PrototypeCurrentGasScheduleIdentity()
	require.NoError(t, err)
	expectedCurrentIdentity, err := drwaprototype.GasScheduleIdentity(notifier.LatestGasScheduleCopy())
	require.NoError(t, err)
	require.Equal(t, expectedCurrentIdentity, currentIdentity)
	_, _, _, err = prototypeFactory.PrototypeCurrentWorkBudgets()
	require.ErrorIs(t, err, ErrPrototypeGasScheduleUnavailable)
	require.ErrorIs(t, err, drwaprototype.ErrInvalidGasScheduleWorkBudget)
}

func (stub *prototypeConfiguredGasScheduleStub) PrototypeDRWAVersionedGasSchedules() []common.PrototypeDRWAGasScheduleVersion {
	return stub.versions
}

func TestCreateBuiltInFunctionsFactorySealsConfiguredGasCatalog(t *testing.T) {
	t.Parallel()

	args := createMockArguments()
	first := args.GasSchedule.LatestGasSchedule()
	second := fillGasMapInternal(make(map[string]map[string]uint64), 2)
	notifier := &prototypeConfiguredGasScheduleStub{
		GasScheduleNotifierMock: testscommon.NewGasScheduleNotifierMock(first),
		versions: []common.PrototypeDRWAGasScheduleVersion{
			{StartEpoch: 7, Schedule: second},
			{StartEpoch: 0, Schedule: first},
		},
	}
	args.GasSchedule = notifier

	builtInFactory, err := CreateBuiltInFunctionsFactory(args)
	require.NoError(t, err)
	prototypeFactory, ok := builtInFactory.(*prototypeGuardedBuiltInFunctionFactory)
	require.True(t, ok)

	expectedCatalog, err := drwaprototype.SealGasScheduleCatalog([]drwaprototype.GasScheduleProfile{
		{StartEpoch: 0, Schedule: first},
		{StartEpoch: 7, Schedule: second},
	})
	require.NoError(t, err)
	expectedCatalogIdentity, err := expectedCatalog.Identity()
	require.NoError(t, err)
	actualCatalogIdentity, err := prototypeFactory.PrototypeGasScheduleCatalogIdentity()
	require.NoError(t, err)
	require.Equal(t, expectedCatalogIdentity, actualCatalogIdentity)

	expectedCurrentIdentity, err := drwaprototype.GasScheduleIdentity(first)
	require.NoError(t, err)
	actualCurrentIdentity, err := prototypeFactory.PrototypeCurrentGasScheduleIdentity()
	require.NoError(t, err)
	require.Equal(t, expectedCurrentIdentity, actualCurrentIdentity)

	notifier.versions[1].Schedule[common.BaseOperationCost]["StorePerByte"] = 999
	actualCatalogIdentity, err = prototypeFactory.PrototypeGasScheduleCatalogIdentity()
	require.NoError(t, err)
	require.Equal(t, expectedCatalogIdentity, actualCatalogIdentity)

	notifier.GasSchedule = map[string]map[string]uint64{"section": {"operation": 33}}
	_, err = prototypeFactory.PrototypeCurrentGasScheduleIdentity()
	require.ErrorIs(t, err, ErrPrototypeGasScheduleUnavailable)
}

func TestPrototypeCurrentGasScheduleIdentityRejectsCurrentMapNotRetained(t *testing.T) {
	t.Parallel()

	configured := fillGasMapInternal(make(map[string]map[string]uint64), 1)
	notifier := &prototypeConfiguredGasScheduleStub{
		GasScheduleNotifierMock: testscommon.NewGasScheduleNotifierMock(configured),
		versions: []common.PrototypeDRWAGasScheduleVersion{
			{StartEpoch: 0, Schedule: configured},
		},
	}
	catalog, err := sealPrototypeConfiguredGasScheduleCatalog(notifier)
	require.NoError(t, err)

	notifier.GasSchedule = fillGasMapInternal(make(map[string]map[string]uint64), 2)
	_, err = currentPrototypeGasScheduleIdentity(notifier, catalog)
	require.ErrorIs(t, err, ErrPrototypeGasScheduleUnavailable)
	require.ErrorIs(t, err, drwaprototype.ErrGasScheduleNotFound)
}

func TestPrototypeCurrentWorkBudgetsUsesRetainedIdentityAndWholeCatalogMaximum(t *testing.T) {
	t.Parallel()

	first := fillGasMapInternal(make(map[string]map[string]uint64), 1)
	first[drwaprototype.PrototypeWorkBudgetSection] = prototypeBudgetSection(100, 220, 300, 440)
	second := fillGasMapInternal(make(map[string]map[string]uint64), 2)
	second[drwaprototype.PrototypeWorkBudgetSection] = prototypeBudgetSection(110, 210, 330, 410)
	notifier := &prototypeConfiguredGasScheduleStub{
		GasScheduleNotifierMock: testscommon.NewGasScheduleNotifierMock(first),
		versions: []common.PrototypeDRWAGasScheduleVersion{
			{StartEpoch: 7, Schedule: second},
			{StartEpoch: 0, Schedule: first},
		},
	}
	catalog, err := sealPrototypeConfiguredGasScheduleCatalog(notifier)
	require.NoError(t, err)

	identity, budgets, total, err := currentPrototypeWorkBudgets(notifier, catalog)
	require.NoError(t, err)
	expectedIdentity, err := drwaprototype.GasScheduleIdentity(first)
	require.NoError(t, err)
	require.Equal(t, expectedIdentity, identity)
	require.Equal(t, drwaprototype.WorkBudgets{
		DestinationGate:  110,
		SuccessReceipt:   220,
		RefundGeneration: 330,
		SourceCompletion: 440,
	}, budgets)
	require.Equal(t, uint64(1100), total)
}

func TestPrototypeCurrentWorkBudgetsRejectsUnavailableConfiguredCosts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(schedule map[string]map[string]uint64)
	}{
		{
			name: "profile missing section",
			mutate: func(schedule map[string]map[string]uint64) {
				delete(schedule, drwaprototype.PrototypeWorkBudgetSection)
			},
		},
		{
			name: "profile zero component",
			mutate: func(schedule map[string]map[string]uint64) {
				schedule[drwaprototype.PrototypeWorkBudgetSection][drwaprototype.PrototypeRefundGenerationCost] = 0
			},
		},
		{
			name: "profile total overflow",
			mutate: func(schedule map[string]map[string]uint64) {
				schedule[drwaprototype.PrototypeWorkBudgetSection][drwaprototype.PrototypeDestinationGateCost] = math.MaxUint64
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			first := fillGasMapInternal(make(map[string]map[string]uint64), 1)
			first[drwaprototype.PrototypeWorkBudgetSection] = prototypeBudgetSection(100, 200, 300, 400)
			second := fillGasMapInternal(make(map[string]map[string]uint64), 2)
			second[drwaprototype.PrototypeWorkBudgetSection] = prototypeBudgetSection(110, 210, 310, 410)
			test.mutate(second)
			notifier := &prototypeConfiguredGasScheduleStub{
				GasScheduleNotifierMock: testscommon.NewGasScheduleNotifierMock(first),
				versions: []common.PrototypeDRWAGasScheduleVersion{
					{StartEpoch: 0, Schedule: first},
					{StartEpoch: 7, Schedule: second},
				},
			}
			catalog, err := sealPrototypeConfiguredGasScheduleCatalog(notifier)
			require.NoError(t, err)

			_, _, _, err = currentPrototypeWorkBudgets(notifier, catalog)
			require.ErrorIs(t, err, ErrPrototypeGasScheduleUnavailable)
			require.ErrorIs(t, err, drwaprototype.ErrInvalidGasScheduleWorkBudget)
		})
	}
}

func TestCreateBuiltInFunctionsFactoryRejectsInvalidConfiguredGasCatalog(t *testing.T) {
	t.Parallel()

	args := createMockArguments()
	schedule := args.GasSchedule.LatestGasSchedule()
	notifier := &prototypeConfiguredGasScheduleStub{
		GasScheduleNotifierMock: testscommon.NewGasScheduleNotifierMock(schedule),
		versions: []common.PrototypeDRWAGasScheduleVersion{
			{StartEpoch: 1, Schedule: schedule},
		},
	}
	args.GasSchedule = notifier

	builtInFactory, err := CreateBuiltInFunctionsFactory(args)
	require.Nil(t, builtInFactory)
	require.ErrorIs(t, err, ErrPrototypeGasScheduleUnavailable)
	require.ErrorIs(t, err, drwaprototype.ErrInvalidGasScheduleCatalog)
}

func prototypeBudgetSection(destination, success, refund, completion uint64) map[string]uint64 {
	return map[string]uint64{
		drwaprototype.PrototypeDestinationGateCost:  destination,
		drwaprototype.PrototypeSuccessReceiptCost:   success,
		drwaprototype.PrototypeRefundGenerationCost: refund,
		drwaprototype.PrototypeSourceCompletionCost: completion,
	}
}
