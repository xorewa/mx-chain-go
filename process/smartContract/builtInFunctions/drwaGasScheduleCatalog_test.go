package builtInFunctions

import (
	"math"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
	"github.com/multiversx/mx-chain-go/testscommon"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

type drwaConfiguredGasScheduleStub struct {
	*testscommon.GasScheduleNotifierMock
	versions []common.DRWAGasScheduleVersion
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
	drwaFactory, ok := builtInFactory.(*drwaGuardedBuiltInFunctionFactory)
	require.True(t, ok)
	_, err = drwaFactory.DRWAGasScheduleCatalogIdentity()
	require.NoError(t, err)
	currentIdentity, err := drwaFactory.DRWACurrentGasScheduleIdentity()
	require.NoError(t, err)
	expectedCurrentIdentity, err := drwa.GasScheduleIdentity(notifier.LatestGasScheduleCopy())
	require.NoError(t, err)
	require.Equal(t, expectedCurrentIdentity, currentIdentity)
	_, _, _, err = drwaFactory.DRWACurrentWorkBudgets()
	require.ErrorIs(t, err, ErrDRWAGasScheduleUnavailable)
	require.ErrorIs(t, err, drwa.ErrInvalidGasScheduleWorkBudget)
}

func (stub *drwaConfiguredGasScheduleStub) DRWAVersionedGasSchedules() []common.DRWAGasScheduleVersion {
	return stub.versions
}

func TestCreateBuiltInFunctionsFactorySealsConfiguredGasCatalog(t *testing.T) {
	t.Parallel()

	args := createMockArguments()
	first := args.GasSchedule.LatestGasSchedule()
	second := fillGasMapInternal(make(map[string]map[string]uint64), 2)
	notifier := &drwaConfiguredGasScheduleStub{
		GasScheduleNotifierMock: testscommon.NewGasScheduleNotifierMock(first),
		versions: []common.DRWAGasScheduleVersion{
			{StartEpoch: 7, Schedule: second},
			{StartEpoch: 0, Schedule: first},
		},
	}
	args.GasSchedule = notifier

	builtInFactory, err := CreateBuiltInFunctionsFactory(args)
	require.NoError(t, err)
	drwaFactory, ok := builtInFactory.(*drwaGuardedBuiltInFunctionFactory)
	require.True(t, ok)

	expectedCatalog, err := drwa.SealGasScheduleCatalog([]drwa.GasScheduleProfile{
		{StartEpoch: 0, Schedule: first},
		{StartEpoch: 7, Schedule: second},
	})
	require.NoError(t, err)
	expectedCatalogIdentity, err := expectedCatalog.Identity()
	require.NoError(t, err)
	actualCatalogIdentity, err := drwaFactory.DRWAGasScheduleCatalogIdentity()
	require.NoError(t, err)
	require.Equal(t, expectedCatalogIdentity, actualCatalogIdentity)

	expectedCurrentIdentity, err := drwa.GasScheduleIdentity(first)
	require.NoError(t, err)
	actualCurrentIdentity, err := drwaFactory.DRWACurrentGasScheduleIdentity()
	require.NoError(t, err)
	require.Equal(t, expectedCurrentIdentity, actualCurrentIdentity)

	notifier.versions[1].Schedule[common.BaseOperationCost]["StorePerByte"] = 999
	actualCatalogIdentity, err = drwaFactory.DRWAGasScheduleCatalogIdentity()
	require.NoError(t, err)
	require.Equal(t, expectedCatalogIdentity, actualCatalogIdentity)

	notifier.GasSchedule = map[string]map[string]uint64{"section": {"operation": 33}}
	_, err = drwaFactory.DRWACurrentGasScheduleIdentity()
	require.ErrorIs(t, err, ErrDRWAGasScheduleUnavailable)
}

func TestDRWACurrentGasScheduleIdentityRejectsCurrentMapNotRetained(t *testing.T) {
	t.Parallel()

	configured := fillGasMapInternal(make(map[string]map[string]uint64), 1)
	notifier := &drwaConfiguredGasScheduleStub{
		GasScheduleNotifierMock: testscommon.NewGasScheduleNotifierMock(configured),
		versions: []common.DRWAGasScheduleVersion{
			{StartEpoch: 0, Schedule: configured},
		},
	}
	catalog, err := sealDRWAConfiguredGasScheduleCatalog(notifier)
	require.NoError(t, err)

	notifier.GasSchedule = fillGasMapInternal(make(map[string]map[string]uint64), 2)
	_, err = currentDRWAGasScheduleIdentity(notifier, catalog)
	require.ErrorIs(t, err, ErrDRWAGasScheduleUnavailable)
	require.ErrorIs(t, err, drwa.ErrGasScheduleNotFound)
}

func TestDRWACurrentWorkBudgetsUsesRetainedIdentityAndWholeCatalogMaximum(t *testing.T) {
	t.Parallel()

	first := fillGasMapInternal(make(map[string]map[string]uint64), 1)
	first[drwa.DRWAWorkBudgetSection] = drwaBudgetSection(100, 220, 300, 440)
	second := fillGasMapInternal(make(map[string]map[string]uint64), 2)
	second[drwa.DRWAWorkBudgetSection] = drwaBudgetSection(110, 210, 330, 410)
	notifier := &drwaConfiguredGasScheduleStub{
		GasScheduleNotifierMock: testscommon.NewGasScheduleNotifierMock(first),
		versions: []common.DRWAGasScheduleVersion{
			{StartEpoch: 7, Schedule: second},
			{StartEpoch: 0, Schedule: first},
		},
	}
	catalog, err := sealDRWAConfiguredGasScheduleCatalog(notifier)
	require.NoError(t, err)

	identity, budgets, total, err := currentDRWAWorkBudgets(notifier, catalog)
	require.NoError(t, err)
	expectedIdentity, err := drwa.GasScheduleIdentity(first)
	require.NoError(t, err)
	require.Equal(t, expectedIdentity, identity)
	require.Equal(t, drwa.WorkBudgets{
		DestinationGate:  110,
		SuccessReceipt:   220,
		RefundGeneration: 330,
		SourceCompletion: 440,
	}, budgets)
	require.Equal(t, uint64(1100), total)
}

func TestDRWARetainedWorkBudgetsAcceptsOldExactIdentityAndRejectsUnknown(t *testing.T) {
	t.Parallel()

	first := fillGasMapInternal(make(map[string]map[string]uint64), 1)
	first[drwa.DRWAWorkBudgetSection] = drwaBudgetSection(100, 220, 300, 440)
	second := fillGasMapInternal(make(map[string]map[string]uint64), 2)
	second[drwa.DRWAWorkBudgetSection] = drwaBudgetSection(110, 210, 330, 410)
	catalog, err := drwa.SealGasScheduleCatalog([]drwa.GasScheduleProfile{
		{StartEpoch: 0, Schedule: first},
		{StartEpoch: 7, Schedule: second},
	})
	require.NoError(t, err)

	oldIdentity, err := drwa.GasScheduleIdentity(first)
	require.NoError(t, err)
	budgets, total, err := retainedDRWAWorkBudgets(oldIdentity, catalog)
	require.NoError(t, err)
	require.Equal(t, drwa.WorkBudgets{
		DestinationGate:  110,
		SuccessReceipt:   220,
		RefundGeneration: 330,
		SourceCompletion: 440,
	}, budgets)
	require.Equal(t, uint64(1100), total)

	_, _, err = retainedDRWAWorkBudgets([32]byte{0xff}, catalog)
	require.ErrorIs(t, err, ErrDRWAGasScheduleUnavailable)
	require.ErrorIs(t, err, drwa.ErrGasScheduleNotFound)

	_, _, err = retainedDRWAWorkBudgets(oldIdentity, nil)
	require.ErrorIs(t, err, ErrDRWAGasScheduleUnavailable)

	missingCosts := fillGasMapInternal(make(map[string]map[string]uint64), 3)
	invalidCatalog, err := drwa.SealGasScheduleCatalog([]drwa.GasScheduleProfile{{
		StartEpoch: 0,
		Schedule:   missingCosts,
	}})
	require.NoError(t, err)
	invalidIdentity, err := drwa.GasScheduleIdentity(missingCosts)
	require.NoError(t, err)
	_, _, err = retainedDRWAWorkBudgets(invalidIdentity, invalidCatalog)
	require.ErrorIs(t, err, ErrDRWAGasScheduleUnavailable)
	require.ErrorIs(t, err, drwa.ErrInvalidGasScheduleWorkBudget)
}

func TestDRWACurrentWorkBudgetsRejectsUnavailableConfiguredCosts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(schedule map[string]map[string]uint64)
	}{
		{
			name: "profile missing section",
			mutate: func(schedule map[string]map[string]uint64) {
				delete(schedule, drwa.DRWAWorkBudgetSection)
			},
		},
		{
			name: "profile zero component",
			mutate: func(schedule map[string]map[string]uint64) {
				schedule[drwa.DRWAWorkBudgetSection][drwa.DRWARefundGenerationCost] = 0
			},
		},
		{
			name: "profile total overflow",
			mutate: func(schedule map[string]map[string]uint64) {
				schedule[drwa.DRWAWorkBudgetSection][drwa.DRWADestinationGateCost] = math.MaxUint64
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			first := fillGasMapInternal(make(map[string]map[string]uint64), 1)
			first[drwa.DRWAWorkBudgetSection] = drwaBudgetSection(100, 200, 300, 400)
			second := fillGasMapInternal(make(map[string]map[string]uint64), 2)
			second[drwa.DRWAWorkBudgetSection] = drwaBudgetSection(110, 210, 310, 410)
			test.mutate(second)
			notifier := &drwaConfiguredGasScheduleStub{
				GasScheduleNotifierMock: testscommon.NewGasScheduleNotifierMock(first),
				versions: []common.DRWAGasScheduleVersion{
					{StartEpoch: 0, Schedule: first},
					{StartEpoch: 7, Schedule: second},
				},
			}
			catalog, err := sealDRWAConfiguredGasScheduleCatalog(notifier)
			require.NoError(t, err)

			_, _, _, err = currentDRWAWorkBudgets(notifier, catalog)
			require.ErrorIs(t, err, ErrDRWAGasScheduleUnavailable)
			require.ErrorIs(t, err, drwa.ErrInvalidGasScheduleWorkBudget)
		})
	}
}

func TestCreateBuiltInFunctionsFactoryRejectsInvalidConfiguredGasCatalog(t *testing.T) {
	t.Parallel()

	args := createMockArguments()
	schedule := args.GasSchedule.LatestGasSchedule()
	notifier := &drwaConfiguredGasScheduleStub{
		GasScheduleNotifierMock: testscommon.NewGasScheduleNotifierMock(schedule),
		versions: []common.DRWAGasScheduleVersion{
			{StartEpoch: 1, Schedule: schedule},
		},
	}
	args.GasSchedule = notifier

	builtInFactory, err := CreateBuiltInFunctionsFactory(args)
	require.Nil(t, builtInFactory)
	require.ErrorIs(t, err, ErrDRWAGasScheduleUnavailable)
	require.ErrorIs(t, err, drwa.ErrInvalidGasScheduleCatalog)
}

func drwaBudgetSection(destination, success, refund, completion uint64) map[string]uint64 {
	return map[string]uint64{
		drwa.DRWADestinationGateCost:  destination,
		drwa.DRWASuccessReceiptCost:   success,
		drwa.DRWARefundGenerationCost: refund,
		drwa.DRWASourceCompletionCost: completion,
	}
}
