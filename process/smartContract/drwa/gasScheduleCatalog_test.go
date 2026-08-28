package drwa

import (
	"encoding/hex"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

func TestSealGasScheduleCatalogDRWADeterministicFixture(t *testing.T) {
	t.Parallel()

	profiles := drwaGasScheduleProfiles()
	catalog, err := SealGasScheduleCatalog([]GasScheduleProfile{profiles[1], profiles[0]})
	require.NoError(t, err)

	firstIdentity, err := GasScheduleIdentity(profiles[0].Schedule)
	require.NoError(t, err)
	secondIdentity, err := GasScheduleIdentity(profiles[1].Schedule)
	require.NoError(t, err)
	require.Equal(t, "24085eea60a7f13e6c4bd5ea1546a317c906e948b716a2b18a9b16bd41dcc2d8", hex.EncodeToString(firstIdentity[:]))
	require.Equal(t, "48c14b0855126aa12f486b220df3808de2461fbff306f29ba67d0e56f3475c65", hex.EncodeToString(secondIdentity[:]))
	catalogIdentity, err := catalog.Identity()
	require.NoError(t, err)
	require.Equal(t, "6ab5ca8a1e552cc48a11495de6143740bcda125576bfb82cf4a9a2550e42b073", hex.EncodeToString(catalogIdentity[:]))

	selected, err := catalog.IdentityAtEpoch(0)
	require.NoError(t, err)
	require.Equal(t, firstIdentity, selected)
	selected, err = catalog.IdentityAtEpoch(6)
	require.NoError(t, err)
	require.Equal(t, firstIdentity, selected)
	selected, err = catalog.IdentityAtEpoch(7)
	require.NoError(t, err)
	require.Equal(t, secondIdentity, selected)
	selected, err = catalog.IdentityAtEpoch(^uint32(0))
	require.NoError(t, err)
	require.Equal(t, secondIdentity, selected)
}

func TestGasScheduleCatalogDRWACanonicalizesMapOrderAndCopiesState(t *testing.T) {
	t.Parallel()

	profiles := drwaGasScheduleProfiles()
	reordered := GasScheduleMap{
		"BuiltInCost": {
			"DRWASourceCompletion": 41,
			"DRWARefundGeneration": 31,
		},
		"BaseOperationCost": {
			"DRWASuccessReceipt":  21,
			"DRWADestinationGate": 11,
		},
	}
	identity, err := GasScheduleIdentity(profiles[0].Schedule)
	require.NoError(t, err)
	reorderedIdentity, err := GasScheduleIdentity(reordered)
	require.NoError(t, err)
	require.Equal(t, identity, reorderedIdentity)

	catalog, err := SealGasScheduleCatalog(profiles)
	require.NoError(t, err)
	profiles[0].Schedule["BaseOperationCost"]["DRWADestinationGate"] = 999
	retained, err := catalog.Schedule(identity)
	require.NoError(t, err)
	require.Equal(t, uint64(11), retained["BaseOperationCost"]["DRWADestinationGate"])
	retained["BaseOperationCost"]["DRWADestinationGate"] = 888
	retainedAgain, err := catalog.Schedule(identity)
	require.NoError(t, err)
	require.Equal(t, uint64(11), retainedAgain["BaseOperationCost"]["DRWADestinationGate"])
}

func TestSealGasScheduleCatalogDRWARejectsMalformedOrAmbiguousInput(t *testing.T) {
	t.Parallel()

	valid := drwaGasScheduleProfiles()
	tests := []struct {
		name     string
		profiles []GasScheduleProfile
	}{
		{name: "empty", profiles: nil},
		{name: "first epoch not zero", profiles: []GasScheduleProfile{{StartEpoch: 1, Schedule: valid[0].Schedule}}},
		{name: "duplicate epoch", profiles: []GasScheduleProfile{{StartEpoch: 0, Schedule: valid[0].Schedule}, {StartEpoch: 0, Schedule: valid[1].Schedule}}},
		{name: "empty schedule", profiles: []GasScheduleProfile{{StartEpoch: 0, Schedule: GasScheduleMap{}}}},
		{name: "empty section", profiles: []GasScheduleProfile{{StartEpoch: 0, Schedule: GasScheduleMap{"": {"operation": 1}}}}},
		{name: "empty section body", profiles: []GasScheduleProfile{{StartEpoch: 0, Schedule: GasScheduleMap{"section": {}}}}},
		{name: "empty operation", profiles: []GasScheduleProfile{{StartEpoch: 0, Schedule: GasScheduleMap{"section": {"": 1}}}}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			catalog, err := SealGasScheduleCatalog(test.profiles)
			require.Nil(t, catalog)
			require.ErrorIs(t, err, ErrInvalidGasScheduleCatalog)
		})
	}
}

func TestGasScheduleCatalogDRWARejectsUnknownAndNilAccess(t *testing.T) {
	t.Parallel()

	var nilCatalog *GasScheduleCatalog
	_, err := nilCatalog.Identity()
	require.ErrorIs(t, err, ErrInvalidGasScheduleCatalog)
	_, err = nilCatalog.IdentityAtEpoch(0)
	require.ErrorIs(t, err, ErrInvalidGasScheduleCatalog)
	_, err = nilCatalog.Schedule([drwaDigestLength]byte{})
	require.ErrorIs(t, err, ErrInvalidGasScheduleCatalog)

	catalog, err := SealGasScheduleCatalog(drwaGasScheduleProfiles())
	require.NoError(t, err)
	_, err = catalog.Schedule(sequentialDRWADigest(1))
	require.ErrorIs(t, err, ErrGasScheduleNotFound)
}

func TestGasScheduleCatalogMaximumWorkBudgetsUsesWholeCatalogComponentwiseMaximum(t *testing.T) {
	t.Parallel()

	profiles := drwaWorkBudgetProfiles()
	catalog, err := SealGasScheduleCatalog([]GasScheduleProfile{profiles[1], profiles[0]})
	require.NoError(t, err)

	budgets, err := catalog.MaximumWorkBudgets()
	require.NoError(t, err)
	require.Equal(t, WorkBudgets{
		DestinationGate:  110,
		SuccessReceipt:   220,
		RefundGeneration: 330,
		SourceCompletion: 440,
	}, budgets)
	total, err := budgets.Total()
	require.NoError(t, err)
	require.Equal(t, uint64(1100), total)
}

func TestGasScheduleCatalogMaximumWorkBudgetsRejectsMissingZeroAndOverflow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(schedule GasScheduleMap)
	}{
		{
			name: "missing section",
			mutate: func(schedule GasScheduleMap) {
				delete(schedule, DRWAWorkBudgetSection)
			},
		},
		{
			name: "missing destination gate",
			mutate: func(schedule GasScheduleMap) {
				delete(schedule[DRWAWorkBudgetSection], DRWADestinationGateCost)
			},
		},
		{
			name: "zero success receipt",
			mutate: func(schedule GasScheduleMap) {
				schedule[DRWAWorkBudgetSection][DRWASuccessReceiptCost] = 0
			},
		},
		{
			name: "missing refund generation",
			mutate: func(schedule GasScheduleMap) {
				delete(schedule[DRWAWorkBudgetSection], DRWARefundGenerationCost)
			},
		},
		{
			name: "zero source completion",
			mutate: func(schedule GasScheduleMap) {
				schedule[DRWAWorkBudgetSection][DRWASourceCompletionCost] = 0
			},
		},
		{
			name: "total overflow",
			mutate: func(schedule GasScheduleMap) {
				schedule[DRWAWorkBudgetSection][DRWADestinationGateCost] = math.MaxUint64
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			profiles := drwaWorkBudgetProfiles()
			test.mutate(profiles[1].Schedule)
			catalog, err := SealGasScheduleCatalog(profiles)
			require.NoError(t, err)
			_, err = catalog.MaximumWorkBudgets()
			require.ErrorIs(t, err, ErrInvalidGasScheduleWorkBudget)
		})
	}

	var nilCatalog *GasScheduleCatalog
	_, err := nilCatalog.MaximumWorkBudgets()
	require.ErrorIs(t, err, ErrInvalidGasScheduleWorkBudget)
}

func TestWorkBudgetsTotalRejectsEveryZeroComponent(t *testing.T) {
	t.Parallel()

	valid := WorkBudgets{
		DestinationGate:  1,
		SuccessReceipt:   2,
		RefundGeneration: 3,
		SourceCompletion: 4,
	}
	tests := []struct {
		name   string
		mutate func(budgets *WorkBudgets)
	}{
		{name: "destination gate", mutate: func(budgets *WorkBudgets) { budgets.DestinationGate = 0 }},
		{name: "success receipt", mutate: func(budgets *WorkBudgets) { budgets.SuccessReceipt = 0 }},
		{name: "refund generation", mutate: func(budgets *WorkBudgets) { budgets.RefundGeneration = 0 }},
		{name: "source completion", mutate: func(budgets *WorkBudgets) { budgets.SourceCompletion = 0 }},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			budgets := valid
			test.mutate(&budgets)
			_, err := budgets.Total()
			require.ErrorIs(t, err, ErrInvalidGasScheduleWorkBudget)
		})
	}
}

func drwaGasScheduleProfiles() []GasScheduleProfile {
	return []GasScheduleProfile{
		{
			StartEpoch: 0,
			Schedule: GasScheduleMap{
				"BaseOperationCost": {
					"DRWADestinationGate": 11,
					"DRWASuccessReceipt":  21,
				},
				"BuiltInCost": {
					"DRWARefundGeneration": 31,
					"DRWASourceCompletion": 41,
				},
			},
		},
		{
			StartEpoch: 7,
			Schedule: GasScheduleMap{
				"BaseOperationCost": {
					"DRWADestinationGate": 12,
					"DRWASuccessReceipt":  22,
				},
				"BuiltInCost": {
					"DRWARefundGeneration": 32,
					"DRWASourceCompletion": 42,
				},
			},
		},
	}
}

func drwaWorkBudgetProfiles() []GasScheduleProfile {
	return []GasScheduleProfile{
		{
			StartEpoch: 0,
			Schedule: GasScheduleMap{
				"BaseOperationCost": {"StorePerByte": 10},
				DRWAWorkBudgetSection: {
					DRWADestinationGateCost:  100,
					DRWASuccessReceiptCost:   220,
					DRWARefundGenerationCost: 300,
					DRWASourceCompletionCost: 440,
				},
			},
		},
		{
			StartEpoch: 7,
			Schedule: GasScheduleMap{
				"BaseOperationCost": {"StorePerByte": 11},
				DRWAWorkBudgetSection: {
					DRWADestinationGateCost:  110,
					DRWASuccessReceiptCost:   210,
					DRWARefundGenerationCost: 330,
					DRWASourceCompletionCost: 410,
				},
			},
		},
	}
}
