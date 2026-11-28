package drwa

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

func TestQualSP248ClassifiedAccountingProjection(t *testing.T) {
	// Independent expected rows: direction derives from the declared operation
	// class and named native primitive, not a signature, role or runtime grant.
	rows := []struct {
		operation string
		class     supplyAccountingClass
		issued    int64
		live      int64
	}{
		{core.BuiltInFunctionESDTLocalMint, supplyOrdinaryIncrease, 44, 34},
		{core.BuiltInFunctionESDTNFTCreate, supplyOrdinaryIncrease, 44, 34},
		{core.BuiltInFunctionESDTNFTAddQuantity, supplyOrdinaryIncrease, 44, 34},
		{core.BuiltInFunctionESDTLocalBurn, supplyOrdinaryDecrease, 40, 26},
		{core.BuiltInFunctionESDTNFTBurn, supplyOrdinaryDecrease, 40, 26},
		{core.BuiltInFunctionESDTLocalBurn, supplyTerminalDecrease, 40, 26},
		{core.BuiltInFunctionESDTNFTBurn, supplyTerminalDecrease, 40, 26},
	}
	start := &supplyAccounting{big.NewInt(40), big.NewInt(30), 3}
	quantity := big.NewInt(4)
	cap := big.NewInt(100)
	for _, row := range rows {
		next, err := start.projectClassified(row.class, row.operation, 3, quantity, cap, 8)
		require.NoError(t, err)
		require.Equal(t, row.issued, next.cumulativeIssued.Int64())
		require.Equal(t, row.live, next.liveSupply.Int64())
		require.Equal(t, uint64(4), next.nextSupplyNonce)
		// Results do not alias the independently observed prior state.
		next.liveSupply.SetInt64(0)
		next.cumulativeIssued.SetInt64(0)
		require.Equal(t, int64(30), start.liveSupply.Int64())
		require.Equal(t, int64(40), start.cumulativeIssued.Int64())
		require.Equal(t, uint64(3), start.nextSupplyNonce)
	}
	// Direct table mismatch and absent classification are ordinary pure-model
	// validation, not native submission or transaction qualification.
	for _, tc := range []struct {
		class supplyAccountingClass
		fn    string
	}{
		{0, core.BuiltInFunctionESDTLocalMint},
		{supplyOrdinaryDecrease, core.BuiltInFunctionESDTLocalMint},
		{supplyOrdinaryIncrease, core.BuiltInFunctionESDTLocalBurn},
		{supplyTerminalDecrease, core.BuiltInFunctionESDTNFTAddQuantity},
		{supplyOrdinaryIncrease, "unselected"},
	} {
		next, err := start.projectClassified(tc.class, tc.fn, 3, quantity, cap, 8)
		require.ErrorIs(t, err, errSupplyAccounting)
		require.Nil(t, next)
	}
	next, err := start.projectClassified(supplyOrdinaryIncrease, core.BuiltInFunctionESDTLocalMint, 3, quantity, big.NewInt(41), 8)
	require.ErrorIs(t, err, errSupplyAccounting)
	require.Nil(t, next)
	require.Equal(t, int64(4), quantity.Int64())
	require.Equal(t, int64(100), cap.Int64())
}

func TestQualSP248OrdinaryFactorTableStructure(t *testing.T) {
	// These are structural fixtures for every in-memory factor-table partition,
	// not adopted CEB masks. Independent expectation: a complete partition with
	// current D1 selected may be evaluated, and all required factors must pass.
	roster := []supplyFactor{supplyFactorB3, supplyFactorC1, supplyFactorC2, supplyFactorC3, supplyFactorC4, supplyFactorD1, supplyFactorE1}
	for flags := 0; flags < 1<<len(roster); flags++ {
		var yes, no supplyFactor
		containsClearance := false
		for i, bit := range roster {
			if flags&(1<<i) == 0 {
				no |= bit
				continue
			}
			yes |= bit
			if i == 5 {
				containsClearance = true
			}
		}
		for _, class := range []supplyAccountingClass{supplyOrdinaryIncrease, supplyOrdinaryDecrease} {
			table := ordinarySupplyFactorTable{yes, no}
			err := checkOrdinarySupplyFactors(class, table, yes)
			if containsClearance {
				require.NoError(t, err)
				for _, bit := range roster {
					if yes&bit != 0 {
						require.ErrorIs(t, checkOrdinarySupplyFactors(class, table, yes&^bit), errSupplyAccounting)
					}
				}
			} else {
				require.ErrorIs(t, err, errSupplyAccounting)
			}
		}
	}
	for _, table := range []ordinarySupplyFactorTable{
		{supplyFactorD1, 0},
		{supplyFactorD1, supplyAllFactors},
		{supplyFactorD1 | 128, supplyAllFactors &^ supplyFactorD1},
	} {
		require.ErrorIs(t, checkOrdinarySupplyFactors(supplyOrdinaryDecrease, table, table.required), errSupplyAccounting)
	}
	var ordinary = ordinarySupplyFactorTable{supplyFactorD1, supplyAllFactors &^ supplyFactorD1}
	require.ErrorIs(t, checkOrdinarySupplyFactors(supplyTerminalDecrease, ordinary, ordinary.required), errSupplyAccounting)
	require.ErrorIs(t, checkOrdinarySupplyFactors(0, ordinary, ordinary.required), errSupplyAccounting)
}

func TestQualSP248IndependentOrdinaryDisposalObservation(t *testing.T) {
	// Synthetic policies have separately scoped destruction restrictions. A
	// positive observation accompanies only the explicitly applicable row;
	// unavailability preserves the refusal. No forward-transfer scope tested.
	rows := []struct {
		policy      ordinaryDisposalPolicy
		observation ordinaryDisposalObservation
		clear       bool
	}{
		{disposalApplies, disposalObservedClear, true},
		{disposalApplies, disposalObservedRestricted, false},
		{disposalApplies, 0, false},
		{disposalApplies, disposalExplicitlyNotApplicable, false},
		{disposalDoesNotApply, disposalExplicitlyNotApplicable, true},
		{disposalDoesNotApply, disposalObservedClear, false},
		{disposalDoesNotApply, 0, false},
		{0, disposalExplicitlyNotApplicable, false},
	}
	for _, row := range rows {
		err := checkOrdinaryBurnDisposal(supplyOrdinaryDecrease, row.policy, row.observation)
		if row.clear {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, errSupplyAccounting)
		}
	}
	require.ErrorIs(t, checkOrdinaryBurnDisposal(supplyOrdinaryIncrease, disposalApplies, disposalObservedClear), errSupplyAccounting)
	require.ErrorIs(t, checkOrdinaryBurnDisposal(supplyTerminalDecrease, disposalApplies, disposalObservedClear), errSupplyAccounting)
}

func TestQualSP248OpenRedemptionQuantityExposure(t *testing.T) {
	// Independent small-integer model from the pre-code record. Use a bounded
	// table of ordinary accounting observations, not a native state/route model.
	for settled := int64(0); settled <= 9; settled++ {
		for unfulfilled := int64(0); unfulfilled <= 5; unfulfilled++ {
			for fulfilled := int64(0); fulfilled <= 5; fulfilled++ {
				for pending := int64(0); pending <= settled; pending++ {
					wantRequired := unfulfilled + fulfilled
					wantAvailable := settled - pending
					wantShort := int64(0)
					if wantRequired > wantAvailable {
						wantShort = wantRequired - wantAvailable
					}
					got, err := measureOpenRedemptionExposure(big.NewInt(settled), big.NewInt(unfulfilled), big.NewInt(fulfilled), big.NewInt(pending), 8)
					require.NoError(t, err)
					require.Equal(t, wantRequired, got.controlledRequired.Int64())
					require.Equal(t, wantAvailable, got.settledAvailable.Int64())
					require.Equal(t, wantShort, got.shortfall.Int64())
				}
			}
		}
	}
	for _, values := range [][4]*big.Int{
		{nil, big.NewInt(0), big.NewInt(0), big.NewInt(0)},
		{big.NewInt(3), big.NewInt(-1), big.NewInt(0), big.NewInt(0)},
		{big.NewInt(3), big.NewInt(0), big.NewInt(0), big.NewInt(4)},
		{big.NewInt(256), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
		{big.NewInt(255), big.NewInt(200), big.NewInt(100), big.NewInt(0)},
	} {
		got, err := measureOpenRedemptionExposure(values[0], values[1], values[2], values[3], 1)
		require.ErrorIs(t, err, errSupplyAccounting)
		require.Nil(t, got.controlledRequired)
		require.Nil(t, got.settledAvailable)
		require.Nil(t, got.shortfall)
	}
}

func TestQualSP248CollectionFulfilmentBurnAccounting(t *testing.T) {
	// A synthetic bookkeeping progression, not a transaction/payment replay.
	// Final fulfilment changes the category but not stock; final burn removes
	// both fulfilled quantity and stock. Pending observation does neither.
	for _, row := range []struct {
		stage                                                         string
		settled, unfulfilled, fulfilled, pending, required, available int64
	}{
		{"before collection", 8, 0, 0, 0, 0, 8},
		{"canonical collection", 12, 4, 0, 0, 4, 12},
		{"provisional settlement remains unfulfilled", 12, 4, 0, 0, 4, 12},
		{"partial method-final settlement", 12, 3, 1, 0, 4, 12},
		{"method-final complete", 12, 0, 4, 0, 4, 12},
		{"uncertain burn observation", 12, 0, 4, 0, 4, 12},
		{"canonical burn", 8, 0, 0, 0, 0, 8},
		{"post-burn external reconciliation", 8, 0, 0, 0, 0, 8},
	} {
		t.Run(row.stage, func(t *testing.T) {
			values := []*big.Int{big.NewInt(row.settled), big.NewInt(row.unfulfilled), big.NewInt(row.fulfilled), big.NewInt(row.pending)}
			got, err := measureOpenRedemptionExposure(values[0], values[1], values[2], values[3], 8)
			require.NoError(t, err)
			require.Equal(t, row.required, got.controlledRequired.Int64())
			require.Equal(t, row.available, got.settledAvailable.Int64())
			require.Zero(t, got.shortfall.Sign())
			got.controlledRequired.SetInt64(100)
			got.settledAvailable.SetInt64(100)
			got.shortfall.SetInt64(100)
			require.Equal(t, row.settled, values[0].Int64())
			require.Equal(t, row.unfulfilled, values[1].Int64())
			require.Equal(t, row.fulfilled, values[2].Int64())
			require.Equal(t, row.pending, values[3].Int64())
		})
	}
}
