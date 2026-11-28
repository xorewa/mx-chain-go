package drwa

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRepairOrdinaryDetachedWideSupplyObservation(t *testing.T) {
	// Independent decimal and binary arithmetic representations of the same
	// nominal accounting point. Values are illustrative quantities, not limits.
	issuedDecimal := "1267650600228229401496703217721" // 2^100 + 12345
	liveDecimal := "1237940039285380274899131013"      // 2^90 + 6789
	issued, ok := new(big.Int).SetString(issuedDecimal, 10)
	require.True(t, ok)
	live, ok := new(big.Int).SetString(liveDecimal, 10)
	require.True(t, ok)
	binaryIssued := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 100), big.NewInt(12345))
	binaryLive := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 90), big.NewInt(6789))
	first := &supplyAccounting{issued, live, 3}
	equivalent := &supplyAccounting{binaryIssued, binaryLive, 3}

	require.Equal(t, repairSupplyComparison{true, true, true}, compareRepairSupplyAccounting(first, equivalent))
	require.Equal(t, repairSupplyComparison{true, true, true}, compareRepairSupplyAccounting(equivalent, first))
	// A different, independently observed cumulative quantity remains distinct
	// at full precision, without making a claim about admission or state transition.
	adjacent, ok := new(big.Int).SetString("1267650600228229401496703217722", 10)
	require.True(t, ok)
	other := &supplyAccounting{adjacent, new(big.Int).Set(binaryLive), 3}
	require.Equal(t, repairSupplyComparison{false, true, true}, compareRepairSupplyAccounting(first, other))
	require.Equal(t, issuedDecimal, issued.String())
	require.Equal(t, liveDecimal, live.String())
	require.Equal(t, issuedDecimal, binaryIssued.String())
	require.Equal(t, liveDecimal, binaryLive.String())
}

func TestRepairOrdinaryDetachedObservationComposition(t *testing.T) {
	// These are detached byte-length observations, not keys for a native store
	// or claims about profile identity. The independent totals are 3 visits,
	// key lengths 1+3+2=6 and material lengths 4+2+5=11.
	first := &currentLocalView{
		keys:      [][]byte{[]byte("a"), []byte("bbb")},
		materials: [][]byte{[]byte("four"), []byte("xy")},
	}
	second := &currentLocalView{
		keys:      [][]byte{[]byte("cc")},
		materials: [][]byte{[]byte("three")},
	}
	combined := &currentLocalView{
		keys:      [][]byte{[]byte("a"), []byte("bbb"), []byte("cc")},
		materials: [][]byte{[]byte("four"), []byte("xy"), []byte("three")},
	}
	bounds := repairInterpretationObservationBounds{3, 17}
	want := repairInterpretationObservation{3, 6, 11}
	for _, test := range []struct {
		name  string
		views []*currentLocalView
	}{
		{"separate_views", []*currentLocalView{first, second}},
		{"opposite_order", []*currentLocalView{second, first}},
		{"combined_view", []*currentLocalView{combined}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := measureRepairInterpretationObservations(test.views, bounds)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}
