package drwa

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// Independently specified wide positive observations test arithmetic only.
// They are synthetic reporting quantities, not programme limits, control
// evidence, a reservation, or native admission.
func TestQualSP248Z3WideStockProjection(t *testing.T) {
	asQuantity := func(t *testing.T, value string) *big.Int {
		t.Helper()
		q, ok := new(big.Int).SetString(value, 10)
		require.True(t, ok)
		return q
	}
	for _, row := range []struct {
		name                                      string
		settled, unfulfilled, fulfilled, outgoing string
		required, available, shortfall            string
	}{
		{
			name:        "wide_surplus",
			settled:     "184467440737095516160",
			unfulfilled: "55340232221128654848",
			fulfilled:   "36893488147419103232",
			outgoing:    "18446744073709551616",
			required:    "92233720368547758080",
			available:   "166020696663385964544",
			shortfall:   "0",
		},
		{
			name:        "wide_same_required_exact_stock",
			settled:     "147573952589676412928",
			unfulfilled: "18446744073709551616",
			fulfilled:   "73786976294838206464",
			outgoing:    "55340232221128654848",
			required:    "92233720368547758080",
			available:   "92233720368547758080",
			shortfall:   "0",
		},
		{
			name:        "wide_measured_shortfall",
			settled:     "110680464442257309696",
			unfulfilled: "36893488147419103232",
			fulfilled:   "55340232221128654848",
			outgoing:    "36893488147419103232",
			required:    "92233720368547758080",
			available:   "73786976294838206464",
			shortfall:   "18446744073709551616",
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			settled := asQuantity(t, row.settled)
			unfulfilled := asQuantity(t, row.unfulfilled)
			fulfilled := asQuantity(t, row.fulfilled)
			outgoing := asQuantity(t, row.outgoing)
			// The width is an isolated fixture bound; no resource policy
			// is selected by this comparison.
			const fixtureWidth = 16
			first, err := measureOpenRedemptionExposure(settled, unfulfilled, fulfilled, outgoing, fixtureWidth)
			require.NoError(t, err)
			second, err := measureOpenRedemptionExposure(settled, unfulfilled, fulfilled, outgoing, fixtureWidth)
			require.NoError(t, err)
			assertProjection := func(value openRedemptionExposure) {
				t.Helper()
				require.Equal(t, row.required, value.controlledRequired.String())
				require.Equal(t, row.available, value.settledAvailable.String())
				require.Equal(t, row.shortfall, value.shortfall.String())
			}
			assertProjection(first)
			assertProjection(second)
			require.Equal(t, row.settled, settled.String())
			require.Equal(t, row.unfulfilled, unfulfilled.String())
			require.Equal(t, row.fulfilled, fulfilled.String())
			require.Equal(t, row.outgoing, outgoing.String())

			// Local input updates after calculation and edits of one
			// detached readback must not alter another readback.
			settled.SetInt64(1)
			unfulfilled.SetInt64(2)
			fulfilled.SetInt64(3)
			outgoing.SetInt64(4)
			assertProjection(first)
			assertProjection(second)
			first.controlledRequired.SetInt64(5)
			first.settledAvailable.SetInt64(6)
			first.shortfall.SetInt64(7)
			assertProjection(second)
		})
	}
}
