package drwa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCarrierPricingOrdinaryDescriptor(t *testing.T) {
	pricing := &GasScheduleCarrierPricing{}
	pricing.GasScheduleChange(map[string]map[string]uint64{
		CarrierCostSection: {"ExampleSource": 1, "ExampleDestination": 2, "ExampleSuccess": 3, "ExampleRefund": 4, "ExampleCompletion": 5},
	})
	price, err := pricing.CarrierPrice("Example")
	require.NoError(t, err)
	require.Equal(t, CarrierPrice{Source: 1, Destination: 2, Success: 3, Refund: 4, Completion: 5}, price)
	require.False(t, pricing.IsInterfaceNil())
}
