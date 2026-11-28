package drwa

import (
	"testing"

	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

func TestCarrierPricingOrdinaryNilArgument(t *testing.T) {
	pricing, err := NewGasScheduleCarrierPricing(nil)
	require.ErrorIs(t, err, ErrCarrierFunding)
	require.Nil(t, pricing)

	var notifier *testscommon.GasScheduleNotifierMock
	pricing, err = NewGasScheduleCarrierPricing(notifier)
	require.ErrorIs(t, err, ErrCarrierFunding)
	require.Nil(t, pricing)
}

func TestCarrierPricingOrdinaryAbsentDescriptor(t *testing.T) {
	pricing := &GasScheduleCarrierPricing{}
	pricing.GasScheduleChange(map[string]map[string]uint64{
		CarrierCostSection: {
			"ExampleSource": 1, "ExampleDestination": 2,
			"ExampleSuccess": 3, "ExampleRefund": 4, "ExampleCompletion": 5,
		},
	})

	for _, label := range []string{"", "AbsentExample"} {
		price, err := pricing.CarrierPrice(label)
		require.ErrorIs(t, err, ErrCarrierFunding)
		require.Equal(t, CarrierPrice{}, price)
	}
	price, err := pricing.CarrierPrice("Example")
	require.NoError(t, err)
	require.Equal(t, CarrierPrice{Source: 1, Destination: 2, Success: 3, Refund: 4, Completion: 5}, price)
}
