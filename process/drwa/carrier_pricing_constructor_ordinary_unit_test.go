package drwa

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

func TestCarrierPricingOrdinaryConstructor(t *testing.T) {
	initial := map[string]map[string]uint64{
		CarrierCostSection: {
			"ExampleSource": 11, "ExampleDestination": 12,
			"ExampleSuccess": 13, "ExampleRefund": 14, "ExampleCompletion": 15,
		},
	}
	var subscriber core.GasScheduleSubscribeHandler
	reads, registrations := 0, 0
	notifier := &testscommon.GasScheduleNotifierMock{
		LatestGasScheduleCalled: func() map[string]map[string]uint64 {
			reads++
			return initial
		},
		RegisterNotifyHandlerCalled: func(handler core.GasScheduleSubscribeHandler) {
			registrations++
			subscriber = handler
		},
	}

	pricing, err := NewGasScheduleCarrierPricing(notifier)
	require.NoError(t, err)
	require.NotNil(t, pricing)
	require.False(t, pricing.IsInterfaceNil())
	require.Equal(t, 1, reads)
	require.Equal(t, 1, registrations)
	require.Same(t, pricing, subscriber)

	price, err := pricing.CarrierPrice("Example")
	require.NoError(t, err)
	require.Equal(t, CarrierPrice{Source: 11, Destination: 12, Success: 13, Refund: 14, Completion: 15}, price)

	subscriber.GasScheduleChange(map[string]map[string]uint64{
		CarrierCostSection: {
			"ExampleSource": 21, "ExampleDestination": 22,
			"ExampleSuccess": 23, "ExampleRefund": 24, "ExampleCompletion": 25,
		},
	})
	price, err = pricing.CarrierPrice("Example")
	require.NoError(t, err)
	require.Equal(t, CarrierPrice{Source: 21, Destination: 22, Success: 23, Refund: 24, Completion: 25}, price)
}
