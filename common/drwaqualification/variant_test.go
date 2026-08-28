package drwaqualification

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func resetVariantForTest() {
	variantRegistry.Lock()
	variantRegistry.active = ""
	variantRegistry.Unlock()
}

func TestVariantRegistrationIsMutuallyExclusive(t *testing.T) {
	resetVariantForTest()
	t.Cleanup(resetVariantForTest)
	require.True(t, ProductionEligible())
	RegisterVariant(VariantTransport)
	require.Equal(t, VariantTransport, ActiveVariant())
	require.False(t, ProductionEligible())
	RegisterVariant(VariantTransport)
	require.Panics(t, func() { RegisterVariant(VariantBarrier) })
	require.Panics(t, func() { RegisterVariant("unknown") })
}
