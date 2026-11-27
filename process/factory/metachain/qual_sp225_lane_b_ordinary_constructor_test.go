package metachain

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP225OrdinaryMetaFactoryRetainsConfiguration(t *testing.T) {
	t.Parallel()

	args := createVmContainerMockArgument(makeGasSchedule())
	factory, err := NewVMContainerFactory(args)
	require.NoError(t, err)
	require.NotNil(t, factory)
	require.Same(t, args.SystemSCConfig, factory.systemSCConfig)
	require.Same(t, args.GasSchedule, factory.gasSchedule)
}
