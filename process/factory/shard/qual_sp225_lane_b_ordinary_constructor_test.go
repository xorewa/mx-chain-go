package shard

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP225OrdinaryShardFactoryRetainsGasConfiguration(t *testing.T) {
	if runtime.GOARCH == "arm64" {
		t.Skip("skipping test on arm64")
	}

	args := createMockVMAccountsArguments()
	factory, err := NewVMContainerFactory(args)
	require.NoError(t, err)
	require.NotNil(t, factory)
	require.Equal(t, args.BlockGasLimit, factory.blockGasLimit)
	require.Same(t, args.GasSchedule, factory.gasSchedule)
}
