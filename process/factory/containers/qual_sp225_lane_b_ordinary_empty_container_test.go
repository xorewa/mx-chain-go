package containers_test

import (
	"testing"

	"github.com/multiversx/mx-chain-go/process/factory/containers"
	"github.com/stretchr/testify/require"
)

func TestQualSP225OrdinaryEmptyVMContainerMetadata(t *testing.T) {
	t.Parallel()

	container := containers.NewVirtualMachinesContainer()
	require.Zero(t, container.Len())
	keys := container.Keys()
	require.NotNil(t, keys)
	require.Empty(t, keys)
}
