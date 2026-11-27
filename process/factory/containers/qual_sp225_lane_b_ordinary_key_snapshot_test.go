package containers_test

import (
	"testing"

	"github.com/multiversx/mx-chain-go/process/factory/containers"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/stretchr/testify/require"
)

func TestQualSP225OrdinaryVMContainerKeySnapshots(t *testing.T) {
	t.Parallel()

	container := containers.NewVirtualMachinesContainer()
	require.NoError(t, container.Add([]byte("label"), &mock.VMExecutionHandlerStub{}))

	keys := container.Keys()
	require.Equal(t, [][]byte{[]byte("label")}, keys)
	keys[0][0] = 'L'

	require.Equal(t, [][]byte{[]byte("label")}, container.Keys())
	require.Equal(t, 1, container.Len())
}
