package process

import (
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	"github.com/stretchr/testify/require"
	"testing"
)

type qualFA01ReplacementContext struct {
	*mock.SystemEIStub
	replaced bool
}

func (c *qualFA01ReplacementContext) ReplaceDRWAClassifier(vm.DRWATokenClassifier) error {
	c.replaced = true
	return nil
}

func TestQualFA01SystemVMHandoffLock(t *testing.T) {
	ctx := &qualFA01ReplacementContext{SystemEIStub: &mock.SystemEIStub{}}
	args := createMockArguments()
	args.SystemEI = ctx
	runtime, err := NewSystemVM(args)
	require.NoError(t, err)
	runtime.criticalSection.Lock()
	err = runtime.ReplaceDRWAClassifier(nil)
	runtime.criticalSection.Unlock()
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.False(t, ctx.replaced, "VM boundary must refuse before reaching the context")
}
