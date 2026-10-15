package process

import (
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	"github.com/stretchr/testify/require"
)

type qualDRWAStatusContext struct {
	*mock.SystemEIStub
	failure error
}

func (c *qualDRWAStatusContext) DRWAExecutionError() error { return c.failure }

// DS02-M7: expose the same native context error without clearing, translating
// or creating a second latch. The inherited gas fixture is experimental (R7).
func TestQualDRWAVMStatusForwarding(t *testing.T) {
	for _, shape := range []string{"marker", "wrapped", "joined", "healthy", "legacy_context"} {
		t.Run(shape, func(t *testing.T) {
			failure := vm.ErrDRWAExecution
			switch shape {
			case "wrapped":
				failure = fmt.Errorf("experimental context: %w", failure)
			case "joined":
				failure = errors.Join(failure, errors.New("experimental rollback failure"))
			case "healthy", "legacy_context":
				failure = nil
			}
			args := createMockArguments()
			if shape != "legacy_context" {
				args.SystemEI = &qualDRWAStatusContext{SystemEIStub: &mock.SystemEIStub{}, failure: failure}
			}
			runtime, err := NewSystemVM(args)
			require.NoError(t, err)
			reader, exists := interface{}(runtime).(interface{ DRWAExecutionError() error })
			require.True(t, exists, "native System VM must expose its retained context error")
			if failure == nil {
				require.NoError(t, reader.DRWAExecutionError())
			} else {
				require.Same(t, failure, reader.DRWAExecutionError())
			}
		})
	}
}
