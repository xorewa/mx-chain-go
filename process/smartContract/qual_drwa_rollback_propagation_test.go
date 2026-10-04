package smartContract

import (
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"testing"
)

// These are pinned-upstream observations for Part A 5.4 P-05, not a
// containment implementation or proof that a failed rollback can commit.
func TestQualDRWARollbackHookErrorTranslation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		hookErr    error
		code       vmcommon.ReturnCode
		propagated bool
	}{
		{"success", nil, vmcommon.Ok, false},
		{"vm_denial", nil, vmcommon.UserError, false},
		{"ordinary_error", errors.New("rollback failure"), vmcommon.Ok, false},
		{"database_error", errors.New(core.GetNodeFromDBErrorString), vmcommon.Ok, true},
		{"closing_database_error", errors.New(core.GetNodeFromDBErrorString + ": " + core.ErrDBIsClosed.Error()), vmcommon.Ok, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := &vmcommon.ContractCallInput{}
			output := &vmcommon.VMOutput{ReturnCode: tc.code, GasRemaining: 19, ReturnMessage: "native output"}
			calls := 0
			sc := &scProcessor{blockChainHook: &testscommon.BlockChainHookStub{
				ProcessBuiltInFunctionCalled: func(got *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
					require.Same(t, input, got)
					calls++
					return output, tc.hookErr
				},
			}}
			got, err := sc.resolveBuiltInFunctions(input)
			require.Equal(t, 1, calls)
			if tc.propagated {
				require.Same(t, tc.hookErr, err, "database error identity")
				require.Nil(t, got)
				return
			}
			require.NoError(t, err, "native translation boundary")
			if tc.hookErr == nil {
				require.Same(t, output, got)
				return
			}
			require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.UserError, ReturnMessage: tc.hookErr.Error()}, got, "native error translation")
		})
	}
}
