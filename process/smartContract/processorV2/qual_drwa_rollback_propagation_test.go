package processorV2

import (
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/testscommon"
	cacheMock "github.com/multiversx/mx-chain-go/testscommon/cache"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
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
		{"database_error", errors.New(core.GetNodeFromDBErrorString), vmcommon.Ok, false},
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

// The reload sentinel bounds this probe before refund/log/result production.
// Success here means reaching that boundary, not successful transaction recovery.
func TestQualDRWARollbackProcessIfErrorBoundary(t *testing.T) {
	for _, tc := range []struct {
		name        string
		rollbackErr error
	}{
		{"restoration_succeeds", nil},
		{"restoration_fails", errors.New("journal restoration failed")},
		{"closing", core.ErrDBIsClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := []string{}
			hash := []byte("tx-hash")
			address := []byte("local-address")
			reloadErr := errors.New("stop at reload boundary")
			sc := &scProcessor{
				shardCoordinator: &testscommon.ShardsCoordinatorMock{},
				vmOutputCacher: &cacheMock.CacherStub{PutCalled: func(key []byte, value interface{}, size int) bool {
					require.Equal(t, hash, key)
					require.Zero(t, size)
					require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.SimulateFailed, ReturnMessage: "initial failure"}, value)
					events = append(events, "cache")
					return false
				}},
				accounts: &stateMock.AccountsStub{
					RevertToSnapshotCalled: func(snapshot int) error {
						require.Equal(t, 7, snapshot)
						events = append(events, "revert")
						return tc.rollbackErr
					},
					LoadAccountCalled: func(got []byte) (vmcommon.AccountHandler, error) {
						require.Equal(t, address, got)
						events = append(events, "reload")
						return nil, reloadErr
					},
					SaveAccountCalled: func(vmcommon.AccountHandler) error { t.Error("unexpected save"); return reloadErr },
				},
			}
			err := sc.ProcessIfError(&stateMock.UserAccountStub{Address: address}, hash, nil, "user error", []byte("initial failure"), 7, 0)
			if tc.rollbackErr != nil {
				require.Same(t, tc.rollbackErr, err, "rollback error identity")
				require.Equal(t, []string{"cache", "revert"}, events, "no reload after failed restoration")
			} else {
				require.Same(t, reloadErr, err)
				require.Equal(t, []string{"cache", "revert", "reload"}, events)
			}
		})
	}
}
