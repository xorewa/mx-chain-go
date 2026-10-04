package hooks_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmcommonBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Part A F.2.1 P-05 and Part B 16.2 require containment of rollback failure.
// This records the unmodified hook's error boundary, not a conforming DRWA
// implementation, real trie corruption, partial commit or an exploit.
func TestQualDRWAUpstreamRollbackErrorBoundary(t *testing.T) {
	for _, phase := range []string{"builtin", "save_sender", "save_destination"} {
		for _, rollbackFails := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/rollback_fails_%t", phase, rollbackFails), func(t *testing.T) {
				primary := errors.New("injected operation failure")
				rollback := errors.New("injected rollback failure")
				args := createMockBlockChainHookArgs()
				container := vmcommonBuiltins.NewBuiltInFunctionContainer()
				builtinCalls, saveCalls, rollbackCalls := 0, 0, 0
				require.NoError(t, container.Add("qualProbe", &mock.BuiltInFunctionStub{
					ProcessBuiltinFunctionCalled: func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
						builtinCalls++
						if phase == "builtin" {
							return nil, primary
						}
						return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
					},
				}))
				args.BuiltInFunctions = container
				args.Accounts = &stateMock.AccountsStub{
					GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
						return stateMock.NewAccountWrapMock(address), nil
					},
					LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
						return stateMock.NewAccountWrapMock(address), nil
					},
					JournalLenCalled: func() int { return 7 },
					SaveAccountCalled: func(_ vmcommon.AccountHandler) error {
						saveCalls++
						if phase == "save_sender" || (phase == "save_destination" && saveCalls == 2) {
							return primary
						}
						return nil
					},
					RevertToSnapshotCalled: func(snapshot int) error {
						rollbackCalls++
						require.Equal(t, 7, snapshot)
						if rollbackFails {
							return rollback
						}
						return nil
					},
				}
				hook, err := hooks.NewBlockChainHookImpl(args)
				require.NoError(t, err)
				output, err := hook.ProcessBuiltInFunction(createContractCallInput("qualProbe", []byte("sender"), []byte("destination")))
				require.Nil(t, output)
				require.ErrorIs(t, err, primary)
				require.False(t, errors.Is(err, rollback), "upstream discards the rollback error in every exercised branch")
				require.Equal(t, 1, builtinCalls)
				require.Equal(t, 1, rollbackCalls)
				require.Equal(t, map[string]int{"builtin": 0, "save_sender": 1, "save_destination": 2}[phase], saveCalls)
			})
		}
	}
}
