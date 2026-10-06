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

// A VM return code and a Go error are distinct at this hook boundary. This
// observes native account-save calls only; it does not prove outer transaction
// acceptance, persistence or DRWA containment of a failing execution.
func TestQualDRWAUpstreamBuiltinReturnCodeAndAccountAlias(t *testing.T) {
	for _, sameAddress := range []bool{false, true} {
		for _, code := range []vmcommon.ReturnCode{vmcommon.Ok, vmcommon.UserError} {
			t.Run(fmt.Sprintf("same_address_%t/code_%d", sameAddress, code), func(t *testing.T) {
				args := createMockBlockChainHookArgs()
				container := vmcommonBuiltins.NewBuiltInFunctionContainer()
				sender := stateMock.NewAccountWrapMock([]byte("sender"))
				destination := stateMock.NewAccountWrapMock([]byte("destination"))
				output := &vmcommon.VMOutput{ReturnCode: code, ReturnMessage: "native result"}
				builtinCalls, loads, reverts := 0, 0, 0
				var saved []vmcommon.AccountHandler
				require.NoError(t, container.Add("qualProbe", &mock.BuiltInFunctionStub{
					ProcessBuiltinFunctionCalled: func(snd, dst vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
						builtinCalls++
						require.Same(t, sender, snd)
						if sameAddress {
							require.Same(t, sender, dst)
						} else {
							require.Same(t, destination, dst)
						}
						return output, nil
					},
				}))
				args.BuiltInFunctions = container
				args.Accounts = &stateMock.AccountsStub{
					GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
						require.Equal(t, sender.AddressBytes(), address)
						return sender, nil
					},
					LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
						loads++
						require.Equal(t, destination.AddressBytes(), address)
						return destination, nil
					},
					SaveAccountCalled:      func(account vmcommon.AccountHandler) error { saved = append(saved, account); return nil },
					RevertToSnapshotCalled: func(int) error { reverts++; return nil },
				}
				hook, err := hooks.NewBlockChainHookImpl(args)
				require.NoError(t, err)
				recipient := destination.AddressBytes()
				if sameAddress {
					recipient = sender.AddressBytes()
				}
				actual, err := hook.ProcessBuiltInFunction(createContractCallInput("qualProbe", sender.AddressBytes(), recipient))
				require.NoError(t, err)
				require.Same(t, output, actual)
				require.Equal(t, 1, builtinCalls)
				require.Zero(t, reverts)
				if sameAddress {
					require.Zero(t, loads)
					require.Len(t, saved, 1)
				} else {
					require.Equal(t, 1, loads)
					require.Len(t, saved, 2)
					require.Same(t, destination, saved[1])
				}
				require.Same(t, sender, saved[0])
			})
		}
	}
}
