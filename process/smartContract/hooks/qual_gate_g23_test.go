package hooks_test

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Characterizes the real hook's rollback call and error/output boundary.
// The injected account-store callbacks are not native journal-restoration proof.
func TestQualGateG23HookSaveRollback(t *testing.T) {
	for _, phase := range []string{"builtin", "sender", "destination", "success", "same_address"} {
		for _, rollbackFails := range []bool{false, true} {
			t.Run(phase+map[bool]string{false: "/rollback_success", true: "/rollback_failure"}[rollbackFails], func(t *testing.T) {
				sender, destination := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
				if phase == "same_address" {
					destination = sender
				}
				input := createContractCallInput("gateG23", sender, destination)
				original, rollback := errors.New("experimental operation failure"), errors.New("experimental revert failure")
				var events []string
				output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 17, GasRefund: big.NewInt(2), ReturnData: [][]byte{[]byte("callback")}, Logs: []*vmcommon.LogEntry{{Identifier: []byte("pending")}}}
				container := builtInFunctions.NewBuiltInFunctionContainer()
				require.NoError(t, container.Add("gateG23", &mock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(s, d vmcommon.UserAccountHandler, got *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
					require.Same(t, input, got)
					require.Equal(t, sender, s.AddressBytes())
					require.Equal(t, destination, d.AddressBytes())
					events = append(events, "builtin")
					if phase == "builtin" {
						return output, original
					}
					return output, nil
				}}))
				args := createMockBlockChainHookArgs()
				args.BuiltInFunctions = container
				args.Accounts = &stateMock.AccountsStub{
					GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
						return stateMock.NewAccountWrapMock(address), nil
					},
					LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
						return stateMock.NewAccountWrapMock(address), nil
					},
					JournalLenCalled: func() int { events = append(events, "snapshot"); return 7 },
					SaveAccountCalled: func(account vmcommon.AccountHandler) error {
						name := "destination"
						if bytes.Equal(account.AddressBytes(), sender) {
							name = "sender"
						}
						events = append(events, name)
						if name == phase {
							return original
						}
						return nil
					},
					RevertToSnapshotCalled: func(snapshot int) error {
						require.Equal(t, 7, snapshot)
						events = append(events, "revert")
						if rollbackFails {
							return rollback
						}
						return nil
					},
				}
				hook, err := hooks.NewBlockChainHookImpl(args)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, hook.Close()) })
				got, err := hook.ProcessBuiltInFunction(input)
				want := []string{"snapshot", "builtin"}
				if phase != "builtin" {
					want = append(want, "sender")
				}
				if phase == "destination" || phase == "success" {
					want = append(want, "destination")
				}
				if phase == "success" || phase == "same_address" {
					require.NoError(t, err)
					require.Same(t, output, got)
				} else {
					want = append(want, "revert")
					require.Same(t, original, err)
					require.Nil(t, got)
					require.NotErrorIs(t, err, rollback, "native hook discards revert error; this is a recorded restriction")
				}
				require.Equal(t, want, events)
			})
		}
	}
}
