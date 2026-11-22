package metachain

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAFactoryHookStoreBinding(t *testing.T) {
	for _, genesis := range []bool{false, true} {
		mode := "processing"
		if genesis {
			mode = "genesis"
		}
		for _, binding := range []string{"different", "nil", "typed-nil", "matching", "nil-classifier", "typed-nil-classifier"} {
			t.Run(mode+"/"+binding, func(t *testing.T) {
				// Reuse the native factory fixture. Nil gas deliberately keeps
				// the nil-classifier control at its native validation error;
				// these cases admit no usable profile or execution context.
				gas := testscommon.NewGasScheduleNotifierMock(nil)
				notifications := 0
				gas.RegisterNotifyHandlerCalled = func(core.GasScheduleSubscribeHandler) { notifications++ }
				args := createVmContainerMockArgument(gas)
				cause := errors.New("experimental native store admission refusal")
				validations, hookReads := 0, 0
				args.DRWAClassifier = &qualStoreBindingClassifier{validate: func(user, peer state.AccountsAdapter) error {
					validations++
					require.Same(t, args.UserAccountsDB, user)
					require.Same(t, args.ValidatorAccountsDB, peer)
					return cause
				}}
				args.BlockChainHook = &testscommon.BlockChainHookStub{GetAccountsAdapterCalled: func() state.AccountsAdapter {
					hookReads++
					switch binding {
					case "different":
						return &stateMock.AccountsStub{}
					case "nil":
						return nil
					case "typed-nil":
						return (*stateMock.AccountsStub)(nil)
					case "nil-classifier", "typed-nil-classifier":
						t.Fatal("unconfigured or typed-nil classifier must not inspect the native adapter")
					}
					return args.UserAccountsDB
				}}
				if binding == "nil-classifier" {
					args.DRWAClassifier = nil
				}
				if binding == "typed-nil-classifier" {
					args.DRWAClassifier = (*qualStoreBindingClassifier)(nil)
				}
				factory, err := NewVMContainerFactory(args)
				require.NoError(t, err)
				if genesis {
					container, createErr := factory.CreateForGenesis()
					err = createErr
					require.Nil(t, container)
				} else {
					container, createErr := factory.Create()
					err = createErr
					require.Nil(t, container)
				}
				if binding == "nil-classifier" {
					require.Error(t, err, "native gas validation remains reachable")
					require.NotErrorIs(t, err, vm.ErrDRWAExecution)
					require.Zero(t, hookReads)
					require.Zero(t, validations)
					return
				}
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				if binding == "matching" {
					require.ErrorIs(t, err, cause, "matching hook must reach the existing user/peer validator")
					require.Equal(t, 1, validations)
				} else {
					require.NotErrorIs(t, err, cause)
					require.Zero(t, validations)
				}
				if binding == "typed-nil-classifier" {
					require.Zero(t, hookReads)
				} else {
					require.Equal(t, 1, hookReads)
				}
				require.Zero(t, notifications)
				require.Nil(t, factory.SystemSmartContractContainer())
				require.Nil(t, factory.SystemSmartContractContainerFactory())
			})
		}
	}
}
