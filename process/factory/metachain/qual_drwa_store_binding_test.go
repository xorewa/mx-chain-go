package metachain

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualStoreBindingClassifier struct {
	validate func(state.AccountsAdapter, state.AccountsAdapter) error
}

func (q *qualStoreBindingClassifier) ValidateAccounts(user, peer state.AccountsAdapter) error {
	return q.validate(user, peer)
}

func (q *qualStoreBindingClassifier) WithTokenClassification(state.AccountsAdapter, []byte,
	func(bool) (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	panic("classification must not occur during factory admission")
}

func (q *qualStoreBindingClassifier) IsInterfaceNil() bool { return q == nil }

func TestQualDRWAFactoryStoreBinding(t *testing.T) {
	for _, genesis := range []bool{false, true} {
		name := "processing"
		if genesis {
			name = "genesis"
		}
		t.Run(name, func(t *testing.T) {
			// Reuse the native factory fixture, without selecting another gas
			// schedule or rebuilding any native contracts on an admission error.
			gas := testscommon.NewGasScheduleNotifierMock(nil)
			notifications := 0
			gas.RegisterNotifyHandlerCalled = func(core.GasScheduleSubscribeHandler) { notifications++ }
			args := createVmContainerMockArgument(gas)
			cause := errors.New("experimental native store admission refusal")
			validations := 0
			args.DRWAClassifier = &qualStoreBindingClassifier{validate: func(user, peer state.AccountsAdapter) error {
				validations++
				require.Same(t, args.UserAccountsDB, user)
				require.Same(t, args.ValidatorAccountsDB, peer)
				return cause
			}}
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
			require.ErrorIs(t, err, vm.ErrDRWAExecution)
			require.ErrorIs(t, err, cause)
			require.Equal(t, 1, validations)
			require.Zero(t, notifications)
			require.Nil(t, factory.SystemSmartContractContainer())
			require.Nil(t, factory.SystemSmartContractContainerFactory())
		})
	}
}
