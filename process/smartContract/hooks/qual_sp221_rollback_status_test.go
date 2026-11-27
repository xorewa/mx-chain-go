package hooks_test

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmcommonBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// qualSP221Store is the real account store. With failRevert set, the store's
// own RevertToSnapshot fails (snapshot out of bounds). Inert local fixture.
type qualSP221Store struct {
	*state.AccountsDB
	failRevert bool
	reverts    int
	saves      int
	failSaveAt int
	saveErr    error
}

func (s *qualSP221Store) RevertToSnapshot(snapshot int) error {
	s.reverts++
	if s.failRevert {
		return s.AccountsDB.RevertToSnapshot(s.AccountsDB.JournalLen() + 1)
	}
	return s.AccountsDB.RevertToSnapshot(snapshot)
}

func (s *qualSP221Store) SaveAccount(account vmcommon.AccountHandler) error {
	s.saves++
	if s.saves == s.failSaveAt {
		return s.saveErr
	}
	return s.AccountsDB.SaveAccount(account)
}

func (s *qualSP221Store) credit(t *testing.T, address []byte, value int64) {
	t.Helper()
	account, err := s.AccountsDB.LoadAccount(address)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).AddToBalance(big.NewInt(value)))
	require.NoError(t, s.AccountsDB.SaveAccount(account))
}

func (s *qualSP221Store) balance(t *testing.T, address []byte) int64 {
	t.Helper()
	account, err := s.AccountsDB.LoadAccount(address)
	require.NoError(t, err)
	return account.(state.UserAccountHandler).GetBalance().Int64()
}

// SP2-21, Part A P-05, INV-0: at each of the three hook sites the caller gets
// the native error value whether or not the rollback fails; a failed rollback
// is carried on the store's status and the store does not commit.
func TestQualSP221HookRollbackStatus(t *testing.T) {
	sender, destination, marker := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	for _, phase := range []string{"builtin", "save_sender", "save_destination"} {
		for _, rollbackFails := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/rollback_fails_%t", phase, rollbackFails), func(t *testing.T) {
				primary := errors.New("inert operation failure")
				store := &qualSP221Store{AccountsDB: integrationtests.CreateInMemoryShardAccountsDB(), failRevert: rollbackFails, saveErr: primary}
				store.credit(t, sender, 10)
				root, err := store.Commit()
				require.NoError(t, err)
				store.failSaveAt = map[string]int{"builtin": 0, "save_sender": 1, "save_destination": 2}[phase]

				args := createMockBlockChainHookArgs()
				container := vmcommonBuiltins.NewBuiltInFunctionContainer()
				require.NoError(t, container.Add("qualProbe", &mock.BuiltInFunctionStub{
					ProcessBuiltinFunctionCalled: func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
						store.credit(t, marker, 5)
						if phase == "builtin" {
							return nil, primary
						}
						return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
					},
				}))
				args.BuiltInFunctions = container
				args.Accounts = store
				hook, err := hooks.NewBlockChainHookImpl(args)
				require.NoError(t, err)

				output, err := hook.ProcessBuiltInFunction(createContractCallInput("qualProbe", sender, destination))
				require.Nil(t, output)
				require.Same(t, primary, err, "the native error value is returned unchanged")
				require.Equal(t, 1, store.reverts)

				if !rollbackFails {
					require.NoError(t, store.RollbackFailure())
					require.Zero(t, store.balance(t, marker))
					committed, commitErr := store.Commit()
					require.NoError(t, commitErr)
					require.Equal(t, root, committed)
					return
				}

				status := store.RollbackFailure()
				require.ErrorIs(t, status, state.ErrRollbackFailed)
				require.ErrorIs(t, status, state.ErrSnapshotValueOutOfBounds)
				require.EqualValues(t, 5, store.balance(t, marker), "the mutation was not undone")
				committed, commitErr := store.Commit()
				require.Same(t, status, commitErr, "the partially reverted store does not commit")
				require.Nil(t, committed)
				require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
				require.NoError(t, store.RollbackFailure())
				require.Zero(t, store.balance(t, marker))
				require.EqualValues(t, 10, store.balance(t, sender))
			})
		}
	}
}
