package hooks_test

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-go/integrationTests"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Fault injection delegates every journal operation to the real AccountsDB.
// A SaveAccount fault is reported after the native write, requiring rollback
// of that partial operation. It does not model a failed native rollback.
type qualPartialsG23Accounts struct {
	state.AccountsAdapter
	failAddress []byte
	failure     error
	snapshot    int
	reverts     int
}

func (a *qualPartialsG23Accounts) SaveAccount(account vmcommon.AccountHandler) error {
	if err := a.AccountsAdapter.SaveAccount(account); err != nil {
		return err
	}
	if bytes.Equal(account.AddressBytes(), a.failAddress) {
		return a.failure
	}
	return nil
}
func (a *qualPartialsG23Accounts) RevertToSnapshot(snapshot int) error {
	a.reverts++
	if snapshot != a.snapshot {
		return errors.New("unexpected journal checkpoint")
	}
	return a.AccountsAdapter.RevertToSnapshot(snapshot)
}

func TestQualPartialsG23NativeJournalRestore(t *testing.T) {
	for _, phase := range []string{"builtin", "sender", "destination", "success"} {
		t.Run(phase, func(t *testing.T) {
			manager, _ := integrationTests.CreateTrieStorageManager(testscommon.CreateMemUnit())
			db, _ := integrationTests.CreateAccountsDB(integrationTests.UserAccount, manager)
			require.NotNil(t, db)
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			sender, destination, witness := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
			for _, addr := range [][]byte{sender, destination, witness} {
				a, err := db.LoadAccount(addr)
				require.NoError(t, err)
				u := a.(state.UserAccountHandler)
				require.NoError(t, u.AddToBalance(big.NewInt(100)))
				require.NoError(t, u.SaveKeyValue([]byte("key"), []byte("before")))
				require.NoError(t, db.SaveAccount(u))
			}
			_, err := db.Commit()
			require.NoError(t, err)
			// Preserve earlier uncommitted work: snapshot zero/root recreation would
			// erase this witness and is not equivalent to the owning journal checkpoint.
			w, err := db.LoadAccount(witness)
			require.NoError(t, err)
			require.NoError(t, w.(state.UserAccountHandler).SaveKeyValue([]byte("key"), []byte("checkpoint")))
			require.NoError(t, db.SaveAccount(w))
			snapshot := db.JournalLen()
			require.Positive(t, snapshot)
			root, err := db.RootHash()
			require.NoError(t, err)
			primary := errors.New("synthetic post-write operation failure")
			accounts := &qualPartialsG23Accounts{AccountsAdapter: db, failure: primary, snapshot: snapshot}
			if phase == "sender" {
				accounts.failAddress = sender
			}
			if phase == "destination" {
				accounts.failAddress = destination
			}
			args := createMockBlockChainHookArgs()
			args.Accounts = accounts
			container := builtInFunctions.NewBuiltInFunctionContainer()
			expected := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 17, GasRefund: big.NewInt(2), ReturnData: [][]byte{[]byte("callback")}, Logs: []*vmcommon.LogEntry{{Identifier: []byte("staged")}}}
			require.NoError(t, container.Add("partialsG23", &mock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(s, d vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				require.NoError(t, s.AddToBalance(big.NewInt(-1)))
				require.NoError(t, d.AddToBalance(big.NewInt(1)))
				for _, a := range []vmcommon.UserAccountHandler{s, d} {
					require.NoError(t, a.AccountDataHandler().SaveKeyValue([]byte("key"), []byte("after")))
					require.NoError(t, db.SaveAccount(a))
				}
				if phase == "builtin" {
					return expected, primary
				}
				return expected, nil
			}}))
			args.BuiltInFunctions = container
			hook, err := hooks.NewBlockChainHookImpl(args)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, hook.Close()) })
			output, err := hook.ProcessBuiltInFunction(createContractCallInput("partialsG23", sender, destination))
			if phase == "success" {
				require.NoError(t, err)
				require.Same(t, expected, output)
				require.Zero(t, accounts.reverts)
			} else {
				require.Same(t, primary, err)
				require.Nil(t, output)
				require.Equal(t, 1, accounts.reverts)
				after, e := db.RootHash()
				require.NoError(t, e)
				require.Equal(t, root, after)
				require.Equal(t, snapshot, db.JournalLen())
			}
			for _, addr := range [][]byte{sender, destination, witness} {
				a, e := db.GetExistingAccount(addr)
				require.NoError(t, e)
				u := a.(state.UserAccountHandler)
				value, _, e := u.RetrieveValue([]byte("key"))
				require.NoError(t, e)
				want := []byte("before")
				balance := int64(100)
				if bytes.Equal(addr, witness) {
					want = []byte("checkpoint")
				} else if phase == "success" {
					want = []byte("after")
					if bytes.Equal(addr, sender) {
						balance = 99
					} else {
						balance = 101
					}
				}
				require.Equal(t, want, value)
				require.Equal(t, big.NewInt(balance), u.GetBalance())
			}
			committed, err := db.Commit()
			require.NoError(t, err)
			if phase != "success" {
				require.Equal(t, root, committed)
			} else {
				require.NotEqual(t, root, committed)
			}
		})
	}
}
