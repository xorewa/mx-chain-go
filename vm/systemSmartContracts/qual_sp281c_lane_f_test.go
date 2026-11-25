package systemSmartContracts

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/process"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/state"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualSP281CLaneFClassifier struct {
	*publicOwner
	protectionErr error
	afterErr      error
}

func (c *qualSP281CLaneFClassifier) WithDRWAAccountProtection(_ state.AccountsAdapter, execute func() error) error {
	if c.protectionErr != nil {
		return c.protectionErr
	}
	err := execute()
	c.failure = c.afterErr
	return err
}

func (c *qualSP281CLaneFClassifier) WithDRWANativeCall(_ data.TransactionHandler, _ any, _ state.AccountsAdapter,
	_ vmcommon.VMExecutionHandler, _ func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
	c.failure = c.afterErr
	return vmcommon.UserError, c.protectionErr
}

func TestQualSP281CLaneFAccountDeletionUsesExactInstalledOwner(t *testing.T) {
	sentinel := errors.New("inert account-protection source error")
	for _, mode := range []string{"unconfigured", "nil-body", "latched", "foreign-store", "no-protection",
		"bad-accounts", "before-entry", "protected", "callback-error", "execution-error", "after-entry", "ordinary"} {
		t.Run(mode, func(t *testing.T) {
			accounts := &stateMock.AccountsStub{}
			owner := &qualSP281CLaneFClassifier{publicOwner: &publicOwner{publicClassifier: &publicClassifier{}}}
			host := &vmContext{drwaClassifierConfigured: mode != "unconfigured", drwaClassifier: owner, userAccountsDB: accounts}
			addresses := [][]byte{[]byte("inert")}
			calls := 0
			body := func() error {
				calls++
				if mode == "callback-error" {
					return sentinel
				}
				if mode == "execution-error" {
					return vm.ErrDRWAExecution
				}
				return nil
			}
			expectedCalls := 0
			var expected, latched error
			switch mode {
			case "unconfigured", "ordinary":
				expectedCalls = 1
			case "nil-body":
				body, expected = nil, vm.ErrDRWAExecution
			case "latched":
				owner.failure, expected, latched = sentinel, sentinel, sentinel
			case "foreign-store":
				accounts, expected, latched = &stateMock.AccountsStub{}, vm.ErrDRWAExecution, vm.ErrDRWAExecution
			case "no-protection":
				host.drwaClassifier, expected, latched = owner.publicOwner, vm.ErrDRWAExecution, vm.ErrDRWAExecution
			case "bad-accounts":
				owner.accountsErr, expected, latched = sentinel, sentinel, sentinel
			case "before-entry":
				owner.protectionErr, expected, latched = sentinel, sentinel, sentinel
			case "protected":
				addresses, expected = [][]byte{core.SystemAccountAddress}, process.ErrNotAllowedToWriteUnderProtectedKey
			case "callback-error":
				expectedCalls, expected = 1, sentinel
			case "execution-error":
				expectedCalls, expected, latched = 1, vm.ErrDRWAExecution, vm.ErrDRWAExecution
			case "after-entry":
				expectedCalls, owner.afterErr, expected, latched = 1, sentinel, sentinel, sentinel
			}
			require.Equal(t, mode != "unconfigured", host.DRWANativeCallConfigured())
			err := host.WithDRWAAccountDeletion(accounts, addresses, body)
			require.ErrorIs(t, err, expected)
			require.Equal(t, expectedCalls, calls)
			require.ErrorIs(t, host.drwaExecutionAvailabilityError(), latched)
		})
	}
}

func TestQualSP281CLaneFNativeContextForwardsOwnerOutcomeAndHealth(t *testing.T) {
	sentinel := errors.New("inert native owner refusal")
	for _, mode := range []string{"foreign-store", "provider-invalid-accounts", "already-failed", "became-unavailable", "provider-result"} {
		t.Run(mode, func(t *testing.T) {
			accounts := &stateMock.AccountsStub{}
			owner := &qualSP281CLaneFClassifier{publicOwner: &publicOwner{publicClassifier: &publicClassifier{}}}
			host := &vmContext{drwaClassifierConfigured: true, drwaClassifier: owner, userAccountsDB: accounts}
			expectedCode, expected := vmcommon.ExecutionFailed, sentinel
			switch mode {
			case "foreign-store":
				accounts, expected = &stateMock.AccountsStub{}, vm.ErrDRWAExecution
			case "provider-invalid-accounts":
				owner.accountsErr = sentinel
			case "already-failed":
				owner.failure = sentinel
			case "became-unavailable":
				owner.afterErr = sentinel
			case "provider-result":
				owner.protectionErr, expectedCode = sentinel, vmcommon.UserError
			}
			code, err := host.WithDRWANativeCall(&transaction.Transaction{}, nil, accounts,
				&processMock.VMExecutionHandlerStub{}, func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error) {
					t.Fatal("a refusing fixture cannot enter native execution")
					return vmcommon.Ok, nil
				})
			require.Equal(t, expectedCode, code)
			require.ErrorIs(t, err, expected)
		})
	}
}
