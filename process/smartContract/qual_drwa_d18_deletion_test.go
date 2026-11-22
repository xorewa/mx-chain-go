package smartContract

import (
	"bytes"
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/state"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"testing"
)

// Exact untouched pinned native deletion body; receiver name only adapted.
func (sc *scProcessor) qualD18UntouchedDeleteAccounts(deletedAccounts [][]byte) error {
	for _, value := range deletedAccounts {
		acc, err := sc.getAccountFromAddress(value)
		if err != nil {
			return err
		}

		if check.IfNil(acc) {
			// TODO: sharded Smart Contract processing
			continue
		}

		err = sc.accounts.RemoveAccount(acc.AddressBytes())
		if err != nil {
			return err
		}
	}
	return nil
}

// This fixture ALWAYS denies; it cannot authenticate a creating owner.
type qualD18DenyDeletion struct {
	calls int
	err   error
}

func (g *qualD18DenyDeletion) WithDRWAAccountDeletion(_ state.AccountsAdapter, _ [][]byte, _ func() error) error {
	g.calls++
	return g.err
}
func TestQualD18DeletionNativeComparison(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		loadError, removeError, cross bool
	}{
		{name: "ordinary-and-both-reserved-names"}, {name: "load-error", loadError: true}, {name: "remove-error", removeError: true}, {name: "cross-shard", cross: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(baseline bool) ([]string, error) {
				trace := []string{}
				sentinel := errors.New("synthetic native failure")
				db := &stateMock.AccountsStub{LoadAccountCalled: func(a []byte) (vmcommon.AccountHandler, error) {
					trace = append(trace, "load:"+string(a))
					if tc.loadError {
						return nil, sentinel
					}
					return createAccount(a), nil
				}, RemoveAccountCalled: func(a []byte) error {
					trace = append(trace, "remove:"+string(a))
					if tc.removeError {
						return sentinel
					}
					return nil
				}}
				coord := mock.NewMultiShardsCoordinatorMock(2)
				coord.ComputeIdCalled = func([]byte) uint32 {
					if tc.cross {
						return coord.SelfId() + 1
					}
					return coord.SelfId()
				}
				sc := &scProcessor{accounts: db, shardCoordinator: coord}
				batch := [][]byte{[]byte("ordinary"), []byte("DRWAInstallInitialProgrammeAuthorities"), []byte("DRWARegisterToken"), []byte("ordinary")}
				var err error
				if baseline {
					err = sc.qualD18UntouchedDeleteAccounts(batch)
				} else {
					err = sc.deleteAccounts(batch)
				}
				return trace, err
			}
			want, werr := run(true)
			got, gerr := run(false)
			require.Equal(t, want, got)
			require.Equal(t, werr, gerr)
		})
	}
}
func TestQualD18DeletionDenialAndResolvedAddress(t *testing.T) {
	for _, actual := range [][]byte{core.SystemAccountAddress, []byte("foreign")} {
		name := "foreign-resolved-account"
		if bytes.Equal(actual, core.SystemAccountAddress) {
			name = "protected-system-account"
		}
		t.Run(name, func(t *testing.T) {
			removed := 0
			db := &stateMock.AccountsStub{LoadAccountCalled: func([]byte) (vmcommon.AccountHandler, error) { return createAccount(actual), nil }, RemoveAccountCalled: func([]byte) error { removed++; return nil }}
			coord := mock.NewMultiShardsCoordinatorMock(2)
			coord.ComputeIdCalled = func([]byte) uint32 { return coord.SelfId() }
			sc := &scProcessor{accounts: db, shardCoordinator: coord}
			err := sc.deleteAccountsNative([][]byte{[]byte("requested")}, true)
			if bytes.Equal(actual, core.SystemAccountAddress) {
				require.ErrorIs(t, err, process.ErrNotAllowedToWriteUnderProtectedKey)
			} else {
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
			}
			require.Zero(t, removed)
			deny := &qualD18DenyDeletion{err: vm.ErrDRWAExecution}

			args := createMockSmartContractProcessorArguments()
			args.AccountsDB = db
			args.ShardCoordinator = coord
			args.DRWAAccountDeletionGuard = deny
			sc, err = NewSmartContractProcessor(args)
			require.NoError(t, err)
			require.Same(t, deny, sc.drwaAccountDeletionGuard)

			require.ErrorIs(t, sc.deleteAccounts([][]byte{[]byte("requested"), core.SystemAccountAddress}), vm.ErrDRWAExecution)
			require.Equal(t, 1, deny.calls)
			require.Zero(t, removed)
		})
	}
	require.True(t, vm.DRWADeletionTargetsProtectedAccount([][]byte{[]byte("ordinary"), bytes.Clone(core.SystemAccountAddress)}))
	require.False(t, vm.DRWADeletionTargetsProtectedAccount([][]byte{[]byte("ordinary")}))
}
