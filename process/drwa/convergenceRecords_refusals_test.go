package drwa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Keep native AccountsDB and trie behavior except for the selected read fault.
// An inconsistent read is modeled as an unavailable record, not a storage write.
type convergenceReadFaultStore struct {
	state.AccountsAdapter
	key       []byte
	readCalls int
	failure   error
	missing   bool
}

func (s *convergenceReadFaultStore) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	a, err := s.AccountsAdapter.GetExistingAccount(address)
	if err != nil {
		return nil, err
	}
	return &convergenceReadFaultAccount{UserAccountHandler: a.(state.UserAccountHandler), store: s}, nil
}

type convergenceReadFaultAccount struct {
	state.UserAccountHandler
	store *convergenceReadFaultStore
}

func (a *convergenceReadFaultAccount) RetrieveValue(key []byte) ([]byte, uint32, error) {
	v, depth, err := a.UserAccountHandler.RetrieveValue(key)
	if err != nil || !bytes.Equal(key, a.store.key) {
		return v, depth, err
	}
	a.store.readCalls++
	if a.store.readCalls == 2 {
		if a.store.failure != nil {
			return nil, 0, a.store.failure
		}
		if a.store.missing {
			return nil, depth, nil
		}
	}
	return v, depth, nil
}

func TestConvergenceRecords_VerifyStateReadDependency(t *testing.T) {
	failure := errors.New("test fixture: convergence read unavailable")
	for _, tc := range []struct {
		name    string
		failure error
		missing bool
		want    error
	}{
		{name: "healthy"},
		{name: "second read fails", failure: failure, want: failure},
		{name: "inconsistent read", missing: true, want: errConvergence},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := qualConvergenceNew(t, 1)
			f.create(t)
			_, _, err := f.owner.Commit()
			require.NoError(t, err)
			root, err := f.store.RootHash()
			require.NoError(t, err)
			faulted := &convergenceReadFaultStore{AccountsAdapter: f.store, key: f.key, failure: tc.failure, missing: tc.missing}
			f.reopen(t, faulted)
			calls := f.host.verifyCalls
			err = f.owner.executeOwned(func(_ *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				return nil, f.records.verifyState(f.key, func() error {
					return f.host.VerifyTransition(f.binding)
				})
			})
			if tc.want == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.want)
			}
			require.Equal(t, 2, faulted.readCalls)
			require.Equal(t, calls+1, f.host.verifyCalls)
			assertConvergenceRefusalState(t, f, root)
		})
	}
}

func assertConvergenceRefusalState(t *testing.T, f *qualConvergenceFixture, root []byte) {
	t.Helper()
	f.assert(t, "PENDING")
	after, err := f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Zero(t, f.store.JournalLen())
	require.Empty(t, f.owner.outputs)
	require.Empty(t, qualRegistryValue(t, f.store, qualConvergenceParent))
}

func TestConvergenceRecords_OwnedPreparationRefusals(t *testing.T) {
	for _, operation := range []string{"acknowledge", "complete"} {
		t.Run(operation, func(t *testing.T) {
			for _, mode := range []string{"nil records", "nil codec", "nil state", "invalid transition"} {
				t.Run(mode, func(t *testing.T) {
					f := qualConvergenceNew(t, 1)
					f.create(t)
					_, _, err := f.owner.Commit()
					require.NoError(t, err)
					f.reopen(t, f.store)
					root, err := f.store.RootHash()
					require.NoError(t, err)
					r, tr := f.records, f.tr
					switch mode {
					case "nil records":
						r = nil
					case "nil codec":
						r = &convergenceRecords{}
					case "nil state":
						r = &convergenceRecords{codec: &registrationRecords{}}
					case "invalid transition":
						tr.token = nil
					}
					calls := f.host.verifyCalls
					err = f.owner.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
						if operation == "acknowledge" {
							return nil, r.acknowledgeOwned(op, tr, 0, f.local[0], []byte("synthetic-S-R-H-M-B-proof"))
						}
						out, err := r.completeOwned(op, tr)
						require.Nil(t, out)
						return nil, err
					})
					require.ErrorIs(t, err, errConvergence)
					require.Equal(t, calls, f.host.verifyCalls)
					require.Zero(t, f.host.ackCalls)
					require.Zero(t, f.host.completeCalls)
					assertConvergenceRefusalState(t, f, root)
				})
			}
		})
	}
}
