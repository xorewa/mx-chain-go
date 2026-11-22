package drwa

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func routeGuardUser(t *testing.T, accounts vmcommon.AccountsAdapter) vmcommon.UserAccountHandler {
	t.Helper()
	a, err := accounts.LoadAccount(qualContainmentAddress)
	require.NoError(t, err)
	return a.(vmcommon.UserAccountHandler)
}

// Independent native operations, not an oracle manufactured by the guard.
// EXPERIMENTAL unit probes (RECORD_4 FIELD_LABELS G1): amount3, data byte7,
// metadata byte1, nonce increment1 and the literal name; no production defaults.
func routeGuardMutations() map[string]func(vmcommon.UserAccountHandler) error {
	return map[string]func(vmcommon.UserAccountHandler) error{
		"add": func(u vmcommon.UserAccountHandler) error { return u.AddToBalance(big.NewInt(3)) },
		"sub": func(u vmcommon.UserAccountHandler) error { return u.SubFromBalance(big.NewInt(3)) },
		"claim": func(u vmcommon.UserAccountHandler) error {
			_, err := u.ClaimDeveloperRewards(qualContainmentAddress)
			return err
		},
		"change-owner": func(u vmcommon.UserAccountHandler) error {
			return u.ChangeOwnerAddress(qualContainmentAddress, qualContainmentAddress)
		},
		"metadata": func(u vmcommon.UserAccountHandler) error { u.SetCodeMetadata([]byte{1}); return nil },
		"owner":    func(u vmcommon.UserAccountHandler) error { u.SetOwnerAddress(qualContainmentAddress); return nil },
		"name":     func(u vmcommon.UserAccountHandler) error { u.SetUserName([]byte("experimental")); return nil },
		"nonce":    func(u vmcommon.UserAccountHandler) error { u.IncreaseNonce(1); return nil },
		"data": func(u vmcommon.UserAccountHandler) error {
			return u.AccountDataHandler().SaveKeyValue([]byte("fixture/protocol-record"), []byte{7})
		},
		"migrate": func(u vmcommon.UserAccountHandler) error {
			return u.AccountDataHandler().MigrateDataTrieLeaves(vmcommon.ArgsMigrateDataTrieLeaves{})
		},
	}
}

func routeGuardSnapshot(u vmcommon.UserAccountHandler) []interface{} {
	v, _, err := u.AccountDataHandler().RetrieveValue([]byte("fixture/protocol-record"))
	return []interface{}{new(big.Int).Set(u.GetBalance()), new(big.Int).Set(u.GetDeveloperReward()), bytes.Clone(u.GetCodeMetadata()), bytes.Clone(u.GetOwnerAddress()), bytes.Clone(u.GetUserName()), u.GetNonce(), bytes.Clone(v), err, bytes.Clone(u.AddressBytes()), bytes.Clone(u.GetCodeHash()), bytes.Clone(u.GetRootHash())}
}

func TestRouteNativeGuardMutationBarrierAndNativeDifferential(t *testing.T) {
	for name, mutate := range routeGuardMutations() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := qualContainmentStore(t)
			g, a, err := newRouteNativeGuard(s)
			require.NoError(t, err)
			u := routeGuardUser(t, a)
			before := routeGuardSnapshot(u)
			_ = mutate(u) // void native setters must be caught by the same barrier.
			require.ErrorIs(t, g.finish(), errRouteNativeGuard)
			require.Equal(t, before, routeGuardSnapshot(u))
			require.Zero(t, s.JournalLen())

			s = qualContainmentStore(t)
			g, a, err = newRouteNativeGuard(s)
			require.NoError(t, err)
			u = routeGuardUser(t, a)
			native := routeGuardUser(t, qualContainmentStore(t))
			require.NoError(t, g.admit())
			expected := mutate(native)
			actual := mutate(u)
			require.Equal(t, expected, actual)
			require.Equal(t, routeGuardSnapshot(native), routeGuardSnapshot(u))
			require.Equal(t, actual, g.finish())
		})
	}
}

type routeGuardFaultAccounts struct {
	vmcommon.AccountsAdapter
	load, existing, remove error
}

func (a *routeGuardFaultAccounts) LoadAccount(address []byte) (vmcommon.AccountHandler, error) {
	if a.load != nil {
		return nil, a.load
	}
	return a.AccountsAdapter.LoadAccount(address)
}
func (a *routeGuardFaultAccounts) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	if a.existing != nil {
		return nil, a.existing
	}
	return a.AccountsAdapter.GetExistingAccount(address)
}
func (a *routeGuardFaultAccounts) RemoveAccount(address []byte) error { return a.remove }

func TestRouteNativeGuardOriginalErrorsAndOwnership(t *testing.T) {
	_, _, err := newRouteNativeGuard(nil)
	require.ErrorIs(t, err, state.ErrNilAccountsAdapter)
	original := errors.New("experimental native read failure")
	for _, existing := range []bool{false, true} {
		s := &routeGuardFaultAccounts{AccountsAdapter: qualContainmentStore(t)}
		g, a, err := newRouteNativeGuard(s)
		require.NoError(t, err)
		if existing {
			s.existing = original
			_, _ = a.GetExistingAccount(qualContainmentAddress)
		} else {
			s.load = original
			_, _ = a.LoadAccount(qualContainmentAddress)
		}
		require.Same(t, original, g.admit())
		require.Same(t, original, g.finish())
		require.Same(t, original, a.SaveAccount(nil))
	}

	s := qualContainmentStore(t)
	g, a, err := newRouteNativeGuard(s)
	require.NoError(t, err)
	_, err = a.GetExistingAccount(qualContainmentAddress)
	require.NoError(t, err)
	u := routeGuardUser(t, a)
	require.ErrorIs(t, a.SaveAccount(u), errRouteNativeGuard)
	require.ErrorIs(t, a.RemoveAccount(qualContainmentAddress), errRouteNativeGuard)
	for _, rollback := range []bool{false, true} {
		g, a, err = newRouteNativeGuard(s)
		require.NoError(t, err)
		if rollback {
			err = a.RevertToSnapshot(0)
		} else {
			_, err = a.Commit()
		}
		require.ErrorIs(t, err, errRouteNativeGuard)
		require.ErrorIs(t, g.admit(), errRouteNativeGuard)
	}
	require.Zero(t, s.commits)
	require.Zero(t, s.reverts)

	g, a, err = newRouteNativeGuard(s)
	require.NoError(t, err)
	require.NoError(t, g.admit())
	_, other, err := newRouteNativeGuard(s)
	require.NoError(t, err)
	require.ErrorIs(t, a.SaveAccount(routeGuardUser(t, other)), errRouteNativeGuard)
	g, a, err = newRouteNativeGuard(s)
	require.NoError(t, err)
	require.NoError(t, g.admit())
	require.NoError(t, g.finish())
	require.ErrorIs(t, g.admit(), errRouteNativeGuard)
	require.ErrorIs(t, a.RemoveAccount(qualContainmentAddress), errRouteNativeGuard)

	faults := &routeGuardFaultAccounts{AccountsAdapter: s, remove: original}
	g, a, err = newRouteNativeGuard(faults)
	require.NoError(t, err)
	require.NoError(t, g.admit())
	require.Same(t, original, a.RemoveAccount(qualContainmentAddress))
	require.Same(t, original, g.finish())
}

type routeGuardFaultUser struct {
	vmcommon.UserAccountHandler
	root []byte
	data vmcommon.AccountDataHandler
}

func (u *routeGuardFaultUser) GetRootHash() []byte                             { return u.root }
func (u *routeGuardFaultUser) AccountDataHandler() vmcommon.AccountDataHandler { return u.data }

type routeGuardFaultData struct {
	vmcommon.AccountDataHandler
	err error
}

// EXPERIMENTAL reported depth3 (FIELD_LABELS G2), not a trie/profile setting.
func (d *routeGuardFaultData) RetrieveValue([]byte) ([]byte, uint32, error) { return nil, 3, d.err }

func TestRouteNativeGuardDataAbsenceAndDiscardedFailure(t *testing.T) {
	// EXPERIMENTAL fault-only root byte1 (G3): a nonempty-root marker, not a
	// claimed canonical hash. Nil roots and errors test native absence semantics.
	for _, test := range []struct {
		name    string
		root    []byte
		err     error
		latched bool
	}{
		{"absent-key", []byte{1}, nil, false},
		{"empty-trie", nil, state.ErrNilTrie, false},
		{"wrapped-fault", nil, errors.Join(state.ErrNilTrie, errors.New("experimental backend fault")), true},
		{"missing-trie", []byte{1}, state.ErrNilTrie, true},
		{"io", nil, errors.New("experimental data read fault"), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := &routeNativeGuard{}
			u := &routeNativeUser{UserAccountHandler: &routeGuardFaultUser{root: test.root, data: &routeGuardFaultData{err: test.err}}, guard: g}
			_, depth, err := u.AccountDataHandler().RetrieveValue([]byte("experimental"))
			require.Equal(t, test.err, err)
			require.Equal(t, uint32(3), depth)
			if test.latched {
				require.Equal(t, test.err, g.admit())
			} else {
				require.NoError(t, g.admit())
			}
		})
	}
	g, a, err := newRouteNativeGuard(qualContainmentStore(t))
	require.NoError(t, err)
	u, err := a.LoadAccount([]byte("experimental empty native account"))
	require.NoError(t, err)
	_, _, err = u.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue([]byte("absent"))
	require.ErrorIs(t, err, state.ErrNilTrie)
	require.NoError(t, g.admit())
}

func TestRouteNativeGuardRealJournalRollbackAfterIgnoredSaveFailure(t *testing.T) {
	s := qualContainmentStore(t)
	owner, err := NewRollbackContainment(s)
	require.NoError(t, err)
	original := errors.New("experimental save failed after native write")
	err = owner.Execute(func() (*vmcommon.VMOutput, error) {
		g, a, e := newRouteNativeGuard(s)
		require.NoError(t, e)
		u := routeGuardUser(t, a)
		require.NoError(t, g.admit())
		// EXPERIMENTAL debit10 (G4) against the inherited native fixture balance100.
		require.NoError(t, u.SubFromBalance(big.NewInt(10)))
		s.saveErr = original
		_ = a.SaveAccount(u)
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, g.finish()
	})
	s.saveErr = nil
	require.Same(t, original, err)
	qualAssertContainmentBalance(t, s, 100)
	require.Equal(t, 1, s.reverts)
	require.Zero(t, s.commits)
}

func TestRouteNativeGuardReadViewsDoNotMutateNativeBacking(t *testing.T) {
	s := qualContainmentStore(t)
	g, a, err := newRouteNativeGuard(s)
	require.NoError(t, err)
	// The native tracker returns the dirty-cache value directly. Prepare that
	// actual native state so a missing data-view copy cannot hide behind a
	// fresh trie read that happens to allocate another buffer.
	raw := routeGuardUser(t, s)
	// EXPERIMENTAL nonempty read-view fixtures (RECORD_5 G8). These byte
	// sequences are alias probes, not canonical code hashes, owner keys or
	// production metadata/name profiles. Use the actual native setters.
	native, ok := raw.(state.UserAccountHandler)
	require.True(t, ok)
	native.SetCodeMetadata([]byte("experimental metadata"))
	native.SetCodeHash([]byte("experimental code hash"))
	native.SetOwnerAddress([]byte("experimental owner"))
	native.SetUserName([]byte("experimental name"))
	// EXPERIMENTAL dirty value100 (G5), matching the inherited fixture record.
	require.NoError(t, raw.AccountDataHandler().SaveKeyValue([]byte("fixture/protocol-record"), []byte{100}))
	wrapped, err := a.wrap(raw, nil)
	require.NoError(t, err)
	u := wrapped.(vmcommon.UserAccountHandler)
	before := routeGuardSnapshot(u)
	// EXPERIMENTAL alias attack999 and byte replacement0/XOR255 (G6).
	u.GetBalance().SetInt64(999)
	u.GetDeveloperReward().SetInt64(999)
	for _, view := range [][]byte{u.AddressBytes(), u.GetCodeMetadata(), u.GetCodeHash(), u.GetRootHash(), u.GetOwnerAddress(), u.GetUserName()} {
		require.NotEmpty(t, view, "every byte copy must face a nonempty alias probe")
		if len(view) != 0 {
			view[0] ^= 0xff
		}
	}
	v, _, err := u.AccountDataHandler().RetrieveValue([]byte("fixture/protocol-record"))
	require.NoError(t, err)
	v[0] = 0
	require.Equal(t, before, routeGuardSnapshot(u))
	require.NoError(t, g.admit())
	require.NoError(t, a.SaveAccount(u))
	require.NoError(t, g.finish())
	// EXPERIMENTAL stale-writer increment1 (G7), not a protocol allowance.
	require.ErrorIs(t, u.AddToBalance(big.NewInt(1)), errRouteNativeGuard)
	qualAssertContainmentBalance(t, s, 100)
}

func TestRouteNativeGuardKeepsFirstErrorAcrossLaterReads(t *testing.T) {
	// EXPERIMENTAL distinct native I/O failures (RECORD_5 G9), not public
	// denial codes. Each call returns its own error, while the owner retains A.
	first := errors.New("experimental first native read failure")
	second := errors.New("experimental second native read failure")
	require.NotSame(t, first, second)
	for _, later := range []string{"load", "existing", "data"} {
		t.Run(later, func(t *testing.T) {
			backend := &routeGuardFaultAccounts{AccountsAdapter: qualContainmentStore(t), load: first}
			g, accounts, err := newRouteNativeGuard(backend)
			require.NoError(t, err)
			_, err = accounts.LoadAccount(qualContainmentAddress)
			require.Same(t, first, err)
			switch later {
			case "load":
				backend.load = second
				_, err = accounts.LoadAccount(qualContainmentAddress)
			case "existing":
				backend.existing = second
				_, err = accounts.GetExistingAccount(qualContainmentAddress)
			case "data":
				// G3's experimental nonempty-root marker; no canonical hash claim.
				u := &routeNativeUser{UserAccountHandler: &routeGuardFaultUser{root: []byte{1}, data: &routeGuardFaultData{err: second}}, guard: g}
				_, _, err = u.AccountDataHandler().RetrieveValue([]byte("experimental later read"))
			}
			require.Same(t, second, err, "the later native read must really execute")
			require.Same(t, first, g.admit())
			require.Same(t, first, g.finish())
		})
	}
}

func TestRouteNativeGuardPreservesNativeNilAndRepeatedAdmissionDenies(t *testing.T) {
	g, a, err := newRouteNativeGuard(qualContainmentStore(t))
	require.NoError(t, err)
	account, err := a.wrap(nil, nil)
	require.NoError(t, err)
	require.Nil(t, account) // The builtin retains its original nil/type check.
	require.NoError(t, g.admit())
	require.ErrorIs(t, g.admit(), errRouteNativeGuard)
	require.ErrorIs(t, g.finish(), errRouteNativeGuard)
	g, a, err = newRouteNativeGuard(qualContainmentStore(t))
	require.NoError(t, err)
	require.NoError(t, g.admit())
	var missing *routeNativeUser
	require.ErrorIs(t, a.SaveAccount(missing), errRouteNativeGuard)
}
