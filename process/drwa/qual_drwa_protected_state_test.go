package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/accounts"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

func qualProtectedFixture(t *testing.T, auto bool) (*qualReaderFixture, *protectedState) {
	t.Helper()
	f := qualNativeReaderFixture(t, auto, 0)
	a, err := f.adb.LoadAccount(bytes.Clone(core.SystemAccountAddress))
	require.NoError(t, err)
	u := a.(state.UserAccountHandler)
	// Provision a real native trie. This fixture is not production genesis
	// authorization; the component refuses an unprovisioned/absent account.
	require.NoError(t, u.SaveKeyValue([]byte("ordinary-existing-leaf"), []byte("untouched")))
	require.NoError(t, u.SaveKeyValue([]byte("ELRONDDRWA@membershipIndex@count"), make([]byte, 8)))
	require.NoError(t, f.adb.SaveAccount(u))
	_, err = f.adb.Commit()
	require.NoError(t, err)
	s, err := newProtectedState(f.adb)
	require.NoError(t, err)
	return f, s
}

func TestQualDRWAProtectedStateLifecycle(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprint(auto), func(t *testing.T) {
			f, s := qualProtectedFixture(t, auto)
			one, two := []byte("TOKEN-000001"), []byte("TOKEN-000002")
			present, err := s.membership(one)
			require.NoError(t, err)
			require.False(t, present)
			require.NoError(t, s.materializeMembership(one))
			boundary := f.adb.JournalLen()
			require.Positive(t, boundary)
			require.NoError(t, s.materializeMembership(one))
			require.Equal(t, boundary, f.adb.JournalLen(), "duplicate must not save again")
			require.NoError(t, s.materializeMembership(two))
			require.NoError(t, f.adb.RevertToSnapshot(boundary))
			present, err = s.membership(one)
			require.NoError(t, err)
			require.True(t, present)
			present, err = s.membership(two)
			require.NoError(t, err)
			require.False(t, present)
			root, err := f.adb.Commit()
			require.NoError(t, err)
			require.NoError(t, s.materializeMembership(two))
			require.NoError(t, f.adb.RevertToSnapshot(0))
			present, err = s.membership(two)
			require.NoError(t, err)
			require.False(t, present)
			require.NoError(t, f.adb.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
			present, err = s.membership(one)
			require.NoError(t, err)
			require.True(t, present, "same component reloads current native account")
		})
	}
}

func TestQualDRWAProtectedStateMalformed(t *testing.T) {
	for _, value := range [][]byte{{0}, {2}, {1, 0}, {0xff}, {1, 1, 1}} {
		t.Run(fmt.Sprintf("%x", value), func(t *testing.T) {
			f, s := qualProtectedFixture(t, false)
			a, err := f.adb.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			key, err := membershipKey([]byte("TOKEN-000001"))
			require.NoError(t, err)
			u := a.(state.UserAccountHandler)
			require.NoError(t, u.SaveKeyValue(key, value))
			require.NoError(t, f.adb.SaveAccount(u))
			before, err := f.adb.RootHash()
			require.NoError(t, err)
			present, err := s.membership([]byte("TOKEN-000001"))
			require.ErrorIs(t, err, errInvalidMembership)
			require.False(t, present)
			require.ErrorIs(t, s.materializeMembership([]byte("TOKEN-000001")), errInvalidMembership)
			after, err := f.adb.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestQualDRWAProtectedStateDependencies(t *testing.T) {
	_, err := newProtectedState(nil)
	require.ErrorIs(t, err, state.ErrNilAccountsAdapter)
	var nilDB *state.AccountsDB
	_, err = newProtectedState(nilDB)
	require.ErrorIs(t, err, state.ErrNilAccountsAdapter)
	f, s := qualProtectedFixture(t, false)
	require.ErrorIs(t, s.materializeMembership(nil), errInvalidMembership)
	present, err := s.membership(nil)
	require.ErrorIs(t, err, errInvalidMembership)
	require.False(t, present)
	// Native serialized account address tampering isolates the exact-locus guard.
	raw, _, err := f.tr.Get(core.SystemAccountAddress)
	require.NoError(t, err)
	data := &accounts.UserAccountData{}
	require.NoError(t, f.args.Marshaller.Unmarshal(data, raw))
	data.Address = bytes.Repeat([]byte{3}, 32)
	raw, err = f.args.Marshaller.Marshal(data)
	require.NoError(t, err)
	require.NoError(t, f.tr.Update(core.SystemAccountAddress, raw))
	present, err = s.membership([]byte("TOKEN-000001"))
	require.ErrorIs(t, err, errInvalidMembership)
	require.False(t, present)

	f = qualNativeReaderFixture(t, false, 0)
	s, err = newProtectedState(f.adb)
	require.NoError(t, err)
	present, err = s.membership([]byte("TOKEN-000001"))
	require.ErrorIs(t, err, state.ErrAccNotFound)
	require.False(t, present)
	a, err := f.adb.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	require.NoError(t, f.adb.SaveAccount(a))
	present, err = s.membership([]byte("TOKEN-000001"))
	require.ErrorIs(t, err, state.ErrNilTrie)
	require.False(t, present)
	require.ErrorIs(t, s.materializeMembership([]byte("TOKEN-000001")), state.ErrNilTrie)
}

// The decorator only injects one native account-save boundary; all account,
// trie, journal, root and reconstruction behaviour remains actual AccountsDB.
type qualProtectedSaveFault struct {
	state.AccountsAdapter
	fault error
}

func (s *qualProtectedSaveFault) SaveAccount(a vmcommon.AccountHandler) error {
	if s.fault != nil {
		return s.fault
	}
	return s.AccountsAdapter.SaveAccount(a)
}

type qualProtectedItemFault struct {
	state.UserAccountHandler
	fault error
}

func (a *qualProtectedItemFault) SaveKeyValue(_, _ []byte) error { return a.fault }

type qualProtectedAccountSource struct {
	state.AccountsAdapter
	account vmcommon.AccountHandler
	err     error
}

func (a *qualProtectedAccountSource) GetExistingAccount(_ []byte) (vmcommon.AccountHandler, error) {
	return a.account, a.err
}

func TestQualDRWAProtectedStateItemFailure(t *testing.T) {
	f, _ := qualProtectedFixture(t, false)
	a, err := f.adb.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	fault := errors.New("native item-save boundary failed")
	s, err := newProtectedState(&qualProtectedAccountSource{AccountsAdapter: f.adb,
		account: &qualProtectedItemFault{UserAccountHandler: a.(state.UserAccountHandler), fault: fault}})
	require.NoError(t, err)
	before, err := f.adb.RootHash()
	require.NoError(t, err)
	require.ErrorIs(t, s.materializeMembership([]byte("TOKEN-000001")), fault)
	after, err := f.adb.RootHash()
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Zero(t, f.adb.JournalLen())
	// A backend error alongside an account must also be retained, not replaced
	// with absence or used for a write through an otherwise healthy reference.
	s, err = newProtectedState(&qualProtectedAccountSource{AccountsAdapter: f.adb, account: a, err: fault})
	require.NoError(t, err)
	present, err := s.membership([]byte("TOKEN-000001"))
	require.ErrorIs(t, err, fault)
	require.False(t, present)
}

func TestQualDRWAProtectedStateAccountType(t *testing.T) {
	f, _ := qualProtectedFixture(t, false)
	s, err := newProtectedState(&qualProtectedAccountSource{AccountsAdapter: f.adb})
	require.NoError(t, err)
	var present bool
	require.NotPanics(t, func() { present, err = s.membership([]byte("TOKEN-000001")) })
	require.ErrorIs(t, err, errInvalidMembership)
	require.False(t, present)
}

func TestQualDRWAProtectedStateSaveContainment(t *testing.T) {
	f, _ := qualProtectedFixture(t, false)
	fault := errors.New("native account save unavailable")
	adapter := &qualProtectedSaveFault{AccountsAdapter: f.adb, fault: fault}
	s, err := newProtectedState(adapter)
	require.NoError(t, err)
	c, err := NewRollbackContainment(f.adb)
	require.NoError(t, err)
	require.ErrorIs(t, c.Execute(func() (*vmcommon.VMOutput, error) {
		return nil, s.materializeMembership([]byte("TOKEN-000001"))
	}), fault)
	adapter.fault = nil
	present, err := s.membership([]byte("TOKEN-000001"))
	require.NoError(t, err)
	require.False(t, present)
	require.NoError(t, c.Execute(func() (*vmcommon.VMOutput, error) {
		return nil, s.materializeMembership([]byte("TOKEN-000001"))
	}))
	_, _, err = c.Commit()
	require.NoError(t, err)
	present, err = s.membership([]byte("TOKEN-000001"))
	require.NoError(t, err)
	require.True(t, present)
}

func TestQualDRWAProtectedStateMigration(t *testing.T) {
	for _, destination := range []string{"exact", "family", "ordinary"} {
		t.Run(destination, func(t *testing.T) {
			f, s := qualProtectedFixture(t, false)
			token := []byte("TOKEN-000001")
			require.NoError(t, s.materializeMembership(token))
			oldRoot, err := f.adb.Commit()
			require.NoError(t, err)
			key, err := membershipKey(token)
			require.NoError(t, err)
			a, err := f.adb.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			oldTrie := a.(state.UserAccountHandler).DataTrie().(common.Trie)
			oldDataRoot, err := oldTrie.RootHash()
			require.NoError(t, err)
			proof, encodedOldLeaf, err := oldTrie.GetProof(key)
			require.NoError(t, err)
			f.args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).AddActiveFlags(common.AutoBalanceDataTriesFlag)
			addr := bytes.Clone(core.SystemAccountAddress)
			if destination == "family" {
				addr[31] = 0
			}
			if destination == "ordinary" {
				addr = bytes.Clone(f.address)
			}
			dst, err := f.adb.LoadAccount(addr)
			require.NoError(t, err)
			// Existing empty family destination is permitted by the native migrator.
			fn, err := builtInFunctions.NewMigrateDataTrieFunc(vmcommon.BuiltInCost{TrieLoadPerNode: 1, TrieStorePerNode: 1}, f.args.EnableEpochsHandler, f.adb)
			require.NoError(t, err)
			out, err := fn.ProcessBuiltinFunction(nil, dst.(vmcommon.UserAccountHandler), &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallValue: big.NewInt(0), GasProvided: 1000000}, RecipientAddr: addr})
			require.NoError(t, err)
			require.Equal(t, vmcommon.Ok, out.ReturnCode)
			require.NoError(t, f.adb.SaveAccount(dst))
			_, err = f.adb.Commit()
			require.NoError(t, err)
			present, err := s.membership(token)
			require.NoError(t, err)
			require.True(t, present)
			a, err = f.adb.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			value, _, err := a.(state.UserAccountHandler).RetrieveValue(key)
			require.NoError(t, err)
			require.Equal(t, []byte{1}, value, "exact typed bytes survive native representation change")
			value, _, err = a.(state.UserAccountHandler).RetrieveValue([]byte("ELRONDDRWA@membershipIndex@count"))
			require.NoError(t, err)
			require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 1}, value)
			value, _, err = a.(state.UserAccountHandler).RetrieveValue(qualIndexLiteralEntry(0))
			require.NoError(t, err)
			require.Equal(t, token, value)
			value, _, err = a.(state.UserAccountHandler).RetrieveValue([]byte("ordinary-existing-leaf"))
			require.NoError(t, err)
			require.Equal(t, []byte("untouched"), value)
			// Migration may change the current physical root; the old authenticated
			// leaf and its interpretation remain verifiable at the retained old root.
			valid, err := oldTrie.VerifyProof(oldDataRoot, key, proof)
			require.NoError(t, err)
			require.True(t, valid)
			require.NotEmpty(t, encodedOldLeaf)
			require.NoError(t, f.adb.RecreateTrie(holders.NewDefaultRootHashesHolder(oldRoot)))
			present, err = s.membership(token)
			require.NoError(t, err)
			require.True(t, present)
		})
	}
}

func TestQualDRWAProtectedStateNativeKeyDomains(t *testing.T) {
	key, err := membershipKey([]byte("TOKEN-000001"))
	require.NoError(t, err)
	require.False(t, vmcommon.IsAllowedToSaveUnderKey(key))
	require.False(t, process.IsAllowedToSaveUnderKey(key))
	for _, prefix := range []string{"ELRONDesdt", "ELRONDroleesdt", "ELRONDnonce", "ELRONDtransferesdt", "ELRONDguardians", "ELRONDreward", "ELRONDVM@"} {
		require.False(t, bytes.HasPrefix(key, []byte(prefix)), prefix)
		require.False(t, bytes.HasPrefix([]byte(prefix), []byte(membershipKeyPrefix)), prefix)
	}
	// Arbitrary caller-controlled suffixes cannot escape an already-disjoint
	// native constructor prefix; no reserved ordinary-key pattern is added.
	for _, suffix := range [][]byte{key, []byte("@"), {0}, {255}} {
		require.False(t, bytes.HasPrefix(append([]byte("ELRONDesdt"), suffix...), []byte(membershipKeyPrefix)))
	}
}

func TestQualDRWAProtectedStatePublicStorage(t *testing.T) {
	f, s := qualProtectedFixture(t, false)
	token := []byte("TOKEN-000001")
	require.NoError(t, s.materializeMembership(token))
	_, err := f.adb.Commit()
	require.NoError(t, err)
	key, err := membershipKey(token)
	require.NoError(t, err)
	fn, err := builtInFunctions.NewSaveKeyValueStorageFunc(vmcommon.BaseOperationCost{}, 1, f.args.EnableEpochsHandler)
	require.NoError(t, err)
	// All 65536 native 32-byte system-family addresses, not a sampled suffix.
	for suffix := 0; suffix < 65536; suffix++ {
		address := bytes.Clone(core.SystemAccountAddress)
		address[30], address[31] = byte(suffix>>8), byte(suffix)
		a, loadErr := f.adb.LoadAccount(address)
		require.NoError(t, loadErr)
		out, callErr := fn.ProcessBuiltinFunction(nil, a.(vmcommon.UserAccountHandler), &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{CallerAddr: address, CallValue: big.NewInt(0), GasProvided: 1000, Arguments: [][]byte{key, {0}}}, RecipientAddr: address})
		require.ErrorIs(t, callErr, builtInFunctions.ErrOperationNotPermitted)
		require.Nil(t, out)
	}
	present, err := s.membership(token)
	require.NoError(t, err)
	require.True(t, present)
	require.Zero(t, f.adb.JournalLen())
	// Ordinary lookalike remains writable; no new global reserved namespace.
	a, err := f.adb.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	ordinary := []byte("DRWA@membership@TOKEN-000001")
	out, err := fn.ProcessBuiltinFunction(nil, a.(vmcommon.UserAccountHandler), &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(core.SystemAccountAddress), CallValue: big.NewInt(0), GasProvided: 1000, Arguments: [][]byte{ordinary, []byte("public")}}, RecipientAddr: bytes.Clone(core.SystemAccountAddress)})
	require.NoError(t, err)
	require.Equal(t, uint64(999), out.GasRemaining)
	present, err = s.membership(token)
	require.NoError(t, err)
	require.True(t, present)
}
