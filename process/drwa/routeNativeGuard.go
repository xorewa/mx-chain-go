package drwa

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

var errRouteNativeGuard = errors.New("invalid DRWA native transfer dependency phase")

// routeNativeGuard belongs to ONE synchronous regulated native operation. It
// retains original account/data errors that native metadata helpers may discard.
// The owning route must check it after policy evaluation and native execution,
// and return the failure through the actual native B rollback boundary.
// It supplies no policy, finality, funding, rollback or account-store owner.
// Ordinary operations never use this adapter. Instances must not be shared.
type routeNativeGuard struct {
	first    error
	admitted bool
	closed   bool
}

type routeNativeAccounts struct {
	vmcommon.AccountsAdapter
	guard *routeNativeGuard
}

func newRouteNativeGuard(accounts vmcommon.AccountsAdapter) (*routeNativeGuard, *routeNativeAccounts, error) {
	if check.IfNil(accounts) {
		return nil, nil, state.ErrNilAccountsAdapter
	}
	g := &routeNativeGuard{}
	return g, &routeNativeAccounts{AccountsAdapter: accounts, guard: g}, nil
}

func (g *routeNativeGuard) observe(err error) error {
	if err != nil && g.first == nil {
		g.first = err
	}
	return err
}

func (g *routeNativeGuard) admit() error {
	if g.first != nil {
		return g.first
	}
	if g.closed || g.admitted {
		return g.observe(errRouteNativeGuard)
	}
	g.admitted = true
	return nil
}

func (g *routeNativeGuard) write() error {
	if g.first != nil {
		return g.first
	}
	if !g.admitted || g.closed {
		return g.observe(errRouteNativeGuard)
	}
	return nil
}

func (g *routeNativeGuard) finish() error {
	g.closed = true
	return g.first
}

func (a *routeNativeAccounts) wrap(account vmcommon.AccountHandler, err error) (vmcommon.AccountHandler, error) {
	if err != nil {
		return nil, a.guard.observe(err)
	}
	u, ok := account.(vmcommon.UserAccountHandler)
	if !ok || check.IfNil(u) {
		return account, nil // Preserve the native consumer's type/nil error.
	}
	return &routeNativeUser{UserAccountHandler: u, guard: a.guard}, nil
}

func (a *routeNativeAccounts) LoadAccount(address []byte) (vmcommon.AccountHandler, error) {
	return a.wrap(a.AccountsAdapter.LoadAccount(address))
}

func (a *routeNativeAccounts) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	return a.wrap(a.AccountsAdapter.GetExistingAccount(address))
}

// RootHash can expose the native trie's cached hash. Callbacks receive a
// detached read view, and a discarded native read error still denies the operation.
func (a *routeNativeAccounts) RootHash() ([]byte, error) {
	root, err := a.AccountsAdapter.RootHash()
	return bytes.Clone(root), a.guard.observe(err)
}

func (a *routeNativeAccounts) SaveAccount(account vmcommon.AccountHandler) error {
	if err := a.guard.write(); err != nil {
		return err
	}
	u, ok := account.(*routeNativeUser)
	if !ok || u == nil || u.guard != a.guard {
		return a.guard.observe(errRouteNativeGuard)
	}
	return a.guard.observe(a.AccountsAdapter.SaveAccount(u.UserAccountHandler))
}

func (a *routeNativeAccounts) RemoveAccount(address []byte) error {
	if err := a.guard.write(); err != nil {
		return err
	}
	return a.guard.observe(a.AccountsAdapter.RemoveAccount(address))
}

// Native commit and rollback belong exclusively to the original enclosing owner.
func (a *routeNativeAccounts) Commit() ([]byte, error) {
	return nil, a.guard.observe(errRouteNativeGuard)
}

func (a *routeNativeAccounts) RevertToSnapshot(int) error {
	return a.guard.observe(errRouteNativeGuard)
}

type routeNativeUser struct {
	vmcommon.UserAccountHandler
	guard *routeNativeGuard
}

// Native byte getters expose mutable backing storage. Read views must not offer an
// alternate mutation path around the admission barrier.
func (u *routeNativeUser) AddressBytes() []byte {
	return bytes.Clone(u.UserAccountHandler.AddressBytes())
}
func (u *routeNativeUser) GetCodeMetadata() []byte {
	return bytes.Clone(u.UserAccountHandler.GetCodeMetadata())
}
func (u *routeNativeUser) GetCodeHash() []byte {
	return bytes.Clone(u.UserAccountHandler.GetCodeHash())
}
func (u *routeNativeUser) GetRootHash() []byte {
	return bytes.Clone(u.UserAccountHandler.GetRootHash())
}
func (u *routeNativeUser) GetOwnerAddress() []byte {
	return bytes.Clone(u.UserAccountHandler.GetOwnerAddress())
}
func (u *routeNativeUser) GetUserName() []byte {
	return bytes.Clone(u.UserAccountHandler.GetUserName())
}

func (u *routeNativeUser) AccountDataHandler() vmcommon.AccountDataHandler {
	return &routeNativeData{AccountDataHandler: u.UserAccountHandler.AccountDataHandler(), user: u}
}

func (u *routeNativeUser) AddToBalance(value *big.Int) error {
	if err := u.guard.write(); err != nil {
		return err
	}
	return u.guard.observe(u.UserAccountHandler.AddToBalance(value))
}

func (u *routeNativeUser) SubFromBalance(value *big.Int) error {
	if err := u.guard.write(); err != nil {
		return err
	}
	return u.guard.observe(u.UserAccountHandler.SubFromBalance(value))
}

func (u *routeNativeUser) ClaimDeveloperRewards(address []byte) (*big.Int, error) {
	if err := u.guard.write(); err != nil {
		return nil, err
	}
	value, err := u.UserAccountHandler.ClaimDeveloperRewards(address)
	return value, u.guard.observe(err)
}

func (u *routeNativeUser) ChangeOwnerAddress(sender, owner []byte) error {
	if err := u.guard.write(); err != nil {
		return err
	}
	return u.guard.observe(u.UserAccountHandler.ChangeOwnerAddress(sender, owner))
}

func (u *routeNativeUser) SetCodeMetadata(value []byte) {
	if u.guard.write() == nil {
		u.UserAccountHandler.SetCodeMetadata(value)
	}
}

func (u *routeNativeUser) SetOwnerAddress(value []byte) {
	if u.guard.write() == nil {
		u.UserAccountHandler.SetOwnerAddress(value)
	}
}

func (u *routeNativeUser) SetUserName(value []byte) {
	if u.guard.write() == nil {
		u.UserAccountHandler.SetUserName(value)
	}
}

func (u *routeNativeUser) IncreaseNonce(value uint64) {
	if u.guard.write() == nil {
		u.UserAccountHandler.IncreaseNonce(value)
	}
}

type routeNativeData struct {
	vmcommon.AccountDataHandler
	user *routeNativeUser
}

func (d *routeNativeData) RetrieveValue(key []byte) ([]byte, uint32, error) {
	value, depth, err := d.AccountDataHandler.RetrieveValue(key)
	// A native account with no data root has no data trie. Native ESDT readers
	// treat this exact condition as absence. It is not a missing/corrupt trie at
	// an existing authenticated root. Return the original error in both cases.
	if !(err == state.ErrNilTrie && len(d.user.GetRootHash()) == 0) {
		d.user.guard.observe(err)
	}
	return bytes.Clone(value), depth, err
}

func (d *routeNativeData) SaveKeyValue(key, value []byte) error {
	if err := d.user.guard.write(); err != nil {
		return err
	}
	return d.user.guard.observe(d.AccountDataHandler.SaveKeyValue(key, value))
}

func (d *routeNativeData) MigrateDataTrieLeaves(args vmcommon.ArgsMigrateDataTrieLeaves) error {
	if err := d.user.guard.write(); err != nil {
		return err
	}
	return d.user.guard.observe(d.AccountDataHandler.MigrateDataTrieLeaves(args))
}
