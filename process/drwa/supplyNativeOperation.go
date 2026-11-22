package drwa

import (
	"bytes"
	"math/big"
	"sync"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	nativeBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
)

// supplyExistingAccounts makes native loading non-creating. Supply executes at
// an existing origin and existing native system state; it cannot materialize an
// account while reading roles, metadata or policy before the first-effect gate.
type supplyExistingAccounts struct{ vmcommon.AccountsAdapter }

func (a *supplyExistingAccounts) LoadAccount(address []byte) (vmcommon.AccountHandler, error) {
	return a.AccountsAdapter.GetExistingAccount(address)
}

// supplyNativeOperation adapts the existing routeNativeGuard and real native
// factory for ONE already-regulated local supply invocation. It owns no journal,
// parser, supply ledger or authority. The configured native owner must enclose
// construction AND execute in its original boundary and bind its protocol-only
// verified supply context, replay/counters, roots, gas and output publication.
// This component is not a public dispatcher or an unsigned-burn adapter.
type supplyNativeOperation struct {
	mut         sync.Mutex
	used        bool
	running     bool
	name        string
	guard       *routeNativeGuard
	accounts    *routeNativeAccounts
	coordinator vmcommon.Coordinator
	function    vmcommon.BuiltinFunctionWithDRWASupplyGate
	store       vmcommon.AccountsAdapter
	storage     vmcommon.SimpleESDTNFTStorageHandler
}

func newSupplyNativeOperation(args nativeBuiltins.ArgsCreateBuiltInFunctionContainer, name string) (*supplyNativeOperation, error) {
	switch name {
	case core.BuiltInFunctionESDTLocalMint, core.BuiltInFunctionESDTLocalBurn,
		core.BuiltInFunctionESDTNFTCreate, core.BuiltInFunctionESDTNFTAddQuantity, core.BuiltInFunctionESDTNFTBurn:
	default:
		return nil, errRouteNativeGuard
	}
	if check.IfNil(args.Accounts) {
		return nil, errRouteNativeGuard
	}
	store := args.Accounts
	g, accounts, err := newRouteNativeGuard(&supplyExistingAccounts{store})
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*supplyNativeOperation, error) {
		if observed := g.finish(); observed != nil {
			return nil, observed
		}
		return nil, cause
	}
	args.Accounts = accounts
	// As with routeNativeOperation, use the actual native constructor without a
	// process-wide gas subscriber or an alternate role/storage implementation.
	creator, err := nativeBuiltins.NewBuiltInFunctionsCreator(args)
	if err != nil {
		return fail(err)
	}
	if err = creator.CreateBuiltInFunctionContainer(); err != nil {
		return fail(err)
	}
	function, err := creator.BuiltInFunctionContainer().Get(name)
	if err != nil {
		return fail(err)
	}
	typed, found := function.(vmcommon.BuiltinFunctionWithDRWASupplyGate)
	if !found || check.IfNil(typed) {
		return fail(errRouteNativeGuard)
	}
	if g.first != nil {
		return fail(g.first)
	}
	return &supplyNativeOperation{name: name, guard: g, accounts: accounts,
		coordinator: args.ShardCoordinator, function: typed, store: store, storage: creator.NFTStorageHandler()}, nil
}

func (o *supplyNativeOperation) bindLocal(user vmcommon.UserAccountHandler, address []byte) error {
	if check.IfNil(user) || o.coordinator.ComputeId(address) != o.coordinator.SelfId() {
		return errRouteNativeGuard
	}
	u, found := user.(*routeNativeUser)
	if !found || u.guard != o.guard || !bytes.Equal(user.AddressBytes(), address) {
		return errRouteNativeGuard
	}
	return nil
}

func (o *supplyNativeOperation) execute(input *vmcommon.ContractCallInput, policy vmcommon.DRWASupplyGate,
	resolve routeNativeResolver) (output *vmcommon.VMOutput, err error) {
	return o.run(input, policy, resolve, nil)
}

// executeOwned joins the direct, origin-signed native route to the original
// journal. The caller passes the writer parameters from its verified CEB and
// supply authorization, and the existing policy still checks the native parse.
// The terminal relayer path requires its own authenticated native owner.
func (o *supplyNativeOperation) executeOwned(operation *rollbackOperation, reader *setupLocalStateReader,
	header *HeaderTimeContext, input *vmcommon.ContractCallInput, policy vmcommon.DRWASupplyGate,
	resolve routeNativeResolver, binding supplyWriteBinding) (output *vmcommon.VMOutput, err error) {
	if o == nil || reader == nil || reader.current == nil {
		return nil, errSupplyAccounting
	}
	db, ok := o.store.(*state.AccountsDB)
	if !ok || db == nil || db != reader.current.current.codec.state.accounts {
		return nil, errSupplyAccounting
	}
	err = operation.withWrite(reader.current.boundary, db, func() error {
		var e error
		output, e = reader.withInitializedState(header, binding.token, binding.epoch, binding.cebHash,
			func(view lifecycleReadView, local localSetupState) (*vmcommon.VMOutput, error) {
				if input == nil || !bytes.Equal(input.CallerAddr, view.supplyOrigin) ||
					!bytes.Equal(input.RecipientAddr, view.supplyOrigin) || local.supply == nil ||
					view.supplyOriginShard != o.coordinator.SelfId() || view.activation != "Active" ||
					(view.lifecycle != "SETUP" && view.lifecycle != "OPEN") {
					return nil, errSupplyAccounting
				}
				if local.positions != nil {
					if operation.positionJoinUsed {
						return nil, errSetupLocalState
					}
					operation.positionJoinUsed = true
				}
				if binding.leafVersion != nil {
					version := *binding.leafVersion
					binding.leafVersion = &version
				}
				maxBytes := reader.records.maxAmountBytes
				for _, cap := range []**big.Int{&binding.cumulativeCap, &binding.nonceCap} {
					if *cap != nil {
						if !supplyIntegerFits(*cap, maxBytes) {
							return nil, errSupplyAccounting
						}
						*cap = new(big.Int).Set(*cap)
					}
				}
				write := &supplyNativeWrite{reader: reader, db: db, local: local, binding: binding}
				return o.run(input, policy, resolve, write)
			})
		return e
	})
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (o *supplyNativeOperation) run(input *vmcommon.ContractCallInput, policy vmcommon.DRWASupplyGate,
	resolve routeNativeResolver, write *supplyNativeWrite) (output *vmcommon.VMOutput, err error) {
	o.mut.Lock()
	if o.running {
		o.mut.Unlock()
		return nil, ErrExecutionBusy
	}
	if o.used {
		o.mut.Unlock()
		return nil, ErrExecutionClosed
	}
	o.used, o.running = true, true
	o.mut.Unlock()
	defer func() {
		if first := o.guard.finish(); first != nil {
			err = first
		}
		if err != nil {
			output = nil
		}
		o.mut.Lock()
		o.running = false
		o.mut.Unlock()
	}()
	if input == nil {
		return nil, process.ErrNilVmInput
	}
	if input.Function != o.name || check.IfNil(policy) || resolve == nil {
		return nil, errRouteNativeGuard
	}
	sameAccount := bytes.Equal(input.CallerAddr, input.RecipientAddr)
	gate := &supplyNativeOperationGate{operation: o, policy: policy, write: write}
	var sender, receiver vmcommon.UserAccountHandler
	resolver := func(snapshot *vmcommon.ContractCallInput, regulated bool) (vmcommon.UserAccountHandler, vmcommon.UserAccountHandler, error) {
		if !regulated || snapshot == nil {
			return nil, nil, errRouteNativeGuard
		}
		caller, recipient := bytes.Clone(snapshot.CallerAddr), bytes.Clone(snapshot.RecipientAddr)
		var loadError error
		sender, receiver, loadError = resolve(o.accounts, snapshot)
		if o.guard.first != nil {
			return nil, nil, o.guard.first
		}
		if loadError != nil {
			return nil, nil, loadError
		}
		if e := o.bindLocal(sender, caller); e != nil {
			return nil, nil, e
		}
		if e := o.bindLocal(receiver, recipient); e != nil {
			return nil, nil, e
		}
		if sameAccount && sender != receiver {
			return nil, nil, errRouteNativeGuard
		}
		gate.origin = sender
		return sender, receiver, nil
	}
	output, err = o.function.ProcessBuiltinFunctionWithDRWASupplyGate(input, resolver, gate)
	if o.guard.first != nil {
		return nil, o.guard.first
	}
	if err != nil {
		return nil, err
	}
	if !gate.checked || output == nil || output.ReturnCode != vmcommon.Ok {
		return nil, errRouteNativeGuard
	}
	if err = o.accounts.SaveAccount(sender); err != nil {
		return nil, err
	}
	if !sameAccount {
		if err = o.accounts.SaveAccount(receiver); err != nil {
			return nil, err
		}
	}
	if write != nil {
		if err = write.finish(o, sender, output); err != nil {
			return nil, err
		}
	}
	return output, nil
}

type supplyNativeOperationGate struct {
	operation *supplyNativeOperation
	policy    vmcommon.DRWASupplyGate
	write     *supplyNativeWrite
	origin    vmcommon.UserAccountHandler
	checked   bool
}

func (g *supplyNativeOperationGate) ClassifySupply(function string, token []byte) (bool, error) {
	var regulated bool
	err := g.checkPolicy(func() error {
		var e error
		regulated, e = g.policy.ClassifySupply(function, token)
		return e
	})
	if g.operation.guard.first != nil {
		return false, g.operation.guard.first
	}
	if err != nil {
		return false, err
	}
	if !regulated || function != g.operation.name {
		return false, errRouteNativeGuard
	}
	return true, nil
}

func (g *supplyNativeOperationGate) CheckSupply(function string, effect vmcommon.DRWASupplyEffect, input *vmcommon.ContractCallInput) error {
	if g.operation.guard.first != nil {
		return g.operation.guard.first
	}
	if g.checked || function != g.operation.name {
		return errRouteNativeGuard
	}
	// The policy gets detached buffers. Preserve the exact native effect for
	// the journal even if the verifier alters its view.
	native := effect
	if g.write != nil {
		if !supplyIntegerFits(effect.Quantity, g.write.reader.records.maxAmountBytes) {
			return errSupplyAccounting
		}
		native.TokenIdentifier, native.RoleAddress = bytes.Clone(effect.TokenIdentifier), bytes.Clone(effect.RoleAddress)
		native.Quantity = new(big.Int).Set(effect.Quantity)
	}
	if err := g.checkPolicy(func() error { return g.policy.CheckSupply(function, effect, input) }); err != nil {
		return err
	}
	if err := g.operation.guard.admit(); err != nil {
		return err
	}
	if g.write != nil {
		if err := g.write.prepare(g.operation, g.origin, native); err != nil {
			return g.operation.guard.observe(err)
		}
	}
	g.checked = true
	return nil
}

func (g *supplyNativeOperationGate) checkPolicy(check func() error) error {
	if g.write == nil {
		return check()
	}
	return verifyRegistrationState(g.write.reader.current.boundary.stores, check)
}

func (g *supplyNativeOperationGate) IsInterfaceNil() bool { return g == nil }
