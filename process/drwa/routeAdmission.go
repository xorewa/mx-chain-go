package drwa

import (
	"bytes"
	"sync"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	nativeBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
)

// routeNativeResolver binds the existing native loader to this operation's
// guarded accounts. It supplies no classification or policy authority.
type routeNativeResolver func(vmcommon.AccountsAdapter, *vmcommon.ContractCallInput) (vmcommon.UserAccountHandler, vmcommon.UserAccountHandler, error)

// routeNativeOperation is a DRWA-defined, single-use binding of the native
// constructor and parse seam to the existing guard (Part A P-05 and 5.5). The
// actual route must supply its admitted context/policy, stable dependencies and
// enclosing native B owner. It is not installed in a dispatcher by itself.
type routeNativeOperation struct {
	mut         sync.Mutex
	used        bool
	running     bool
	name        string
	guard       *routeNativeGuard
	accounts    *routeNativeAccounts
	coordinator vmcommon.Coordinator
	function    vmcommon.BuiltinFunctionWithESDTTransferGate
	store       vmcommon.AccountsAdapter
	storage     vmcommon.SimpleESDTNFTStorageHandler
}

func newRouteNativeOperation(args nativeBuiltins.ArgsCreateBuiltInFunctionContainer, name string,
	payable func(vmcommon.AccountsAdapter) (vmcommon.PayableHandler, error),
) (*routeNativeOperation, error) {
	switch name {
	case core.BuiltInFunctionESDTTransfer, core.BuiltInFunctionESDTNFTTransfer, core.BuiltInFunctionMultiESDTNFTTransfer:
	default:
		return nil, errRouteNativeGuard
	}
	store := args.Accounts
	g, accounts, err := newRouteNativeGuard(store)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*routeNativeOperation, error) {
		if observed := g.finish(); observed != nil {
			return nil, observed
		}
		return nil, cause
	}
	args.Accounts = accounts
	// Reuse the real factory: its global-settings, NFT-storage and transfer
	// dependencies all receive the same guarded adapter. Unlike the ordinary
	// process factory, this short-lived graph registers no schedule subscriber.
	creator, err := nativeBuiltins.NewBuiltInFunctionsCreator(args)
	if err != nil {
		return fail(err)
	}
	if err = creator.CreateBuiltInFunctionContainer(); err != nil {
		return fail(err)
	}
	if payable == nil {
		return fail(errRouteNativeGuard)
	}
	handler, err := payable(accounts)
	if err != nil {
		return fail(err)
	}
	if err = creator.SetPayableHandler(handler); err != nil {
		return fail(err)
	}
	function, err := creator.BuiltInFunctionContainer().Get(name)
	if err != nil {
		return fail(err)
	}
	typed, found := function.(vmcommon.BuiltinFunctionWithESDTTransferGate)
	if !found || check.IfNil(typed) {
		return fail(errRouteNativeGuard)
	}
	if g.first != nil {
		return fail(g.first)
	}
	return &routeNativeOperation{name: name, guard: g, accounts: accounts, coordinator: args.ShardCoordinator,
		function: typed, store: store, storage: creator.NFTStorageHandler()}, nil
}

func (o *routeNativeOperation) bindUser(user vmcommon.UserAccountHandler, address []byte) error {
	local := o.coordinator.ComputeId(address) == o.coordinator.SelfId()
	if check.IfNil(user) {
		if local {
			return errRouteNativeGuard
		}
		return nil
	}
	wrapped, found := user.(*routeNativeUser)
	if !found || wrapped.guard != o.guard || !local || !bytes.Equal(user.AddressBytes(), address) {
		return errRouteNativeGuard
	}
	return nil
}

// execute includes the original hook's final account saves. Its caller encloses
// this ENTIRE operation in the actual B journal/output/gas boundary. No output on
// error is publishable; this component neither rolls back nor commits a store.
func (o *routeNativeOperation) execute(input *vmcommon.ContractCallInput, policy vmcommon.ESDTTransferGate,
	resolve routeNativeResolver,
) (output *vmcommon.VMOutput, parsed *vmcommon.ParsedESDTTransfers, err error) {
	return o.run(input, policy, resolve, nil)
}

// executeOwnedPositions joins the same-shard, single-token preserve route
// (including repeated native legs) to the supplied original owner. The
// original route must already have authenticated the operation and policy.
func (o *routeNativeOperation) executeOwnedPositions(operation *rollbackOperation, reader *setupLocalStateReader,
	header *HeaderTimeContext, input *vmcommon.ContractCallInput, policy vmcommon.ESDTTransferGate,
	resolve routeNativeResolver, binding positionTransferBinding) (output *vmcommon.VMOutput, parsed *vmcommon.ParsedESDTTransfers, err error) {
	if o == nil || reader == nil || reader.current == nil {
		return nil, nil, errSetupLocalState
	}
	db, ok := o.store.(*state.AccountsDB)
	if !ok || db == nil || db != reader.current.current.codec.state.accounts {
		return nil, nil, errSetupLocalState
	}
	err = operation.withWrite(reader.current.boundary, db, func() error {
		var e error
		output, e = reader.withInitializedState(header, binding.token, binding.epoch, binding.cebHash,
			func(view lifecycleReadView, local localSetupState) (*vmcommon.VMOutput, error) {
				if view.activation != "Active" || view.lifecycle != "OPEN" || local.positions == nil ||
					operation.positionJoinUsed || !validWriteLeafVersion(binding.leafVersion) ||
					binding.maxKeys <= 0 || binding.maxLegs <= 0 {
					return nil, errSetupLocalState
				}
				operation.positionJoinUsed = true
				version := *binding.leafVersion
				binding.leafVersion = &version
				write := &nativePositionTransfer{reader: reader, db: db, local: local, binding: binding}
				var out *vmcommon.VMOutput
				var runErr error
				out, parsed, runErr = o.run(input, policy, resolve, write)
				return out, runErr
			})
		return e
	})
	if err != nil {
		return nil, nil, err
	}
	return output, parsed, nil
}

func (o *routeNativeOperation) run(input *vmcommon.ContractCallInput, policy vmcommon.ESDTTransferGate,
	resolve routeNativeResolver, write *nativePositionTransfer,
) (output *vmcommon.VMOutput, parsed *vmcommon.ParsedESDTTransfers, err error) {
	o.mut.Lock()
	if o.running {
		o.mut.Unlock()
		return nil, nil, ErrExecutionBusy
	}
	if o.used {
		o.mut.Unlock()
		return nil, nil, ErrExecutionClosed
	}
	o.used, o.running = true, true
	o.mut.Unlock()
	defer func() {
		if observed := o.guard.finish(); observed != nil {
			err = observed
		}
		if err != nil {
			output = nil
		}
		o.mut.Lock()
		o.running = false
		o.mut.Unlock()
	}()
	if input == nil {
		return nil, nil, process.ErrNilVmInput
	}
	if input.Function != o.name || check.IfNil(policy) || resolve == nil {
		return nil, nil, errRouteNativeGuard
	}
	gate := &routeNativeOperationGate{operation: o, policy: policy, write: write}
	var sender, receiver vmcommon.UserAccountHandler
	sameAccount := bytes.Equal(input.CallerAddr, input.RecipientAddr)
	resolver := func(snapshot *vmcommon.ContractCallInput, regulated bool) (vmcommon.UserAccountHandler, vmcommon.UserAccountHandler, error) {
		if !regulated || snapshot == nil {
			return nil, nil, errRouteNativeGuard
		}
		// The resolver receives a detached input view, but may mutate it. Bind
		// returned accounts to the native input identities captured before calling it.
		caller, recipient := bytes.Clone(snapshot.CallerAddr), bytes.Clone(snapshot.RecipientAddr)
		var loadError error
		sender, receiver, loadError = resolve(o.accounts, snapshot)
		if o.guard.first != nil {
			return nil, nil, o.guard.first
		}
		if loadError != nil {
			return nil, nil, loadError
		}
		if e := o.bindUser(sender, caller); e != nil {
			return nil, nil, e
		}
		if e := o.bindUser(receiver, recipient); e != nil {
			return nil, nil, e
		}
		if sameAccount && !check.IfNil(sender) && sender != receiver {
			return nil, nil, errRouteNativeGuard
		}
		return sender, receiver, nil
	}
	output, parsed, err = o.function.ProcessBuiltinFunctionWithESDTTransferGate(input, resolver, gate)
	if o.guard.first != nil {
		return nil, parsed, o.guard.first
	}
	if err != nil {
		return nil, parsed, err
	}
	if !gate.checked || output == nil || output.ReturnCode != vmcommon.Ok {
		return nil, parsed, errRouteNativeGuard
	}
	if !check.IfNil(sender) {
		if err = o.accounts.SaveAccount(sender); err != nil {
			return nil, parsed, err
		}
	}
	if !check.IfNil(receiver) && !sameAccount {
		if err = o.accounts.SaveAccount(receiver); err != nil {
			return nil, parsed, err
		}
	}
	if write != nil {
		if err = write.finish(o); err != nil {
			return nil, nil, err
		}
	}
	return output, parsed, nil
}

type routeNativeOperationGate struct {
	operation *routeNativeOperation
	policy    vmcommon.ESDTTransferGate
	write     *nativePositionTransfer
	checked   bool
}

func (g *routeNativeOperationGate) Classify(function string, identifiers [][]byte) (bool, error) {
	var regulated bool
	err := g.checkPolicy(func() error {
		var e error
		regulated, e = g.policy.Classify(function, identifiers)
		return e
	})
	if g.operation.guard.first != nil {
		return false, g.operation.guard.first
	}
	if err != nil {
		return false, err
	}
	// Ordinary calls must continue through the untouched process-wide graph.
	// This already-regulated component must never become an ordinary fallback.
	if !regulated || function != g.operation.name {
		return false, errRouteNativeGuard
	}
	return true, nil
}

func (g *routeNativeOperationGate) CheckTransfer(function string, source []byte, parsed *vmcommon.ParsedESDTTransfers, input *vmcommon.ContractCallInput) error {
	if g.operation.guard.first != nil {
		return g.operation.guard.first
	}
	if g.checked || function != g.operation.name {
		return errRouteNativeGuard
	}
	if g.write != nil {
		if err := g.write.prepare(g.operation, source, parsed); err != nil {
			return g.operation.guard.observe(err)
		}
	}
	err := g.checkPolicy(func() error { return g.policy.CheckTransfer(function, source, parsed, input) })
	if g.operation.guard.first != nil {
		return g.operation.guard.first
	}
	if err != nil {
		return err
	}
	if err = g.operation.guard.admit(); err != nil {
		return err
	}
	g.checked = true
	return nil
}

func (g *routeNativeOperationGate) checkPolicy(check func() error) error {
	if g.write == nil {
		return check()
	}
	return verifyRegistrationState(g.write.reader.current.boundary.stores, check)
}

func (g *routeNativeOperationGate) IsInterfaceNil() bool { return g == nil }
