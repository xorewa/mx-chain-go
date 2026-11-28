package processing

import (
	"github.com/multiversx/mx-chain-core-go/core/check"

	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
)

// drwaHeaderTimeSource is the one production way to obtain the time source of
// a DRWA time consumer (Part A N-02/M-04). It returns the block-chain hook of
// a processing VM factory itself: the object in which the block processor
// installs the evaluated header of the block in execution and ends it with
// that block. Nothing else is accepted:
//   - the hook must be the native hook, not a wrapper, stub or second clock;
//   - it must own the accounts adapter the consumer writes, so a consumer
//     cannot be given the hook of another store (API, simulation, genesis);
//   - it must have been constructed with the per-header activation predicate,
//     so the typed view follows the candidate header's epoch and round.
//
// Every later row that constructs a time consumer in production obtains its
// source here and passes it unchanged.
func drwaHeaderTimeSource(hook process.BlockChainHookWithAccountsAdapter, accounts state.AccountsAdapter) (drwa.HeaderTimeSource, error) {
	native, ok := hook.(*hooks.BlockChainHookImpl)
	if !ok || native == nil || check.IfNil(accounts) || native.GetAccountsAdapter() != accounts || !native.DRWAHeaderTimeBound() {
		return nil, vm.ErrDRWAExecution
	}
	return native, nil
}
