package systemSmartContracts

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// Structural coupling follows the existing native registration owner; no
// System-SC/process dependency cycle or public Execute case is introduced.
type drwaBootstrapCancellationOwner interface {
	CancelBootstrapRegistration(tokenID, intentID, paProof, independentProof, stateProof []byte,
		nativeProof func(state.AccountsAdapter, []byte, []byte, []byte) ([]byte, error)) error
	IsInterfaceNil() bool
}

// cancelDRWABootstrapToken supplies the actual native no-supply/no-role record
// under the same exclusive native execution lock as registration. The owning
// DRWA component additionally requires canonical no setup/SupplyState/OpenEffect
// proof and exact independent scoped cancellation approvals. This local native
// record alone cannot prove all execution-shard NFT state or lawful authority.
// It must be dispatched outside ordinary Execute's read lock when installed.
func (e *esdt) cancelDRWABootstrapToken(owner drwaBootstrapCancellationOwner,
	tokenID, intentID, paProof, independentProof, stateProof []byte) (err error) {
	e.mutExecution.Lock()
	defer e.mutExecution.Unlock()
	context, native := e.eei.(*vmContext)
	if !native || context == nil || check.IfNil(owner) || !bytes.Equal(e.esdtSCAddress, core.ESDTSCAddress) ||
		!bytes.Equal(context.scAddress, core.ESDTSCAddress) || len(context.storageUpdate) != 0 ||
		len(context.outputAccounts) != 0 || len(context.output) != 0 || len(context.logs) != 0 {
		return errInvalidDRWARegistration
	}
	original := e.eei
	originalOutput, originalLogs := context.output, context.logs
	defer func() {
		e.eei = original
		if err != nil {
			context.CleanStorageUpdates()
			context.outputAccounts = make(map[string]*vmcommon.OutputAccount)
			context.output, context.logs = originalOutput, originalLogs
		}
	}()
	return owner.CancelBootstrapRegistration(tokenID, intentID, paProof, independentProof, stateProof,
		func(accounts state.AccountsAdapter, tokenID, manager, family []byte) ([]byte, error) {
			if context.userAccountsDB != accounts || len(context.storageUpdate) != 0 ||
				len(context.outputAccounts) != 0 || len(context.output) != 0 || len(context.logs) != 0 {
				return nil, errInvalidDRWARegistration
			}
			strict := &drwaRegistrationEI{SystemEI: original, context: context, accounts: accounts}
			e.eei = strict
			token, err := e.getExistingToken(tokenID)
			if strict.readErr != nil {
				return nil, strict.readErr
			}
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(token.OwnerAddress, manager) || !bytes.Equal(token.TokenType, family) ||
				token.MintedValue == nil || token.BurntValue == nil || token.MintedValue.Sign() != 0 || token.BurntValue.Sign() != 0 ||
				len(token.SpecialRoles) != 0 || token.IsPaused || token.NFTCreateStopped || token.NumWiped != 0 {
				return nil, errInvalidDRWARegistration
			}
			encoded := strict.GetStorage(tokenID)
			if strict.readErr != nil {
				return nil, strict.readErr
			}
			return bytes.Clone(encoded), nil
		})
}
