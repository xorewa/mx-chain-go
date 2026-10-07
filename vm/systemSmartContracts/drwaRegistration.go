package systemSmartContracts

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// drwaRegistrationOwner is the DRWA atomic writer contract. Structural typing
// avoids a System-SC dependency on process/drwa (its consumers include System-SC
// integration tests). It is production coupling, not a qualification seam.
type drwaRegistrationOwner interface {
	RegisterToken(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error
	IsInterfaceNil() bool
}

var errInvalidDRWARegistration = errors.New("invalid DRWA native creation")

// drwaTokenCreation is a construction input, not a wire encoding or admission
// certificate. The eventual protected endpoint must first authenticate T14's
// exact live intent, fresh approvals, current support/profile and enforcement
// epoch, and include intent consumption, BootstrapDeny and immutable association
// in this same journal. No ordinary Execute case invokes this component.
type drwaTokenCreation struct {
	issuer, manager, name, ticker, family []byte
	decimals                              uint32
	properties                            [][]byte
}

// drwaRegistrationEI retains native overlay semantics but reads native storage
// errors explicitly. The ordinary vmContext intentionally turns a hook error
// into absence; registration must not overwrite an unavailable token record.
// This adapter is installed only for the new private DRWA operation, with native
// execution exclusively locked; it is restored before returning.
type drwaRegistrationEI struct {
	vm.SystemEI
	context  *vmContext
	accounts state.AccountsAdapter
	readErr  error
}

func (s *drwaRegistrationEI) GetStorage(key []byte) []byte {
	if values := s.context.storageUpdate[string(core.ESDTSCAddress)]; values != nil {
		if value, exists := values[string(key)]; exists {
			return value
		}
	}
	account, err := s.accounts.GetExistingAccount(core.ESDTSCAddress)
	if err != nil {
		s.readErr = err
		return nil
	}
	user, _ := account.(state.UserAccountHandler)
	if check.IfNil(user) || !bytes.Equal(user.AddressBytes(), core.ESDTSCAddress) {
		s.readErr = errInvalidDRWARegistration
		return nil
	}
	value, _, err := user.RetrieveValue(key)
	if err != nil {
		s.readErr = err
		return nil
	}
	return value
}

// registerDRWAToken is the unwired native creation/count core, not the complete
// public DRWARegisterToken endpoint. Part A L2195-2197 requires direct reuse of
// createNewToken, not ordinary issue validation. Its caller owns authenticated
// admission, native issuance-fee economics and the full atomic registration
// record bundle. No profile, address, fee or encoding is allocated here.
//
// The retained immutable properties are checked before any native account save.
// E10 uses the permitted same-operation native burn-role removal candidate. The
// native set/type/unset fan-out remains pending; T44 must prove materialization
// and ordering before every receiving effect, and activation still needs all
// shard false-state ACKs. This component alone does not close that proof.
func (e *esdt) registerDRWAToken(registration drwaRegistrationOwner, request drwaTokenCreation) (err error) {
	e.mutExecution.Lock()
	defer e.mutExecution.Unlock()
	context, ok := e.eei.(*vmContext)
	if !ok || check.IfNil(registration) || !bytes.Equal(e.esdtSCAddress, core.ESDTSCAddress) ||
		!bytes.Equal(context.scAddress, core.ESDTSCAddress) || len(context.storageUpdate) != 0 ||
		len(context.outputAccounts) != 0 || len(context.output) != 0 || len(context.logs) != 0 ||
		len(request.issuer) != e.addressPubKeyConverter.Len() || len(request.manager) != e.addressPubKeyConverter.Len() ||
		request.decimals < minNumberOfDecimals || request.decimals > maxNumberOfDecimals {
		return errInvalidDRWARegistration
	}
	switch string(request.family) {
	case core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT,
		core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT:
	default:
		return errInvalidDRWARegistration
	}
	original := e.eei
	defer func() {
		e.eei = original
		if err != nil {
			// No pending success output or local overlay survives failed creation
			// or a later registry save. Keep native gas and error-message facts.
			context.CleanStorageUpdates()
			context.outputAccounts = make(map[string]*vmcommon.OutputAccount)
			context.output = nil
			context.logs = nil
		}
	}()
	return registration.RegisterToken(func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		if context.userAccountsDB != accounts {
			return nil, nil, errInvalidDRWARegistration
		}
		strict := &drwaRegistrationEI{SystemEI: original, context: context, accounts: accounts}
		e.eei = strict
		identifier, token, createErr := e.createNewToken(bytes.Clone(request.issuer), bytes.Clone(request.name),
			bytes.Clone(request.ticker), big.NewInt(0), request.decimals, request.properties, bytes.Clone(request.family))
		if strict.readErr != nil {
			return nil, nil, strict.readErr
		}
		if createErr != nil {
			return nil, nil, createErr
		}
		if token.Upgradable || !token.CanAddSpecialRoles || token.CanFreeze || token.CanWipe || token.CanPause ||
			token.CanChangeOwner || token.CanCreateMultiShard || token.CanTransferNFTCreateRole || token.Mintable || token.Burnable {
			return nil, nil, errInvalidDRWARegistration
		}
		if checkIfDefinedRoleExistsInToken(token, []byte(vmcommon.ESDTRoleBurnForAll)) {
			code := e.unsetBurnRoleGlobally(&vmcommon.ContractCallInput{
				VMInput:       vmcommon.VMInput{CallerAddr: bytes.Clone(request.issuer), CallValue: big.NewInt(0), Arguments: [][]byte{identifier}},
				RecipientAddr: core.ESDTSCAddress, Function: "unsetBurnRoleGlobally",
			})
			if code != vmcommon.Ok {
				return nil, nil, fmt.Errorf("%w: native burn normalization %s", errInvalidDRWARegistration, context.returnMessage)
			}
			token, createErr = e.getExistingToken(identifier)
			if createErr != nil || strict.readErr != nil {
				if strict.readErr != nil {
					return nil, nil, strict.readErr
				}
				return nil, nil, createErr
			}
		}
		token.OwnerAddress = bytes.Clone(request.manager)
		if createErr = e.saveToken(identifier, token); createErr != nil {
			return nil, nil, createErr
		}
		account, loadErr := accounts.GetExistingAccount(core.ESDTSCAddress)
		if loadErr != nil {
			return nil, nil, loadErr
		}
		user, _ := account.(state.UserAccountHandler)
		if check.IfNil(user) || !bytes.Equal(user.AddressBytes(), core.ESDTSCAddress) {
			return nil, nil, errInvalidDRWARegistration
		}
		// Check the actual journal-visible prestate, not the new VM overlay.
		old, _, readErr := user.RetrieveValue(identifier)
		if readErr != nil {
			return nil, nil, readErr
		}
		if len(old) != 0 {
			return nil, nil, errInvalidDRWARegistration
		}
		encoded := context.storageUpdate[string(core.ESDTSCAddress)][string(identifier)]
		if len(encoded) == 0 {
			return nil, nil, errInvalidDRWARegistration
		}
		if createErr = user.SaveKeyValue(identifier, encoded); createErr != nil {
			return nil, nil, createErr
		}
		if createErr = accounts.SaveAccount(user); createErr != nil {
			return nil, nil, createErr
		}
		// The native journal already owns the token write. Do not return it
		// again as an unapplied VM storage update to an outer executor. Only
		// the pending native fan-out/log/result output crosses this boundary.
		context.CleanStorageUpdates()
		context.Finish(bytes.Clone(identifier))
		output := context.CreateVMOutput()
		output.ReturnCode = vmcommon.Ok
		return identifier, output, nil
	})
}
