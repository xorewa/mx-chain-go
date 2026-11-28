package systemSmartContracts

import (
	"bytes"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// errDRWAManager refuses a protected manager operation that is not the exact
// verified admin mutation of a regulated token.
var errDRWAManager = errors.New("DRWA protected manager operation refused")

// drwaManagerSetSpecialRoleName names the mutation to the verified context:
// the native operation whose shared internal logic the protected path runs.
const drwaManagerSetSpecialRoleName = "setSpecialRole"

// drwaManagerContext is the protocol-only VerifiedDRWAAdminContext of Part A
// L3151-3161 as the ESDT system contract sees it. Only the native candidate
// owner supplies one; it is not built from a transaction's arguments, a
// caller address or a flag.
//
// VerifyManagerMutation authenticates the exact mutation: the token, the
// manager the token record holds (which must be the reserved manager the
// registration bound), the operation and its arguments, under the CEB state,
// certificates and governed action that apply. It is read-only.
//
// CarryManagerEffect is called after the metachain record is saved, inside the
// same native journal step: the context carries the mutation's shard effect by
// the protected admin leg (process/drwa AdminEffects). An error rolls the
// whole operation back.
type drwaManagerContext interface {
	VerifyManagerMutation(tokenID, manager []byte, operation string, arguments [][]byte) error
	CarryManagerEffect(tokenID []byte, operation string, arguments [][]byte) error
	IsInterfaceNil() bool
}

// drwaManagerSetSpecialRole is the reserved DRWA_SYSTEM_MANAGER path for a
// role grant (Part A L3156-3161, section 13 item 2): inside the metachain ESDT
// system contract, for a regulated token only, under a verified DRWA admin
// context only, it runs the shared internal role mutation of the native
// contract (setRolesForTokenAndAddress) and saves the record.
//
// It does not call the public setSpecialRole endpoint and forges no caller:
// the public endpoint keeps its own caller check and stays denied for a
// regulated token. It does not emit the native role fan-out either, which
// every shard refuses for a regulated token; the context carries the shard
// effect. Any refusal leaves the record, the outputs and the logs as they
// were.
func (e *esdt) drwaManagerSetSpecialRole(admin drwaManagerContext, tokenID, address []byte, roles [][]byte) (err error) {
	e.mutExecution.Lock()
	defer e.mutExecution.Unlock()
	context, native := e.eei.(*vmContext)
	if !native || check.IfNil(admin) || !context.drwaClassifierConfigured || check.IfNil(context.drwaClassifier) ||
		!bytes.Equal(e.esdtSCAddress, core.ESDTSCAddress) || !bytes.Equal(context.scAddress, core.ESDTSCAddress) ||
		!vmcommon.ValidateToken(tokenID) || len(roles) == 0 || !e.isAddressValid(address) {
		return errDRWAManager
	}
	arguments := append([][]byte{bytes.Clone(tokenID), bytes.Clone(address)}, roles...)
	entered := false
	_, err = context.drwaClassifier.WithTokenClassification(context.userAccountsDB, tokenID,
		func(regulated bool) (*vmcommon.VMOutput, error) {
			entered = true
			// The protected path administers regulated tokens only: an ordinary
			// token keeps its own manager and the public endpoints.
			if !regulated {
				return nil, errDRWAManager
			}
			return nil, e.drwaManagerRoleMutation(context, admin, tokenID, address, roles, arguments)
		})
	if err != nil && !entered {
		return errors.Join(errDRWAManager, err)
	}
	return err
}

func (e *esdt) drwaManagerRoleMutation(context *vmContext, admin drwaManagerContext, tokenID, address []byte, roles, arguments [][]byte) (err error) {
	storage, message := context.storageUpdate[string(core.ESDTSCAddress)][string(tokenID)], context.returnMessage
	stored := storage != nil
	outputs, logs := len(context.outputAccounts), len(context.logs)
	defer func() {
		if err == nil {
			return
		}
		// Nothing of a refused mutation remains: neither the record overlay nor
		// a native message.
		if stored {
			context.storageUpdate[string(core.ESDTSCAddress)][string(tokenID)] = storage
		} else if updates := context.storageUpdate[string(core.ESDTSCAddress)]; updates != nil {
			delete(updates, string(tokenID))
		}
		context.returnMessage = message
	}()
	token, err := e.getExistingToken(tokenID)
	if err != nil {
		return errors.Join(errDRWAManager, err)
	}
	if len(token.OwnerAddress) == 0 {
		return errDRWAManager
	}
	if err = admin.VerifyManagerMutation(bytes.Clone(tokenID), bytes.Clone(token.OwnerAddress), drwaManagerSetSpecialRoleName, arguments); err != nil {
		return errors.Join(errDRWAManager, err)
	}
	if _, code := e.setRolesForTokenAndAddress(token, address, roles); code != vmcommon.Ok {
		return errors.Join(errDRWAManager, errors.New(context.returnMessage))
	}
	if err = e.saveToken(tokenID, token); err != nil {
		return errors.Join(errDRWAManager, err)
	}
	if len(context.outputAccounts) != outputs || len(context.logs) != logs {
		// The shared internal mutation sends and logs nothing; anything here
		// would be a native fan-out for a regulated token.
		return errDRWAManager
	}
	if err = admin.CarryManagerEffect(bytes.Clone(tokenID), drwaManagerSetSpecialRoleName, arguments); err != nil {
		return errors.Join(errDRWAManager, err)
	}
	return nil
}
