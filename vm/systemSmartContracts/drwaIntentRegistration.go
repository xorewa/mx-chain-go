package systemSmartContracts

import (
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// Structural production coupling avoids a System-SC/process import cycle.
// This is the DRWA-owned full-record identity binding, not native ingress or
// authority. No ordinary Execute case, factory or public route imports it.
type drwaIntentRegistrationOwner interface {
	RegisterTokenForCreation(issuer, manager, family []byte,
		create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error
	IsInterfaceNil() bool
}

type drwaIntentCreator struct {
	owner   drwaIntentRegistrationOwner
	request drwaTokenCreation
}

func (o *drwaIntentCreator) RegisterToken(create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
	return o.owner.RegisterTokenForCreation(o.request.issuer, o.request.manager, o.request.family, create)
}

func (o *drwaIntentCreator) IsInterfaceNil() bool { return o == nil }

// registerDRWAIntentToken reuses the actual private native creator's locking,
// strict storage errors, zero supply/fixed L39 fields, burn normalization,
// account save and output cleanup. Its required owner validates identity inside
// the native journal and consumes the complete record bundle before returning.
// The T14 protected producer must still authenticate current admission/approvals,
// exact creation commitments, support/epoch/expiry and native issuance economics.
// It is deliberately unwired; neither format/profile nor ingress is admitted.
func (e *esdt) registerDRWAIntentToken(owner drwaIntentRegistrationOwner, request drwaTokenCreation) error {
	if check.IfNil(owner) {
		return errInvalidDRWARegistration
	}
	return e.registerDRWAToken(&drwaIntentCreator{owner: owner, request: request}, request)
}
