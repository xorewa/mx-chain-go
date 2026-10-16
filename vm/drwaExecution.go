package vm

import (
	"errors"

	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// ErrDRWAExecution identifies a DRWA classifier/context failure, rather than a
// token-policy denial. Consumers must preserve its error channel and cause.
// Part A 5.1 and P-05 require node processing to stop on an unavailable view.
var ErrDRWAExecution = errors.New("DRWA execution context unavailable")

// DRWATokenClassifier is the DRWA-defined native read dependency on the existing
// BlockLocalRegistryView (Part A 5.1). The owner binds the native account store
// and keeps the classification dependency held throughout execute. This is not
// a caller-provided membership value, ingress authority or a new journal.
// Factory admission must supply the actual candidate owner; nil retains native
// pre-enforcement behavior and cannot authorize DRWA enforcement.
type DRWATokenClassifier interface {
	// ValidateAccounts refuses native user/validator handles outside the same
	// containment owner before a System-SC context is constructed. Identity is
	// not canonical-context admission or proof of exclusive scheduler ownership.
	ValidateAccounts(user, validator state.AccountsAdapter) error
	WithTokenClassification(accounts state.AccountsAdapter, tokenID []byte,
		execute func(regulated bool) (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error)
	IsInterfaceNil() bool
}

// DRWASystemCallContext lets the native System VM hold the same dependency
// before its value/output effects. Older native context implementations retain
// their existing path. A classifier failure is returned without a VM output.
type DRWASystemCallContext interface {
	ExecuteDRWASystemCall(input *vmcommon.ContractCallInput,
		execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error)
}
