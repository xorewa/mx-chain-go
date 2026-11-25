package vm

import (
	"bytes"
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"

	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// ErrDRWAExecution identifies a DRWA execution failure that must bypass ordinary
// token-policy denial handling. Only retained integrity failures request node
// stop. See Part A 5.1 and P-05.
var ErrDRWAExecution = errors.New("DRWA execution context unavailable")

type drwaClassificationUnavailable struct{ cause error }

func (e drwaClassificationUnavailable) Error() string {
	return ErrDRWAExecution.Error() + ": " + e.cause.Error()
}

func (e drwaClassificationUnavailable) Unwrap() error { return e.cause }

func (e drwaClassificationUnavailable) Is(target error) bool { return target == ErrDRWAExecution }

// NewDRWAClassificationUnavailable is for the native classifier when it
// cannot take its read dependency and has not called execute. The returned
// error still aborts the current attempt through the native error channel.
func NewDRWAClassificationUnavailable(cause error) error {
	return drwaClassificationUnavailable{cause: cause}
}

// IsDirectDRWAClassificationUnavailable only recognizes the classifier's
// direct result. A wrapped or joined error can carry additional failures.
func IsDirectDRWAClassificationUnavailable(err error) bool {
	_, ok := err.(drwaClassificationUnavailable)
	return ok
}

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

// DRWAAccountDeletionGuard retains the actual native VM/current view dependency
// through native deletion. It adds no journal, registry or positive authority.
// Nil constructor dependencies preserve the original native loop.
type DRWAAccountDeletionGuard interface {
	WithDRWAAccountDeletion(state.AccountsAdapter, [][]byte, func() error) error
}

// DRWAAccountProtectionSource is supplied by the SAME installed classifier's
// actual candidate. A store/address match is not canonical/genesis admission.
type DRWAAccountProtectionSource interface {
	WithDRWAAccountProtection(state.AccountsAdapter, func() error) error
}

// DRWANativeCallHandoff is an opaque, operation-local Go handoff (A72 C/D).
// Presence or an implementation of this interface authenticates nothing. Only
// the issuing physical SystemVM accepts its private concrete token. No wire or
// VMInput field, public token constructor or ambient request slot is supplied.
type DRWANativeCallHandoff interface {
	IsInterfaceNil() bool
}

// DRWANativeCallLease belongs to the installed native candidate, not the
// transaction caller. VerifyCall must bind the authenticated original/inner EOA,
// original transaction/parent, complete effective input, programme/domain,
// evaluated header, accounts/containment, physical VM and current lifetime.
// It must refuse stale/replaced/closed, foreign, callback and unproven SCR input.
// Static native validation, a cache hit or input equality alone is insufficient.
type DRWANativeCallLease interface {
	VerifyTransaction(data.TransactionHandler, state.AccountsAdapter, state.UserAccountHandler, state.UserAccountHandler) error
	VerifyCall(*vmcommon.ContractCallInput) error
	IsInterfaceNil() bool
}

// DRWANativeCallSource is an additional duty of the SAME installed native
// candidate. validation is opaque transport of the native validation result;
// its qualified producer/type and immutable bytes must be checked independently.
// The source holds the original all-effect owner/header/store lease throughout
// execute, including native payment/output/rollback. This transport adds no
// journal, signature pass, accepting provider or canonical/funding admission.
type DRWANativeCallSource interface {
	WithDRWANativeCall(data.TransactionHandler, any, state.AccountsAdapter,
		vmcommon.VMExecutionHandler, func(DRWANativeCallLease) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error)
}

// DRWANativeCallContext is the physical VM's existing context adaptation. Its
// native factory must bind the qualified source before any positive use.
type DRWANativeCallContext interface {
	DRWANativeCallSource
}

// DRWANativeCallExecutor leaves vmcommon's execution interface unchanged. Its
// private token expires at operation return/error and is usable once, only at
// the physical issuer, after that issuer rechecks the native lease.
type DRWANativeCallExecutor interface {
	DRWANativeCallConfigured() bool
	WithDRWANativeCall(data.TransactionHandler, any, state.AccountsAdapter,
		func(DRWANativeCallHandoff) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error)
	ValidateDRWANativeTransaction(DRWANativeCallHandoff, data.TransactionHandler, state.AccountsAdapter, state.UserAccountHandler, state.UserAccountHandler) error
	RunSmartContractCallWithDRWA(*vmcommon.ContractCallInput, DRWANativeCallHandoff) (*vmcommon.VMOutput, error)
}

// DRWANativeSCExecutor is operation-local execution, not an authentication
// callback or public route. Its native issuer must check exact input and lifetime
// before every first effect; a receipt's presence grants nothing.
type DRWANativeSCExecutor func(data.TransactionHandler, state.UserAccountHandler, state.UserAccountHandler) (vmcommon.ReturnCode, error)

type DRWANativeTransactionContext interface {
	WithDRWANativeTransaction(data.TransactionHandler, any, func(DRWANativeSCExecutor) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error)
}

// DRWADeletionTargetsProtectedAccount protects the existing native account that
// retains initial@; no caller-selected namespace/address is introduced.
func DRWADeletionTargetsProtectedAccount(addresses [][]byte) bool {
	for _, address := range addresses {
		if bytes.Equal(address, core.SystemAccountAddress) {
			return true
		}
	}
	return false
}

// DRWANativePreparedCall binds only the effective call emitted by the selected
// native SC processor after prepareExecution. It adds no authentication source.
type DRWANativePreparedCall interface {
	BindDRWANativeCall(DRWANativeCallHandoff, *vmcommon.ContractCallInput) error
}

// DRWANativePreparedCallLease receives that call under the same private handoff.
// VerifyCall must never install its own argument as the expected call.
type DRWANativePreparedCallLease interface {
	BindCall(*vmcommon.ContractCallInput) error
}
