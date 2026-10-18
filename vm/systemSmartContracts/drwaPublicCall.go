package systemSmartContracts

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// ExecuteDRWASystemCall places the native VM's value/output effects inside the
// same classifier read dependency as ESDT dispatch. The constructor or guarded
// handoff dependency must be the admitted native candidate owner. It is not selected by
// transaction arguments, manager identity, token properties or a public flag.
func (host *vmContext) ExecuteDRWASystemCall(input *vmcommon.ContractCallInput,
	execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	if input != nil && bytes.Equal(input.RecipientAddr, core.ESDTSCAddress) {
		return host.executeDRWAESDTCall(input, execute)
	}
	return host.executeWithDRWAErrorCheck(execute)
}

func (host *vmContext) executeWithDRWAErrorCheck(execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	if !host.drwaClassifierConfigured {
		return execute()
	}
	host.mutDRWAClassifier.RLock()
	defer host.mutDRWAClassifier.RUnlock()
	if failure := host.drwaExecutionAvailabilityError(); failure != nil {
		return nil, failure
	}
	output, err := execute()
	// Native callers can ignore a nested error. Such an error cannot become a
	// successful outer result, even when that caller returns native Ok.
	if failure := host.drwaExecutionAvailabilityError(); failure != nil {
		return nil, failure
	}
	return output, err
}

func (host *vmContext) executeDRWAESDTCall(input *vmcommon.ContractCallInput,
	execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	return host.executeWithDRWAErrorCheck(func() (*vmcommon.VMOutput, error) {
		if host.drwaClassifier == nil || input == nil || len(input.Arguments) == 0 || !drwaPublicTokenMutation(input.Function) {
			return execute()
		}
		entered := false
		output, err := host.drwaClassifier.WithTokenClassification(host.userAccountsDB, input.Arguments[0],
			func(regulated bool) (*vmcommon.VMOutput, error) {
				entered = true
				if regulated {
					return &vmcommon.VMOutput{ReturnCode: vmcommon.UserError, GasRefund: big.NewInt(0),
						ReturnMessage: "DRWA public operation denied"}, nil
				}
				return execute()
			})
		if err != nil && !entered {
			// Retain the first classification failure across CleanCache and
			// nested contexts. Recovery requires reconstruction with a newly
			// admitted owner; clearing ordinary VM caches is not recovery.
			return nil, host.retainDRWAExecutionError(err)
		}
		return output, err
	})
}

// DRWAExecutionError exposes the existing retained failure to the native owner.
// A shared candidate can fail outside this VM, before another classified call.
// Observe that owner's existing status before native effects, then retain it in
// the same latch. This never clears VM state or admits a replacement candidate.
func (host *vmContext) DRWAExecutionError() error {
	if !host.drwaClassifierConfigured {
		return nil
	}
	host.mutDRWAClassifier.RLock()
	defer host.mutDRWAClassifier.RUnlock()
	failure := host.drwaExecutionError.Load()
	if failure == nil {
		if owner, exists := host.drwaClassifier.(interface{ DRWAExecutionHealthError() error }); exists {
			if err := owner.DRWAExecutionHealthError(); err != nil {
				return host.retainDRWAExecutionError(err)
			}
		} else if owner, exists := host.drwaClassifier.(interface{ DRWAExecutionError() error }); exists {
			if err := owner.DRWAExecutionError(); err != nil {
				return host.retainDRWAExecutionError(err)
			}
		}
		return nil
	}
	return *failure
}

// Caller holds the classifier read dependency through the entire native work.
// A healthy closed owner is not a failure of passive status, but cannot execute.
func (host *vmContext) drwaExecutionAvailabilityError() error {
	if failure := host.drwaExecutionError.Load(); failure != nil {
		return *failure
	}
	if owner, exists := host.drwaClassifier.(interface{ DRWAExecutionError() error }); exists {
		if err := owner.DRWAExecutionError(); err != nil {
			return host.retainDRWAExecutionError(err)
		}
	}
	return nil
}

// ReplaceDRWAClassifier keeps the native context/contracts and their gas
// subscriptions. Only the old private owner can admit the same-lineage handoff;
// an error leaves both the classifier and the existing failure latch unchanged.
func (host *vmContext) ReplaceDRWAClassifier(next vm.DRWATokenClassifier) error {
	if !host.mutDRWAClassifier.TryLock() {
		return vm.ErrDRWAExecution
	}
	defer host.mutDRWAClassifier.Unlock()
	if failure := host.drwaExecutionError.Load(); failure != nil {
		return *failure
	}
	if check.IfNil(next) || check.IfNil(host.drwaClassifier) {
		return vm.ErrDRWAExecution
	}
	owner, exists := host.drwaClassifier.(interface {
		WithDRWAClassifierReplacement(vm.DRWATokenClassifier, func()) error
	})
	if !exists {
		return vm.ErrDRWAExecution
	}
	if err := next.ValidateAccounts(host.userAccountsDB, host.validatorAccountsDB); err != nil {
		return fmt.Errorf("%w: %w", vm.ErrDRWAExecution, err)
	}
	if err := owner.WithDRWAClassifierReplacement(next, func() { host.drwaClassifier = next }); err != nil {
		return fmt.Errorf("%w: %w", vm.ErrDRWAExecution, err)
	}
	return nil
}

func (host *vmContext) retainDRWAExecutionError(err error) error {
	failure := fmt.Errorf("%w: %w", vm.ErrDRWAExecution, err)
	host.drwaExecutionError.CompareAndSwap(nil, &failure)
	return *host.drwaExecutionError.Load()
}

// All targets below use the native Arguments[0] identifier. This is DS01-04's
// public System-SC surface, not the closed P17 inventory or a protected admin
// authorization path. Private bootstrap creation/normalization does not enter
// public Execute. Receiving shard built-ins retain their separate first-effect
// and protected-provenance obligations; this public selector cannot admit them.
func drwaPublicTokenMutation(function string) bool {
	switch function {
	case "setBurnRoleGlobally", "unsetBurnRoleGlobally",
		"transferOwnership", "controlChanges", "transferNFTCreateRole", "stopNFTCreate",
		"setSpecialRole", "unSetSpecialRole", "sendAllTransferRoleAddresses",
		"freeze", "unFreeze", "wipe", "pause", "unPause",
		"freezeSingleNFT", "unFreezeSingleNFT", "wipeSingleNFT",
		"mint", core.BuiltInFunctionESDTBurn,
		"updateTokenID", "changeSFTToMetaESDT", "changeToDynamic", "changeToMultiShardCreate":
		return true
	default:
		return false
	}
}
