package systemSmartContracts

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// ExecuteDRWASystemCall places the native VM's value/output effects inside the
// same classifier read dependency as ESDT dispatch. The immutable constructor
// dependency must be the admitted native candidate owner. It is not selected by
// transaction arguments, manager identity, token properties or a public flag.
func (host *vmContext) ExecuteDRWASystemCall(input *vmcommon.ContractCallInput,
	execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	if input != nil && bytes.Equal(input.RecipientAddr, core.ESDTSCAddress) {
		return host.executeDRWAESDTCall(input, execute)
	}
	return host.executeWithDRWAErrorCheck(execute)
}

func (host *vmContext) executeWithDRWAErrorCheck(execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	if failure := host.DRWAExecutionError(); failure != nil {
		return nil, failure
	}
	output, err := execute()
	// Native callers can ignore a nested error. Such an error cannot become a
	// successful outer result, even when that caller returns native Ok.
	if failure := host.DRWAExecutionError(); failure != nil {
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
			failure := fmt.Errorf("%w: %w", vm.ErrDRWAExecution, err)
			host.drwaExecutionError.CompareAndSwap(nil, &failure)
			return nil, host.DRWAExecutionError()
		}
		return output, err
	})
}

// DRWAExecutionError exposes the existing retained failure to the native owner.
// It never clears VM state or admits a new candidate. Atomic publication also
// permits read-only observation while a direct classification call fails.
func (host *vmContext) DRWAExecutionError() error {
	failure := host.drwaExecutionError.Load()
	if failure == nil {
		return nil
	}
	return *failure
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
