package systemSmartContracts

import (
	"bytes"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// The endpoint requires the authenticated owner, not the bare token/count or
// identity binding. The native admission owner supplies it; input bytes cannot
// select an owner. No default or ordinary Execute registration is installed.
type drwaAuthenticatedRegistrationOwner interface {
	RegisterTokenForAuthenticatedCreation(intentID, creationBody, issuer, manager, family, profile, name, ticker []byte,
		decimals uint32, create func(state.AccountsAdapter, []byte, []byte, []byte, []byte, []byte, uint32, [][]byte) ([]byte, *vmcommon.VMOutput, error)) error
	IsInterfaceNil() bool
}

type drwaEndpointCreation struct {
	owner    drwaAuthenticatedRegistrationOwner
	context  *vmContext
	id, body []byte
	value    *big.Int
}

func (o *drwaEndpointCreation) IsInterfaceNil() bool { return o == nil }

func (o *drwaEndpointCreation) RegisterTokenForCommittedCreation(issuer, manager, family,
	profile, name, ticker []byte, decimals uint32, _ []byte,
	create func(state.AccountsAdapter, []byte, []byte, []byte, []byte, []byte, uint32, [][]byte) ([]byte, *vmcommon.VMOutput, error)) error {
	return o.owner.RegisterTokenForAuthenticatedCreation(o.id, o.body, issuer, manager, family, profile, name, ticker, decimals,
		func(accounts state.AccountsAdapter, actualIssuer, actualManager, actualFamily, actualName, actualTicker []byte,
			actualDecimals uint32, properties [][]byte) ([]byte, *vmcommon.VMOutput, error) {
			id, output, err := create(accounts, actualIssuer, actualManager, actualFamily, actualName, actualTicker, actualDecimals, properties)
			if err != nil {
				return nil, nil, err
			}
			// Reuse the native VM's call-value destination and balance-delta
			// semantics INSIDE the same pending output/T04 receipt. This path
			// owns the value once; an outer dispatcher must not credit it again.
			o.context.AddTxValueToSmartContract(o.value, core.ESDTSCAddress)
			output = o.context.CreateVMOutput()
			output.ReturnCode = vmcommon.Ok
			return id, output, nil
		})
}

// registerDRWATokenEndpoint is the protected ingress construction for Part A
// L2195-2218/L2278. It reuses checkBasicCreateArguments and createNewToken,
// NEVER ordinary issue() validation. Actual D01/native-origin/canonical adapters
// and dispatch installation are admission prerequisites; this is not a public
// route enabled by a request flag. The trusted decoder must supply request and
// profile; the authenticated owner compares them to the exact two raw arguments.
func (e *esdt) registerDRWATokenEndpoint(owner drwaAuthenticatedRegistrationOwner,
	input *vmcommon.ContractCallInput, request drwaTokenCreation, profile []byte) (vmcommon.ReturnCode, error) {
	e.mutExecution.Lock()
	defer e.mutExecution.Unlock()
	context, native := e.eei.(*vmContext)
	if !native || check.IfNil(owner) || input == nil || input.CallValue == nil ||
		input.Function != "DRWARegisterToken" || input.CallType != vmData.DirectCall ||
		!bytes.Equal(input.RecipientAddr, core.ESDTSCAddress) || !bytes.Equal(input.CallerAddr, request.issuer) ||
		len(input.Arguments) != 2 || len(input.Arguments[0]) == 0 || len(input.Arguments[1]) == 0 ||
		len(context.storageUpdate) != 0 || len(context.outputAccounts) != 0 || len(context.output) != 0 || len(context.logs) != 0 {
		return vmcommon.UserError, errInvalidDRWARegistration
	}
	if !e.enableEpochsHandler.IsFlagEnabled(common.ESDTFlag) {
		return vmcommon.UserError, errInvalidDRWARegistration
	}
	// createNewToken is deliberately below these native public dispatch checks
	// (pin 06c383cf esdt.go L354-356/L418-422/L2274-2278). Preserve the
	// ACTUAL epoch/family support in this direct-creator adaptation as well;
	// a supplied support certificate cannot enable an inactive native family.
	switch string(request.family) {
	case core.FungibleESDT, core.SemiFungibleESDT:
	case core.MetaESDT:
		if !e.enableEpochsHandler.IsFlagEnabled(common.MetaESDTSetFlag) {
			return vmcommon.UserError, errInvalidDRWARegistration
		}
	case core.NonFungibleESDTv2, core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT:
		if !e.enableEpochsHandler.IsFlagEnabled(common.DynamicESDTFlag) {
			return vmcommon.UserError, errInvalidDRWARegistration
		}
	default:
		return vmcommon.UserError, errInvalidDRWARegistration
	}
	// Native basic issuance checks consume the native issue gas and compare
	// against the actual retained ESDT config's issuance fee/name limits.
	feeInput := *input
	feeInput.Arguments = [][]byte{bytes.Clone(request.name)}
	if code := e.checkBasicCreateArguments(&feeInput); code != vmcommon.Ok {
		return code, nil
	}
	creation := &drwaEndpointCreation{owner: owner, context: context, id: bytes.Clone(input.Arguments[0]),
		body: bytes.Clone(input.Arguments[1]), value: new(big.Int).Set(input.CallValue)}
	err := e.registerDRWACommittedTokenLocked(creation, request, profile, e.hasher.Compute(string(creation.body)))
	if err != nil {
		return vmcommon.UserError, err
	}
	return vmcommon.Ok, nil
}
