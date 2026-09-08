package builtInFunctions

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
	"github.com/multiversx/mx-chain-go/process/smartContract/scrCommon"
	"github.com/multiversx/mx-chain-go/sharding"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

var (
	// ErrDRWASourceCompletionDenied signals rejection before terminal source mutation.
	ErrDRWASourceCompletionDenied = errors.New("non-normative DRWA prototype source completion denied")
	// ErrDRWASourceCompletionMutation signals a failure after source state may have been journaled.
	ErrDRWASourceCompletionMutation = errors.New("non-normative DRWA prototype source completion mutation failed")
	// ErrInvalidDRWASourceCompletionDelegate signals unusable construction dependencies or delegate output.
	ErrInvalidDRWASourceCompletionDelegate = errors.New("invalid non-normative DRWA prototype source completion delegate")
)

type drwaSourceCompletionArgs struct {
	delegate                    vmcommon.BuiltinFunction
	enableEpochsHandler         vmcommon.EnableEpochsHandler
	shardCoordinator            sharding.Coordinator
	networkDomain               [32]byte
	retainedWorkBudgetsProvider drwaRetainedWorkBudgetsProvider
}

type drwaSourceCompletion struct {
	delegate                    vmcommon.BuiltinFunction
	enableEpochsHandler         vmcommon.EnableEpochsHandler
	shardCoordinator            sharding.Coordinator
	networkDomain               [32]byte
	retainedWorkBudgetsProvider drwaRetainedWorkBudgetsProvider
	loadOpenEffect              func(vmcommon.AccountDataHandler, [32]byte) (*drwa.OpenEffect, error)
	removeOpenEffect            func(vmcommon.AccountDataHandler, [32]byte) error
}

func newDRWASourceCompletion(args drwaSourceCompletionArgs) (*drwaSourceCompletion, error) {
	if check.IfNil(args.delegate) || check.IfNil(args.enableEpochsHandler) ||
		check.IfNil(args.shardCoordinator) || args.retainedWorkBudgetsProvider == nil {
		return nil, ErrInvalidDRWASourceCompletionDelegate
	}
	return &drwaSourceCompletion{
		delegate:                    args.delegate,
		enableEpochsHandler:         args.enableEpochsHandler,
		shardCoordinator:            args.shardCoordinator,
		networkDomain:               args.networkDomain,
		retainedWorkBudgetsProvider: args.retainedWorkBudgetsProvider,
		loadOpenEffect:              drwa.LoadOpenEffect,
		removeOpenEffect:            drwa.RemoveOpenEffect,
	}, nil
}

// ProcessBuiltinFunction applies one authenticated receipt or refund to an exact live OpenEffect.
func (completion *drwaSourceCompletion) ProcessBuiltinFunction(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	payload, err := completion.validateAdmission(acntSnd, acntDst, vmInput)
	if err != nil {
		return nil, err
	}
	dataHandler := acntDst.AccountDataHandler()
	if check.IfNil(dataHandler) {
		return nil, fmt.Errorf("%w: nil source data handler", ErrDRWASourceCompletionDenied)
	}

	switch vmInput.Function {
	case scrCommon.DRWASettlementReceiptFunction:
		return completion.applySettlementReceipt(dataHandler, acntDst, vmInput, payload)
	case scrCommon.DRWARefundEnvelopeFunction:
		return completion.applyRefund(dataHandler, acntDst, vmInput, payload)
	default:
		return nil, fmt.Errorf("%w: function", ErrDRWASourceCompletionDenied)
	}
}

func (completion *drwaSourceCompletion) validateAdmission(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) ([]byte, error) {
	if !completion.enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag) {
		return nil, fmt.Errorf("%w: activation", ErrDRWASourceCompletionDenied)
	}
	if completion.networkDomain == ([32]byte{}) || vmInput == nil || !check.IfNil(acntSnd) || check.IfNil(acntDst) {
		return nil, fmt.Errorf("%w: account route or network domain", ErrDRWASourceCompletionDenied)
	}
	if len(vmInput.CallerAddr) != drwaAddressLength || len(vmInput.RecipientAddr) != drwaAddressLength ||
		core.IsSmartContractAddress(vmInput.CallerAddr) || core.IsSmartContractAddress(vmInput.RecipientAddr) ||
		completion.shardCoordinator.ComputeId(vmInput.CallerAddr) == completion.shardCoordinator.SelfId() ||
		completion.shardCoordinator.ComputeId(vmInput.RecipientAddr) != completion.shardCoordinator.SelfId() ||
		!bytes.Equal(acntDst.AddressBytes(), vmInput.RecipientAddr) {
		return nil, fmt.Errorf("%w: cross-shard holder route", ErrDRWASourceCompletionDenied)
	}
	if vmInput.NativeCallOrigin != vmcommon.NativeCallOriginDRWAProtocolMessage ||
		vmInput.CallType != vmData.DirectCall || vmInput.CallValue == nil || vmInput.CallValue.Sign() != 0 ||
		vmInput.GasLocked != 0 || vmInput.ReturnCallAfterError || hasDRWAAsyncArguments(vmInput.AsyncArguments) ||
		len(vmInput.ESDTTransfers) != 0 || len(vmInput.Arguments) != 1 {
		return nil, fmt.Errorf("%w: execution origin", ErrDRWASourceCompletionDenied)
	}
	if len(vmInput.CurrentTxHash) != drwaHashLength || len(vmInput.OriginalTxHash) != drwaHashLength ||
		len(vmInput.PrevTxHash) != drwaHashLength || bytes.Equal(vmInput.CurrentTxHash, make([]byte, drwaHashLength)) ||
		bytes.Equal(vmInput.OriginalTxHash, make([]byte, drwaHashLength)) ||
		bytes.Equal(vmInput.PrevTxHash, make([]byte, drwaHashLength)) {
		return nil, fmt.Errorf("%w: transaction identity", ErrDRWASourceCompletionDenied)
	}
	return append([]byte(nil), vmInput.Arguments[0]...), nil
}

func (completion *drwaSourceCompletion) applySettlementReceipt(
	dataHandler vmcommon.AccountDataHandler,
	acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
	payload []byte,
) (*vmcommon.VMOutput, error) {
	receipt, err := drwa.DecodeSettlementReceipt(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: receipt: %w", ErrDRWASourceCompletionDenied, err)
	}
	effect, err := completion.loadOpenEffect(dataHandler, receipt.EffectID)
	if err != nil {
		return nil, fmt.Errorf("%w: OpenEffect: %w", ErrDRWASourceCompletionDenied, err)
	}
	if err = validateDRWACompletionEffect(effect, receipt.ContextHash, acntDst, vmInput); err != nil {
		return nil, err
	}
	if !bytes.Equal(receipt.DestinationExecutionIdentity[:], vmInput.PrevTxHash) {
		return nil, fmt.Errorf("%w: destination execution identity", ErrDRWASourceCompletionDenied)
	}
	expectedReceipt, err := drwa.BuildSettlementReceipt(
		completion.networkDomain,
		receipt.EffectID,
		receipt.ContextHash,
		receipt.DestinationExecutionIdentity,
	)
	if err != nil || expectedReceipt != *receipt {
		return nil, fmt.Errorf("%w: receipt identity", ErrDRWASourceCompletionDenied)
	}
	budgets, _, err := completion.retainedWorkBudgetsProvider(effect.GasScheduleIdentity)
	if err != nil {
		return nil, fmt.Errorf("%w: retained work budget: %w", ErrDRWASourceCompletionDenied, err)
	}
	minimumGas, err := core.SafeAddUint64(budgets.RefundGeneration, budgets.SourceCompletion)
	if err != nil {
		return nil, fmt.Errorf("%w: receipt minimum gas", ErrDRWASourceCompletionDenied)
	}
	maximumGas, err := core.SafeAddUint64(minimumGas, budgets.DestinationGate)
	if err != nil || vmInput.GasProvided < minimumGas || vmInput.GasProvided > maximumGas {
		return nil, fmt.Errorf("%w: receipt gas", ErrDRWASourceCompletionDenied)
	}
	gasRemaining, err := core.SafeSubUint64(vmInput.GasProvided, budgets.SourceCompletion)
	if err != nil {
		return nil, fmt.Errorf("%w: receipt gas partition", ErrDRWASourceCompletionDenied)
	}

	err = completion.removeOpenEffect(dataHandler, effect.EffectID)
	if err != nil {
		return nil, fmt.Errorf("%w: remove OpenEffect: %w", ErrDRWASourceCompletionMutation, err)
	}
	return buildDRWACompletionOutput(
		vmcommon.ProtocolExecutionOutcomeSourceSettled,
		budgets.SourceCompletion,
		gasRemaining,
		effect.SourceSubject[:],
	), nil
}

func (completion *drwaSourceCompletion) applyRefund(
	dataHandler vmcommon.AccountDataHandler,
	acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
	payload []byte,
) (*vmcommon.VMOutput, error) {
	refund, err := drwa.DecodeRefundEnvelope(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: refund: %w", ErrDRWASourceCompletionDenied, err)
	}
	effect, err := completion.loadOpenEffect(dataHandler, refund.EffectID)
	if err != nil {
		return nil, fmt.Errorf("%w: OpenEffect: %w", ErrDRWASourceCompletionDenied, err)
	}
	if err = validateDRWACompletionEffect(effect, refund.ContextHash, acntDst, vmInput); err != nil {
		return nil, err
	}
	if !bytes.Equal(refund.DestinationExecutionIdentity[:], vmInput.PrevTxHash) ||
		!bytes.Equal(refund.RefundTo[:], acntDst.AddressBytes()) {
		return nil, fmt.Errorf("%w: refund route or execution identity", ErrDRWASourceCompletionDenied)
	}
	tokenID, quantity, err := drwa.DecodeDirectValueTransferPayload(refund.OriginalTransferPayload)
	if err != nil || !bytes.Equal(tokenID, effect.RegulatedTokenID) {
		return nil, fmt.Errorf("%w: original transfer payload", ErrDRWASourceCompletionDenied)
	}
	budgets, _, err := completion.retainedWorkBudgetsProvider(effect.GasScheduleIdentity)
	if err != nil {
		return nil, fmt.Errorf("%w: retained work budget: %w", ErrDRWASourceCompletionDenied, err)
	}
	expectedGas, err := core.SafeAddUint64(budgets.SuccessReceipt, budgets.SourceCompletion)
	if err != nil || vmInput.GasProvided != expectedGas {
		return nil, fmt.Errorf("%w: refund gas", ErrDRWASourceCompletionDenied)
	}

	delegateInput := *vmInput
	delegateInput.Function = core.BuiltInFunctionESDTTransfer
	delegateInput.Arguments = [][]byte{tokenID, quantity}
	delegateInput.GasProvided = budgets.SourceCompletion
	delegateInput.GasLocked = 0
	delegateInput.ReturnCallAfterError = true
	delegateInput.ESDTTransfers = nil
	delegateOutput, err := completion.delegate.ProcessBuiltinFunction(nil, acntDst, &delegateInput)
	if err != nil {
		return nil, fmt.Errorf("%w: baseline refund: %w", ErrDRWASourceCompletionMutation, err)
	}
	expectedDelegateGasRemaining := uint64(0)
	if completion.enableEpochsHandler.IsFlagEnabled(common.EGLDInESDTMultiTransferFlag) {
		expectedDelegateGasRemaining = budgets.SourceCompletion
	}
	if !isValidDRWARefundDelegateOutput(delegateOutput, expectedDelegateGasRemaining) {
		return nil, fmt.Errorf("%w: baseline refund output", ErrDRWASourceCompletionMutation)
	}
	err = completion.removeOpenEffect(dataHandler, effect.EffectID)
	if err != nil {
		return nil, fmt.Errorf("%w: remove OpenEffect: %w", ErrDRWASourceCompletionMutation, err)
	}
	output := buildDRWACompletionOutput(
		vmcommon.ProtocolExecutionOutcomeSourceRefunded,
		budgets.SourceCompletion,
		budgets.SuccessReceipt,
		effect.SourceSubject[:],
	)
	output.Logs = delegateOutput.Logs
	return output, nil
}

func isValidDRWARefundDelegateOutput(output *vmcommon.VMOutput, expectedGasRemaining uint64) bool {
	return output != nil && output.ReturnCode == vmcommon.Ok && output.GasRemaining == expectedGasRemaining &&
		output.ProtocolExecution == nil && len(output.OutputAccounts) == 0 &&
		len(output.DeletedAccounts) == 0 && len(output.TouchedAccounts) == 0 &&
		len(output.ReturnData) == 0 && (output.GasRefund == nil || output.GasRefund.Sign() == 0)
}

func validateDRWACompletionEffect(
	effect *drwa.OpenEffect,
	contextHash [32]byte,
	account vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) error {
	if effect == nil || effect.ContextHash != contextHash ||
		!bytes.Equal(effect.SourceSubject[:], account.AddressBytes()) ||
		!bytes.Equal(effect.SourceSubject[:], vmInput.RecipientAddr) ||
		!bytes.Equal(effect.OriginExecutionIdentity[:], vmInput.OriginalTxHash) ||
		effect.TerminalKind != drwa.OpenEffectTerminalKindValueResult ||
		effect.State != drwa.OpenEffectStatePendingDestination {
		return fmt.Errorf("%w: OpenEffect binding", ErrDRWASourceCompletionDenied)
	}
	return nil
}

func buildDRWACompletionOutput(
	outcome vmcommon.ProtocolExecutionOutcome,
	localGasUsed uint64,
	gasRemaining uint64,
	gasRefundRecipient []byte,
) *vmcommon.VMOutput {
	var validatedGasRefundRecipient []byte
	if gasRemaining != 0 {
		validatedGasRefundRecipient = append([]byte(nil), gasRefundRecipient...)
	}
	return &vmcommon.VMOutput{
		ReturnCode:   vmcommon.Ok,
		GasRemaining: gasRemaining,
		ProtocolExecution: &vmcommon.ProtocolExecutionInfo{
			MessageKind:        vmData.ProtocolMessageKindDRWA,
			Outcome:            outcome,
			LocalGasUsed:       localGasUsed,
			ForwardedGas:       0,
			GasRefundRecipient: validatedGasRefundRecipient,
		},
	}
}

// SetNewGasConfig preserves the baseline delegate's built-in contract.
func (completion *drwaSourceCompletion) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	completion.delegate.SetNewGasConfig(gasCost)
}

// IsActive keeps transaction classification disabled before the DRWA enforcement flag.
func (completion *drwaSourceCompletion) IsActive() bool {
	return completion != nil && completion.enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag)
}

// IsInterfaceNil returns true for a nil source-completion handler.
func (completion *drwaSourceCompletion) IsInterfaceNil() bool {
	return completion == nil
}
