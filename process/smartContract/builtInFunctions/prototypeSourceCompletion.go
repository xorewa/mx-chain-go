package builtInFunctions

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/process/smartContract/scrCommon"
	"github.com/multiversx/mx-chain-go/sharding"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

var (
	// ErrPrototypeSourceCompletionDenied signals rejection before terminal source mutation.
	ErrPrototypeSourceCompletionDenied = errors.New("non-normative DRWA prototype source completion denied")
	// ErrPrototypeSourceCompletionMutation signals a failure after source state may have been journaled.
	ErrPrototypeSourceCompletionMutation = errors.New("non-normative DRWA prototype source completion mutation failed")
	// ErrInvalidPrototypeSourceCompletionDelegate signals unusable construction dependencies or delegate output.
	ErrInvalidPrototypeSourceCompletionDelegate = errors.New("invalid non-normative DRWA prototype source completion delegate")
)

type prototypeSourceCompletionArgs struct {
	delegate                    vmcommon.BuiltinFunction
	enableEpochsHandler         vmcommon.EnableEpochsHandler
	shardCoordinator            sharding.Coordinator
	networkDomain               [32]byte
	retainedWorkBudgetsProvider prototypeRetainedWorkBudgetsProvider
}

type prototypeSourceCompletion struct {
	delegate                    vmcommon.BuiltinFunction
	enableEpochsHandler         vmcommon.EnableEpochsHandler
	shardCoordinator            sharding.Coordinator
	networkDomain               [32]byte
	retainedWorkBudgetsProvider prototypeRetainedWorkBudgetsProvider
	loadOpenEffect              func(vmcommon.AccountDataHandler, [32]byte) (*drwaprototype.OpenEffect, error)
	removeOpenEffect            func(vmcommon.AccountDataHandler, [32]byte) error
}

func newPrototypeSourceCompletion(args prototypeSourceCompletionArgs) (*prototypeSourceCompletion, error) {
	if check.IfNil(args.delegate) || check.IfNil(args.enableEpochsHandler) ||
		check.IfNil(args.shardCoordinator) || args.retainedWorkBudgetsProvider == nil {
		return nil, ErrInvalidPrototypeSourceCompletionDelegate
	}
	return &prototypeSourceCompletion{
		delegate:                    args.delegate,
		enableEpochsHandler:         args.enableEpochsHandler,
		shardCoordinator:            args.shardCoordinator,
		networkDomain:               args.networkDomain,
		retainedWorkBudgetsProvider: args.retainedWorkBudgetsProvider,
		loadOpenEffect:              drwaprototype.LoadOpenEffect,
		removeOpenEffect:            drwaprototype.RemoveOpenEffect,
	}, nil
}

// ProcessBuiltinFunction applies one authenticated receipt or refund to an exact live OpenEffect.
func (completion *prototypeSourceCompletion) ProcessBuiltinFunction(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	payload, err := completion.validateAdmission(acntSnd, acntDst, vmInput)
	if err != nil {
		return nil, err
	}
	dataHandler := acntDst.AccountDataHandler()
	if check.IfNil(dataHandler) {
		return nil, fmt.Errorf("%w: nil source data handler", ErrPrototypeSourceCompletionDenied)
	}

	switch vmInput.Function {
	case scrCommon.PrototypeSettlementReceiptFunction:
		return completion.applySettlementReceipt(dataHandler, acntDst, vmInput, payload)
	case scrCommon.PrototypeRefundEnvelopeFunction:
		return completion.applyRefund(dataHandler, acntDst, vmInput, payload)
	default:
		return nil, fmt.Errorf("%w: function", ErrPrototypeSourceCompletionDenied)
	}
}

func (completion *prototypeSourceCompletion) validateAdmission(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) ([]byte, error) {
	if !completion.enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag) {
		return nil, fmt.Errorf("%w: activation", ErrPrototypeSourceCompletionDenied)
	}
	if completion.networkDomain == ([32]byte{}) || vmInput == nil || !check.IfNil(acntSnd) || check.IfNil(acntDst) {
		return nil, fmt.Errorf("%w: account route or network domain", ErrPrototypeSourceCompletionDenied)
	}
	if len(vmInput.CallerAddr) != prototypeAddressLength || len(vmInput.RecipientAddr) != prototypeAddressLength ||
		core.IsSmartContractAddress(vmInput.CallerAddr) || core.IsSmartContractAddress(vmInput.RecipientAddr) ||
		completion.shardCoordinator.ComputeId(vmInput.CallerAddr) == completion.shardCoordinator.SelfId() ||
		completion.shardCoordinator.ComputeId(vmInput.RecipientAddr) != completion.shardCoordinator.SelfId() ||
		!bytes.Equal(acntDst.AddressBytes(), vmInput.RecipientAddr) {
		return nil, fmt.Errorf("%w: cross-shard holder route", ErrPrototypeSourceCompletionDenied)
	}
	if vmInput.NativeCallOrigin != vmcommon.NativeCallOriginDRWAProtocolMessage ||
		vmInput.CallType != vmData.DirectCall || vmInput.CallValue == nil || vmInput.CallValue.Sign() != 0 ||
		vmInput.GasLocked != 0 || vmInput.ReturnCallAfterError || hasPrototypeAsyncArguments(vmInput.AsyncArguments) ||
		len(vmInput.ESDTTransfers) != 0 || len(vmInput.Arguments) != 1 {
		return nil, fmt.Errorf("%w: execution origin", ErrPrototypeSourceCompletionDenied)
	}
	if len(vmInput.CurrentTxHash) != prototypeHashLength || len(vmInput.OriginalTxHash) != prototypeHashLength ||
		len(vmInput.PrevTxHash) != prototypeHashLength || bytes.Equal(vmInput.CurrentTxHash, make([]byte, prototypeHashLength)) ||
		bytes.Equal(vmInput.OriginalTxHash, make([]byte, prototypeHashLength)) ||
		bytes.Equal(vmInput.PrevTxHash, make([]byte, prototypeHashLength)) {
		return nil, fmt.Errorf("%w: transaction identity", ErrPrototypeSourceCompletionDenied)
	}
	return append([]byte(nil), vmInput.Arguments[0]...), nil
}

func (completion *prototypeSourceCompletion) applySettlementReceipt(
	dataHandler vmcommon.AccountDataHandler,
	acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
	payload []byte,
) (*vmcommon.VMOutput, error) {
	receipt, err := drwaprototype.DecodeSettlementReceipt(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: receipt: %w", ErrPrototypeSourceCompletionDenied, err)
	}
	effect, err := completion.loadOpenEffect(dataHandler, receipt.EffectID)
	if err != nil {
		return nil, fmt.Errorf("%w: OpenEffect: %w", ErrPrototypeSourceCompletionDenied, err)
	}
	if err = validatePrototypeCompletionEffect(effect, receipt.ContextHash, acntDst, vmInput); err != nil {
		return nil, err
	}
	if !bytes.Equal(receipt.DestinationExecutionIdentity[:], vmInput.PrevTxHash) {
		return nil, fmt.Errorf("%w: destination execution identity", ErrPrototypeSourceCompletionDenied)
	}
	expectedReceipt, err := drwaprototype.BuildSettlementReceipt(
		completion.networkDomain,
		receipt.EffectID,
		receipt.ContextHash,
		receipt.DestinationExecutionIdentity,
	)
	if err != nil || expectedReceipt != *receipt {
		return nil, fmt.Errorf("%w: receipt identity", ErrPrototypeSourceCompletionDenied)
	}
	budgets, _, err := completion.retainedWorkBudgetsProvider(effect.GasScheduleIdentity)
	if err != nil {
		return nil, fmt.Errorf("%w: retained work budget: %w", ErrPrototypeSourceCompletionDenied, err)
	}
	minimumGas, err := core.SafeAddUint64(budgets.RefundGeneration, budgets.SourceCompletion)
	if err != nil {
		return nil, fmt.Errorf("%w: receipt minimum gas", ErrPrototypeSourceCompletionDenied)
	}
	maximumGas, err := core.SafeAddUint64(minimumGas, budgets.DestinationGate)
	if err != nil || vmInput.GasProvided < minimumGas || vmInput.GasProvided > maximumGas {
		return nil, fmt.Errorf("%w: receipt gas", ErrPrototypeSourceCompletionDenied)
	}
	gasRemaining, err := core.SafeSubUint64(vmInput.GasProvided, budgets.SourceCompletion)
	if err != nil {
		return nil, fmt.Errorf("%w: receipt gas partition", ErrPrototypeSourceCompletionDenied)
	}

	err = completion.removeOpenEffect(dataHandler, effect.EffectID)
	if err != nil {
		return nil, fmt.Errorf("%w: remove OpenEffect: %w", ErrPrototypeSourceCompletionMutation, err)
	}
	return buildPrototypeCompletionOutput(
		vmcommon.ProtocolExecutionOutcomeSourceSettled,
		budgets.SourceCompletion,
		gasRemaining,
	), nil
}

func (completion *prototypeSourceCompletion) applyRefund(
	dataHandler vmcommon.AccountDataHandler,
	acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
	payload []byte,
) (*vmcommon.VMOutput, error) {
	refund, err := drwaprototype.DecodeRefundEnvelope(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: refund: %w", ErrPrototypeSourceCompletionDenied, err)
	}
	effect, err := completion.loadOpenEffect(dataHandler, refund.EffectID)
	if err != nil {
		return nil, fmt.Errorf("%w: OpenEffect: %w", ErrPrototypeSourceCompletionDenied, err)
	}
	if err = validatePrototypeCompletionEffect(effect, refund.ContextHash, acntDst, vmInput); err != nil {
		return nil, err
	}
	if !bytes.Equal(refund.DestinationExecutionIdentity[:], vmInput.PrevTxHash) ||
		!bytes.Equal(refund.RefundTo[:], acntDst.AddressBytes()) {
		return nil, fmt.Errorf("%w: refund route or execution identity", ErrPrototypeSourceCompletionDenied)
	}
	tokenID, quantity, err := drwaprototype.DecodeDirectValueTransferPayload(refund.OriginalTransferPayload)
	if err != nil || !bytes.Equal(tokenID, effect.RegulatedTokenID) {
		return nil, fmt.Errorf("%w: original transfer payload", ErrPrototypeSourceCompletionDenied)
	}
	budgets, _, err := completion.retainedWorkBudgetsProvider(effect.GasScheduleIdentity)
	if err != nil {
		return nil, fmt.Errorf("%w: retained work budget: %w", ErrPrototypeSourceCompletionDenied, err)
	}
	expectedGas, err := core.SafeAddUint64(budgets.SuccessReceipt, budgets.SourceCompletion)
	if err != nil || vmInput.GasProvided != expectedGas {
		return nil, fmt.Errorf("%w: refund gas", ErrPrototypeSourceCompletionDenied)
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
		return nil, fmt.Errorf("%w: baseline refund: %w", ErrPrototypeSourceCompletionMutation, err)
	}
	if !isValidPrototypeRefundDelegateOutput(delegateOutput) {
		return nil, fmt.Errorf("%w: baseline refund output", ErrPrototypeSourceCompletionMutation)
	}
	err = completion.removeOpenEffect(dataHandler, effect.EffectID)
	if err != nil {
		return nil, fmt.Errorf("%w: remove OpenEffect: %w", ErrPrototypeSourceCompletionMutation, err)
	}
	output := buildPrototypeCompletionOutput(
		vmcommon.ProtocolExecutionOutcomeSourceRefunded,
		budgets.SourceCompletion,
		budgets.SuccessReceipt,
	)
	output.Logs = delegateOutput.Logs
	return output, nil
}

func isValidPrototypeRefundDelegateOutput(output *vmcommon.VMOutput) bool {
	return output != nil && output.ReturnCode == vmcommon.Ok && output.GasRemaining == 0 &&
		output.ProtocolExecution == nil && len(output.OutputAccounts) == 0 &&
		len(output.DeletedAccounts) == 0 && len(output.TouchedAccounts) == 0 &&
		len(output.ReturnData) == 0 && (output.GasRefund == nil || output.GasRefund.Sign() == 0)
}

func validatePrototypeCompletionEffect(
	effect *drwaprototype.OpenEffect,
	contextHash [32]byte,
	account vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) error {
	if effect == nil || effect.ContextHash != contextHash ||
		!bytes.Equal(effect.SourceSubject[:], account.AddressBytes()) ||
		!bytes.Equal(effect.SourceSubject[:], vmInput.RecipientAddr) ||
		!bytes.Equal(effect.OriginExecutionIdentity[:], vmInput.OriginalTxHash) ||
		effect.TerminalKind != drwaprototype.OpenEffectTerminalKindValueResult ||
		effect.State != drwaprototype.OpenEffectStatePendingDestination {
		return fmt.Errorf("%w: OpenEffect binding", ErrPrototypeSourceCompletionDenied)
	}
	return nil
}

func buildPrototypeCompletionOutput(
	outcome vmcommon.ProtocolExecutionOutcome,
	localGasUsed uint64,
	gasRemaining uint64,
) *vmcommon.VMOutput {
	return &vmcommon.VMOutput{
		ReturnCode:   vmcommon.Ok,
		GasRemaining: gasRemaining,
		ProtocolExecution: &vmcommon.ProtocolExecutionInfo{
			MessageKind:  vmData.ProtocolMessageKindDRWA,
			Outcome:      outcome,
			LocalGasUsed: localGasUsed,
			ForwardedGas: 0,
		},
	}
}

// SetNewGasConfig preserves the baseline delegate's built-in contract.
func (completion *prototypeSourceCompletion) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	completion.delegate.SetNewGasConfig(gasCost)
}

// IsActive keeps transaction classification disabled before the DRWA enforcement flag.
func (completion *prototypeSourceCompletion) IsActive() bool {
	return completion != nil && completion.enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag)
}

// IsInterfaceNil returns true for a nil source-completion handler.
func (completion *prototypeSourceCompletion) IsInterfaceNil() bool {
	return completion == nil
}
