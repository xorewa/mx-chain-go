package scrCommon

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

const (
	// DRWASourceDebitFunction is the bounded S1 source-only entry point.
	DRWASourceDebitFunction = "DRWAPrototypeTransfer"
	// DRWASettlementReceiptFunction is the bounded S1 success-result entry point.
	DRWASettlementReceiptFunction = "DRWASettlementReceipt"
	// DRWARefundEnvelopeFunction is the bounded S1 denial-result entry point.
	DRWARefundEnvelopeFunction = "DRWARefundEnvelope"
)

// ErrInvalidDRWAForwardedGas signals a malformed or arithmetically invalid successful DRWA output.
var ErrInvalidDRWAForwardedGas = errors.New("invalid non-normative DRWA prototype forwarded-gas output")

// DRWAExecutionGasUsed validates one explicit S1 protocol outcome and returns its declared
// local work. Non-candidates return matched=false and retain baseline accounting. Refund outcomes
// return refund=true so the processor can revert the captured destination mutation snapshot before
// treating the single refund carrier as canonical output.
func DRWAExecutionGasUsed(
	txTypeOnDestination process.TransactionType,
	isCrossShard bool,
	vmInput *vmcommon.ContractCallInput,
	vmOutput *vmcommon.VMOutput,
) (gasUsed uint64, matched bool, refund bool, err error) {
	if vmInput == nil || vmOutput == nil {
		return 0, false, false, nil
	}

	hasDRWAOutput := containsDRWAOutput(vmOutput)
	protocolExecution := vmOutput.ProtocolExecution
	if protocolExecution == nil {
		if hasDRWAOutput {
			return 0, true, false, fmt.Errorf("%w: DRWA output without execution contract", ErrInvalidDRWAForwardedGas)
		}
		return 0, false, false, nil
	}
	if protocolExecution.MessageKind != vmData.ProtocolMessageKindDRWA ||
		protocolExecution.Outcome == vmcommon.ProtocolExecutionOutcomeNone ||
		protocolExecution.LocalGasUsed == 0 {
		return 0, true, false, fmt.Errorf("%w: invalid execution contract", ErrInvalidDRWAForwardedGas)
	}
	_, err = drwaGasRefundRecipient(vmInput, vmOutput)
	if err != nil {
		return 0, true, false, err
	}

	isSourceFunction := vmInput.Function == DRWASourceDebitFunction
	isDestinationFunction := vmInput.Function == vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope
	isSettlementCompletion := vmInput.Function == DRWASettlementReceiptFunction
	isRefundCompletion := vmInput.Function == DRWARefundEnvelopeFunction
	if !isSourceFunction && !isDestinationFunction && !isSettlementCompletion && !isRefundCompletion {
		return 0, true, false, fmt.Errorf("%w: protocol contract from an unrelated function", ErrInvalidDRWAForwardedGas)
	}
	if txTypeOnDestination != process.BuiltInFunctionCall {
		return 0, true, false, fmt.Errorf("%w: unexpected destination transaction type", ErrInvalidDRWAForwardedGas)
	}
	if isSettlementCompletion || isRefundCompletion {
		err = validateDRWACompletionGasOutput(
			isCrossShard,
			isSettlementCompletion,
			vmInput,
			vmOutput,
		)
		if err != nil {
			return 0, true, false, err
		}
		accountedGas, addErr := core.SafeAddUint64(protocolExecution.LocalGasUsed, vmOutput.GasRemaining)
		if addErr != nil || accountedGas != vmInput.GasProvided || protocolExecution.ForwardedGas != 0 {
			return 0, true, false, fmt.Errorf("%w: completion gas partition does not conserve input", ErrInvalidDRWAForwardedGas)
		}
		return protocolExecution.LocalGasUsed, true, false, nil
	}

	outputAccount, outputTransfer, err := exactDRWAOutput(vmOutput)
	if err != nil {
		return 0, true, false, err
	}
	if isSourceFunction {
		if vmOutput.ReturnCode != vmcommon.Ok || protocolExecution.Outcome != vmcommon.ProtocolExecutionOutcomeForward {
			return 0, true, false, fmt.Errorf("%w: invalid source outcome", ErrInvalidDRWAForwardedGas)
		}
		err = validateDRWASourceGasOutput(isCrossShard, vmInput, outputAccount, outputTransfer)
	} else {
		switch protocolExecution.Outcome {
		case vmcommon.ProtocolExecutionOutcomeSettlementReceipt:
			if vmOutput.ReturnCode != vmcommon.Ok {
				return 0, true, false, fmt.Errorf("%w: failed settlement outcome", ErrInvalidDRWAForwardedGas)
			}
			err = validateDRWADestinationGasOutput(isCrossShard, vmInput, outputAccount, outputTransfer)
		case vmcommon.ProtocolExecutionOutcomeRefundEnvelope:
			if vmOutput.ReturnCode == vmcommon.Ok {
				return 0, true, false, fmt.Errorf("%w: successful refund outcome", ErrInvalidDRWAForwardedGas)
			}
			refund = true
			err = validateDRWADestinationRefundGasOutput(isCrossShard, vmInput, outputAccount, outputTransfer)
		default:
			return 0, true, false, fmt.Errorf("%w: unsupported destination outcome", ErrInvalidDRWAForwardedGas)
		}
	}
	if err != nil {
		return 0, true, false, err
	}

	if protocolExecution.ForwardedGas != outputTransfer.GasLimit {
		return 0, true, false, fmt.Errorf("%w: forwarded gas declaration mismatch", ErrInvalidDRWAForwardedGas)
	}
	accountedGas, err := core.SafeAddUint64(protocolExecution.LocalGasUsed, protocolExecution.ForwardedGas)
	if err != nil {
		return 0, true, false, fmt.Errorf("%w: local plus forwarded gas: %v", ErrInvalidDRWAForwardedGas, err)
	}
	accountedGas, err = core.SafeAddUint64(accountedGas, vmOutput.GasRemaining)
	if err != nil || accountedGas != vmInput.GasProvided {
		return 0, true, false, fmt.Errorf("%w: gas partition does not conserve input", ErrInvalidDRWAForwardedGas)
	}

	return protocolExecution.LocalGasUsed, true, refund, nil
}

// DRWAExecutionGasAccounting validates one complete S1 gas contract and returns its
// accounting result together with the source-payer recipient, if any. The recipient is never
// returned independently of successful full-route validation.
func DRWAExecutionGasAccounting(
	txTypeOnDestination process.TransactionType,
	isCrossShard bool,
	vmInput *vmcommon.ContractCallInput,
	vmOutput *vmcommon.VMOutput,
) (gasUsed uint64, matched bool, refund bool, gasRefundRecipient []byte, err error) {
	gasUsed, matched, refund, err = DRWAExecutionGasUsed(txTypeOnDestination, isCrossShard, vmInput, vmOutput)
	if err != nil || !matched {
		return gasUsed, matched, refund, nil, err
	}

	gasRefundRecipient, err = drwaGasRefundRecipient(vmInput, vmOutput)
	if err != nil {
		return 0, true, false, nil, err
	}
	return gasUsed, matched, refund, gasRefundRecipient, nil
}

func drwaGasRefundRecipient(
	vmInput *vmcommon.ContractCallInput,
	vmOutput *vmcommon.VMOutput,
) ([]byte, error) {
	if vmInput == nil || vmOutput == nil || vmOutput.ProtocolExecution == nil {
		return nil, nil
	}

	protocolExecution := vmOutput.ProtocolExecution
	isSettlementCompletion := vmInput.Function == DRWASettlementReceiptFunction &&
		protocolExecution.Outcome == vmcommon.ProtocolExecutionOutcomeSourceSettled
	isRefundCompletion := vmInput.Function == DRWARefundEnvelopeFunction &&
		protocolExecution.Outcome == vmcommon.ProtocolExecutionOutcomeSourceRefunded
	isCompletion := isSettlementCompletion || isRefundCompletion
	if !isCompletion {
		if len(protocolExecution.GasRefundRecipient) != 0 {
			return nil, fmt.Errorf("%w: refund recipient on non-completion outcome", ErrInvalidDRWAForwardedGas)
		}
		return nil, nil
	}

	if vmOutput.GasRemaining == 0 {
		if len(protocolExecution.GasRefundRecipient) != 0 {
			return nil, fmt.Errorf("%w: completion refund recipient without remainder", ErrInvalidDRWAForwardedGas)
		}
		return nil, nil
	}

	if len(protocolExecution.GasRefundRecipient) != len(vmInput.RecipientAddr) ||
		len(protocolExecution.GasRefundRecipient) != 32 ||
		!bytes.Equal(protocolExecution.GasRefundRecipient, vmInput.RecipientAddr) ||
		core.IsSmartContractAddress(protocolExecution.GasRefundRecipient) {
		return nil, fmt.Errorf("%w: invalid completion refund recipient", ErrInvalidDRWAForwardedGas)
	}

	return append([]byte(nil), protocolExecution.GasRefundRecipient...), nil
}

func validateDRWACompletionGasOutput(
	isCrossShard bool,
	isSettlement bool,
	vmInput *vmcommon.ContractCallInput,
	vmOutput *vmcommon.VMOutput,
) error {
	if !isCrossShard || vmInput.NativeCallOrigin != vmcommon.NativeCallOriginDRWAProtocolMessage ||
		vmInput.CallType != vmData.DirectCall || vmInput.GasLocked != 0 || vmInput.CallValue == nil ||
		vmInput.CallValue.Sign() != 0 || len(vmInput.Arguments) != 1 || vmOutput.ReturnCode != vmcommon.Ok ||
		len(vmOutput.OutputAccounts) != 0 || len(vmOutput.DeletedAccounts) != 0 ||
		len(vmOutput.TouchedAccounts) != 0 || len(vmOutput.ReturnData) != 0 ||
		(vmOutput.GasRefund != nil && vmOutput.GasRefund.Sign() != 0) {
		return fmt.Errorf("%w: source completion shape", ErrInvalidDRWAForwardedGas)
	}

	if isSettlement {
		if vmOutput.ProtocolExecution.Outcome != vmcommon.ProtocolExecutionOutcomeSourceSettled || len(vmOutput.Logs) != 0 {
			return fmt.Errorf("%w: source settlement outcome", ErrInvalidDRWAForwardedGas)
		}
		receipt, err := drwa.DecodeSettlementReceipt(vmInput.Arguments[0])
		if err != nil || !bytes.Equal(receipt.DestinationExecutionIdentity[:], vmInput.PrevTxHash) {
			return fmt.Errorf("%w: source settlement identity", ErrInvalidDRWAForwardedGas)
		}
		return nil
	}

	if vmOutput.ProtocolExecution.Outcome != vmcommon.ProtocolExecutionOutcomeSourceRefunded {
		return fmt.Errorf("%w: source refund outcome", ErrInvalidDRWAForwardedGas)
	}
	refundEnvelope, err := drwa.DecodeRefundEnvelope(vmInput.Arguments[0])
	if err != nil || !bytes.Equal(refundEnvelope.DestinationExecutionIdentity[:], vmInput.PrevTxHash) {
		return fmt.Errorf("%w: source refund identity", ErrInvalidDRWAForwardedGas)
	}
	return nil
}

func containsDRWAOutput(vmOutput *vmcommon.VMOutput) bool {
	for _, outputAccount := range vmOutput.OutputAccounts {
		if outputAccount == nil {
			continue
		}
		for _, outputTransfer := range outputAccount.OutputTransfers {
			if outputTransfer.ProtocolMessageKind == vmData.ProtocolMessageKindDRWA {
				return true
			}
		}
	}
	return false
}

func exactDRWAOutput(vmOutput *vmcommon.VMOutput) (*vmcommon.OutputAccount, *vmcommon.OutputTransfer, error) {
	if len(vmOutput.OutputAccounts) != 1 || len(vmOutput.DeletedAccounts) != 0 || len(vmOutput.TouchedAccounts) != 0 {
		return nil, nil, fmt.Errorf("%w: output account/deleted/touched cardinality", ErrInvalidDRWAForwardedGas)
	}
	if vmOutput.GasRefund != nil && vmOutput.GasRefund.Sign() != 0 {
		return nil, nil, fmt.Errorf("%w: unexpected gas refund", ErrInvalidDRWAForwardedGas)
	}

	var outputAccount *vmcommon.OutputAccount
	for key, candidate := range vmOutput.OutputAccounts {
		if candidate == nil || key != string(candidate.Address) {
			return nil, nil, fmt.Errorf("%w: nil output or map-key/address mismatch", ErrInvalidDRWAForwardedGas)
		}
		outputAccount = candidate
	}
	if outputAccount.Nonce != 0 || outputAccount.Balance != nil || outputAccount.BalanceDelta != nil ||
		len(outputAccount.StorageUpdates) != 0 || len(outputAccount.Code) != 0 || len(outputAccount.CodeMetadata) != 0 ||
		len(outputAccount.CodeDeployerAddress) != 0 || outputAccount.GasUsed != 0 ||
		outputAccount.BytesAddedToStorage != 0 || outputAccount.BytesDeletedFromStorage != 0 ||
		outputAccount.BytesConsumedByTxAsNetworking != 0 || len(outputAccount.OutputTransfers) != 1 {
		return nil, nil, fmt.Errorf("%w: non-carrier output state", ErrInvalidDRWAForwardedGas)
	}

	outputTransfer := &outputAccount.OutputTransfers[0]
	if outputTransfer.Index != 1 || outputTransfer.Value == nil || outputTransfer.Value.Sign() != 0 ||
		outputTransfer.GasLimit == 0 || outputTransfer.GasLocked != 0 || len(outputTransfer.AsyncData) != 0 ||
		outputTransfer.CallType != vmData.DirectCall || outputTransfer.ProtocolMessageKind != vmData.ProtocolMessageKindDRWA {
		return nil, nil, fmt.Errorf("%w: non-canonical transfer fields", ErrInvalidDRWAForwardedGas)
	}

	return outputAccount, outputTransfer, nil
}

func validateDRWASourceGasOutput(
	isCrossShard bool,
	vmInput *vmcommon.ContractCallInput,
	outputAccount *vmcommon.OutputAccount,
	outputTransfer *vmcommon.OutputTransfer,
) error {
	if isCrossShard || vmInput.NativeCallOrigin != vmcommon.NativeCallOriginOriginalUserTransaction ||
		vmInput.CallType != vmData.DirectCall || vmInput.GasLocked != 0 || vmInput.CallValue == nil ||
		vmInput.CallValue.Sign() != 0 || len(vmInput.Arguments) != 3 ||
		!bytes.Equal(vmInput.CallerAddr, vmInput.RecipientAddr) {
		return fmt.Errorf("%w: source admission shape", ErrInvalidDRWAForwardedGas)
	}

	payload, err := decodeDRWACall(outputTransfer.Data, vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope)
	if err != nil {
		return err
	}
	envelope, err := drwa.DecodeValueEnvelope(payload)
	if err != nil {
		return fmt.Errorf("%w: source envelope: %v", ErrInvalidDRWAForwardedGas, err)
	}
	context := envelope.Context
	if !bytes.Equal(context.SourceHolder[:], vmInput.CallerAddr) ||
		!bytes.Equal(context.DestinationHolder[:], outputAccount.Address) ||
		!bytes.Equal(context.DestinationHolder[:], vmInput.Arguments[0]) ||
		!bytes.Equal(context.RegulatedTokenID, vmInput.Arguments[1]) ||
		!bytes.Equal(context.Quantity, vmInput.Arguments[2]) ||
		!bytes.Equal(outputTransfer.SenderAddress, context.SourceHolder[:]) {
		return fmt.Errorf("%w: source envelope route or arguments", ErrInvalidDRWAForwardedGas)
	}

	reserved, err := drwaContextGasTotal(context)
	if err != nil || reserved != outputTransfer.GasLimit || vmInput.GasProvided <= reserved {
		return fmt.Errorf("%w: source reserve", ErrInvalidDRWAForwardedGas)
	}
	return nil
}

func validateDRWADestinationGasOutput(
	isCrossShard bool,
	vmInput *vmcommon.ContractCallInput,
	outputAccount *vmcommon.OutputAccount,
	outputTransfer *vmcommon.OutputTransfer,
) error {
	if !isCrossShard || vmInput.NativeCallOrigin != vmcommon.NativeCallOriginDRWAProtocolMessage ||
		vmInput.CallType != vmData.DirectCall || vmInput.GasLocked != 0 || vmInput.CallValue == nil ||
		vmInput.CallValue.Sign() != 0 || len(vmInput.Arguments) != 1 {
		return fmt.Errorf("%w: destination admission shape", ErrInvalidDRWAForwardedGas)
	}

	envelope, err := drwa.DecodeValueEnvelope(vmInput.Arguments[0])
	if err != nil {
		return fmt.Errorf("%w: destination envelope: %v", ErrInvalidDRWAForwardedGas, err)
	}
	payload, err := decodeDRWACall(outputTransfer.Data, DRWASettlementReceiptFunction)
	if err != nil {
		return err
	}
	receipt, err := drwa.DecodeSettlementReceipt(payload)
	if err != nil {
		return fmt.Errorf("%w: settlement receipt: %v", ErrInvalidDRWAForwardedGas, err)
	}
	context := envelope.Context
	if !bytes.Equal(context.SourceHolder[:], outputAccount.Address) ||
		!bytes.Equal(context.SourceHolder[:], vmInput.CallerAddr) ||
		!bytes.Equal(context.DestinationHolder[:], vmInput.RecipientAddr) ||
		!bytes.Equal(outputTransfer.SenderAddress, context.DestinationHolder[:]) ||
		receipt.EffectID != context.EffectID ||
		!bytes.Equal(receipt.DestinationExecutionIdentity[:], vmInput.CurrentTxHash) {
		return fmt.Errorf("%w: destination receipt route or identity", ErrInvalidDRWAForwardedGas)
	}

	total, err := drwaContextGasTotal(context)
	if err != nil || vmInput.GasProvided != total {
		return fmt.Errorf("%w: destination total budget", ErrInvalidDRWAForwardedGas)
	}
	minimumForwarded, err := core.SafeAddUint64(context.RefundGenerationGasLimit, context.SourceCompletionGasLimit)
	if err != nil {
		return fmt.Errorf("%w: destination minimum forwarded gas", ErrInvalidDRWAForwardedGas)
	}
	maximumForwarded, err := core.SafeAddUint64(minimumForwarded, context.DestinationGateGasLimit)
	if err != nil || outputTransfer.GasLimit < minimumForwarded || outputTransfer.GasLimit >= maximumForwarded {
		return fmt.Errorf("%w: destination forwarded gas", ErrInvalidDRWAForwardedGas)
	}
	return nil
}

func validateDRWADestinationRefundGasOutput(
	isCrossShard bool,
	vmInput *vmcommon.ContractCallInput,
	outputAccount *vmcommon.OutputAccount,
	outputTransfer *vmcommon.OutputTransfer,
) error {
	if !isCrossShard || vmInput.NativeCallOrigin != vmcommon.NativeCallOriginDRWAProtocolMessage ||
		vmInput.CallType != vmData.DirectCall || vmInput.GasLocked != 0 || vmInput.CallValue == nil ||
		vmInput.CallValue.Sign() != 0 || len(vmInput.Arguments) != 1 {
		return fmt.Errorf("%w: destination refund admission shape", ErrInvalidDRWAForwardedGas)
	}

	envelope, err := drwa.DecodeValueEnvelope(vmInput.Arguments[0])
	if err != nil {
		return fmt.Errorf("%w: destination refund envelope: %v", ErrInvalidDRWAForwardedGas, err)
	}
	payload, err := decodeDRWACall(outputTransfer.Data, DRWARefundEnvelopeFunction)
	if err != nil {
		return err
	}
	refundEnvelope, err := drwa.DecodeRefundEnvelope(payload)
	if err != nil {
		return fmt.Errorf("%w: refund result: %v", ErrInvalidDRWAForwardedGas, err)
	}
	context := envelope.Context
	if !bytes.Equal(context.SourceHolder[:], outputAccount.Address) ||
		!bytes.Equal(context.SourceHolder[:], refundEnvelope.RefundTo[:]) ||
		!bytes.Equal(context.DestinationHolder[:], vmInput.RecipientAddr) ||
		!bytes.Equal(outputTransfer.SenderAddress, context.DestinationHolder[:]) ||
		refundEnvelope.EffectID != context.EffectID ||
		!bytes.Equal(refundEnvelope.DestinationExecutionIdentity[:], vmInput.CurrentTxHash) ||
		!bytes.Equal(refundEnvelope.OriginalTransferPayload, envelope.OriginalTransferPayload) {
		return fmt.Errorf("%w: destination refund route or identity", ErrInvalidDRWAForwardedGas)
	}

	total, err := drwaContextGasTotal(context)
	if err != nil || vmInput.GasProvided != total {
		return fmt.Errorf("%w: destination refund total budget", ErrInvalidDRWAForwardedGas)
	}
	expectedForwarded, err := core.SafeAddUint64(context.SuccessReceiptGasLimit, context.SourceCompletionGasLimit)
	if err != nil || outputTransfer.GasLimit != expectedForwarded {
		return fmt.Errorf("%w: destination refund forwarded gas", ErrInvalidDRWAForwardedGas)
	}
	return nil
}

func decodeDRWACall(data []byte, expectedFunction string) ([]byte, error) {
	prefix := []byte(expectedFunction + "@")
	if !bytes.HasPrefix(data, prefix) || len(data) == len(prefix) || bytes.IndexByte(data[len(prefix):], '@') >= 0 {
		return nil, fmt.Errorf("%w: function or argument cardinality", ErrInvalidDRWAForwardedGas)
	}
	hexPayload := data[len(prefix):]
	if len(hexPayload)%2 != 0 {
		return nil, fmt.Errorf("%w: odd payload encoding", ErrInvalidDRWAForwardedGas)
	}
	payload := make([]byte, hex.DecodedLen(len(hexPayload)))
	decodedLength, err := hex.Decode(payload, hexPayload)
	if err != nil || decodedLength != len(payload) || !bytes.Equal(hexPayload, []byte(hex.EncodeToString(payload))) {
		return nil, fmt.Errorf("%w: non-canonical payload encoding", ErrInvalidDRWAForwardedGas)
	}
	return payload, nil
}

func drwaContextGasTotal(context drwa.ValueContext) (uint64, error) {
	total, err := core.SafeAddUint64(context.DestinationGateGasLimit, context.SuccessReceiptGasLimit)
	if err != nil {
		return 0, err
	}
	total, err = core.SafeAddUint64(total, context.RefundGenerationGasLimit)
	if err != nil {
		return 0, err
	}
	return core.SafeAddUint64(total, context.SourceCompletionGasLimit)
}
