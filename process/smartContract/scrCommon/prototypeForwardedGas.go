package scrCommon

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

const (
	// PrototypeSourceDebitFunction is the bounded S1 source-only entry point.
	PrototypeSourceDebitFunction = "DRWAPrototypeTransfer"
	// PrototypeSettlementReceiptFunction is the bounded S1 success-result entry point.
	PrototypeSettlementReceiptFunction = "DRWASettlementReceipt"
	// PrototypeRefundEnvelopeFunction is the bounded S1 denial-result entry point.
	PrototypeRefundEnvelopeFunction = "DRWARefundEnvelope"
)

// ErrInvalidPrototypeForwardedGas signals a malformed or arithmetically invalid successful DRWA output.
var ErrInvalidPrototypeForwardedGas = errors.New("invalid non-normative DRWA prototype forwarded-gas output")

// PrototypeExecutionGasUsed validates one explicit S1 protocol outcome and returns its declared
// local work. Non-candidates return matched=false and retain baseline accounting. Refund outcomes
// return refund=true so the processor can revert the captured destination mutation snapshot before
// treating the single refund carrier as canonical output.
func PrototypeExecutionGasUsed(
	txTypeOnDestination process.TransactionType,
	isCrossShard bool,
	vmInput *vmcommon.ContractCallInput,
	vmOutput *vmcommon.VMOutput,
) (gasUsed uint64, matched bool, refund bool, err error) {
	if vmInput == nil || vmOutput == nil {
		return 0, false, false, nil
	}

	hasDRWAOutput := containsPrototypeDRWAOutput(vmOutput)
	protocolExecution := vmOutput.ProtocolExecution
	if protocolExecution == nil {
		if hasDRWAOutput {
			return 0, true, false, fmt.Errorf("%w: DRWA output without execution contract", ErrInvalidPrototypeForwardedGas)
		}
		return 0, false, false, nil
	}
	if protocolExecution.MessageKind != vmData.ProtocolMessageKindDRWA ||
		protocolExecution.Outcome == vmcommon.ProtocolExecutionOutcomeNone ||
		protocolExecution.LocalGasUsed == 0 {
		return 0, true, false, fmt.Errorf("%w: invalid execution contract", ErrInvalidPrototypeForwardedGas)
	}

	isSourceFunction := vmInput.Function == PrototypeSourceDebitFunction
	isDestinationFunction := vmInput.Function == vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope
	isSettlementCompletion := vmInput.Function == PrototypeSettlementReceiptFunction
	isRefundCompletion := vmInput.Function == PrototypeRefundEnvelopeFunction
	if !isSourceFunction && !isDestinationFunction && !isSettlementCompletion && !isRefundCompletion {
		return 0, true, false, fmt.Errorf("%w: protocol contract from an unrelated function", ErrInvalidPrototypeForwardedGas)
	}
	if txTypeOnDestination != process.BuiltInFunctionCall {
		return 0, true, false, fmt.Errorf("%w: unexpected destination transaction type", ErrInvalidPrototypeForwardedGas)
	}
	if isSettlementCompletion || isRefundCompletion {
		err = validatePrototypeCompletionGasOutput(
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
			return 0, true, false, fmt.Errorf("%w: completion gas partition does not conserve input", ErrInvalidPrototypeForwardedGas)
		}
		return protocolExecution.LocalGasUsed, true, false, nil
	}

	outputAccount, outputTransfer, err := exactPrototypeOutput(vmOutput)
	if err != nil {
		return 0, true, false, err
	}
	if isSourceFunction {
		if vmOutput.ReturnCode != vmcommon.Ok || protocolExecution.Outcome != vmcommon.ProtocolExecutionOutcomeForward {
			return 0, true, false, fmt.Errorf("%w: invalid source outcome", ErrInvalidPrototypeForwardedGas)
		}
		err = validatePrototypeSourceGasOutput(isCrossShard, vmInput, outputAccount, outputTransfer)
	} else {
		switch protocolExecution.Outcome {
		case vmcommon.ProtocolExecutionOutcomeSettlementReceipt:
			if vmOutput.ReturnCode != vmcommon.Ok {
				return 0, true, false, fmt.Errorf("%w: failed settlement outcome", ErrInvalidPrototypeForwardedGas)
			}
			err = validatePrototypeDestinationGasOutput(isCrossShard, vmInput, outputAccount, outputTransfer)
		case vmcommon.ProtocolExecutionOutcomeRefundEnvelope:
			if vmOutput.ReturnCode == vmcommon.Ok {
				return 0, true, false, fmt.Errorf("%w: successful refund outcome", ErrInvalidPrototypeForwardedGas)
			}
			refund = true
			err = validatePrototypeDestinationRefundGasOutput(isCrossShard, vmInput, outputAccount, outputTransfer)
		default:
			return 0, true, false, fmt.Errorf("%w: unsupported destination outcome", ErrInvalidPrototypeForwardedGas)
		}
	}
	if err != nil {
		return 0, true, false, err
	}

	if protocolExecution.ForwardedGas != outputTransfer.GasLimit {
		return 0, true, false, fmt.Errorf("%w: forwarded gas declaration mismatch", ErrInvalidPrototypeForwardedGas)
	}
	accountedGas, err := core.SafeAddUint64(protocolExecution.LocalGasUsed, protocolExecution.ForwardedGas)
	if err != nil {
		return 0, true, false, fmt.Errorf("%w: local plus forwarded gas: %v", ErrInvalidPrototypeForwardedGas, err)
	}
	accountedGas, err = core.SafeAddUint64(accountedGas, vmOutput.GasRemaining)
	if err != nil || accountedGas != vmInput.GasProvided {
		return 0, true, false, fmt.Errorf("%w: gas partition does not conserve input", ErrInvalidPrototypeForwardedGas)
	}

	return protocolExecution.LocalGasUsed, true, refund, nil
}

func validatePrototypeCompletionGasOutput(
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
		return fmt.Errorf("%w: source completion shape", ErrInvalidPrototypeForwardedGas)
	}

	if isSettlement {
		if vmOutput.ProtocolExecution.Outcome != vmcommon.ProtocolExecutionOutcomeSourceSettled || len(vmOutput.Logs) != 0 {
			return fmt.Errorf("%w: source settlement outcome", ErrInvalidPrototypeForwardedGas)
		}
		receipt, err := drwaprototype.DecodeSettlementReceipt(vmInput.Arguments[0])
		if err != nil || !bytes.Equal(receipt.DestinationExecutionIdentity[:], vmInput.PrevTxHash) {
			return fmt.Errorf("%w: source settlement identity", ErrInvalidPrototypeForwardedGas)
		}
		return nil
	}

	if vmOutput.ProtocolExecution.Outcome != vmcommon.ProtocolExecutionOutcomeSourceRefunded {
		return fmt.Errorf("%w: source refund outcome", ErrInvalidPrototypeForwardedGas)
	}
	refundEnvelope, err := drwaprototype.DecodeRefundEnvelope(vmInput.Arguments[0])
	if err != nil || !bytes.Equal(refundEnvelope.DestinationExecutionIdentity[:], vmInput.PrevTxHash) {
		return fmt.Errorf("%w: source refund identity", ErrInvalidPrototypeForwardedGas)
	}
	return nil
}

func containsPrototypeDRWAOutput(vmOutput *vmcommon.VMOutput) bool {
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

func exactPrototypeOutput(vmOutput *vmcommon.VMOutput) (*vmcommon.OutputAccount, *vmcommon.OutputTransfer, error) {
	if len(vmOutput.OutputAccounts) != 1 || len(vmOutput.DeletedAccounts) != 0 || len(vmOutput.TouchedAccounts) != 0 {
		return nil, nil, fmt.Errorf("%w: output account/deleted/touched cardinality", ErrInvalidPrototypeForwardedGas)
	}
	if vmOutput.GasRefund != nil && vmOutput.GasRefund.Sign() != 0 {
		return nil, nil, fmt.Errorf("%w: unexpected gas refund", ErrInvalidPrototypeForwardedGas)
	}

	var outputAccount *vmcommon.OutputAccount
	for key, candidate := range vmOutput.OutputAccounts {
		if candidate == nil || key != string(candidate.Address) {
			return nil, nil, fmt.Errorf("%w: nil output or map-key/address mismatch", ErrInvalidPrototypeForwardedGas)
		}
		outputAccount = candidate
	}
	if outputAccount.Nonce != 0 || outputAccount.Balance != nil || outputAccount.BalanceDelta != nil ||
		len(outputAccount.StorageUpdates) != 0 || len(outputAccount.Code) != 0 || len(outputAccount.CodeMetadata) != 0 ||
		len(outputAccount.CodeDeployerAddress) != 0 || outputAccount.GasUsed != 0 ||
		outputAccount.BytesAddedToStorage != 0 || outputAccount.BytesDeletedFromStorage != 0 ||
		outputAccount.BytesConsumedByTxAsNetworking != 0 || len(outputAccount.OutputTransfers) != 1 {
		return nil, nil, fmt.Errorf("%w: non-carrier output state", ErrInvalidPrototypeForwardedGas)
	}

	outputTransfer := &outputAccount.OutputTransfers[0]
	if outputTransfer.Index != 1 || outputTransfer.Value == nil || outputTransfer.Value.Sign() != 0 ||
		outputTransfer.GasLimit == 0 || outputTransfer.GasLocked != 0 || len(outputTransfer.AsyncData) != 0 ||
		outputTransfer.CallType != vmData.DirectCall || outputTransfer.ProtocolMessageKind != vmData.ProtocolMessageKindDRWA {
		return nil, nil, fmt.Errorf("%w: non-canonical transfer fields", ErrInvalidPrototypeForwardedGas)
	}

	return outputAccount, outputTransfer, nil
}

func validatePrototypeSourceGasOutput(
	isCrossShard bool,
	vmInput *vmcommon.ContractCallInput,
	outputAccount *vmcommon.OutputAccount,
	outputTransfer *vmcommon.OutputTransfer,
) error {
	if isCrossShard || vmInput.NativeCallOrigin != vmcommon.NativeCallOriginOriginalUserTransaction ||
		vmInput.CallType != vmData.DirectCall || vmInput.GasLocked != 0 || vmInput.CallValue == nil ||
		vmInput.CallValue.Sign() != 0 || len(vmInput.Arguments) != 3 ||
		!bytes.Equal(vmInput.CallerAddr, vmInput.RecipientAddr) {
		return fmt.Errorf("%w: source admission shape", ErrInvalidPrototypeForwardedGas)
	}

	payload, err := decodePrototypeCall(outputTransfer.Data, vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope)
	if err != nil {
		return err
	}
	envelope, err := drwaprototype.DecodeValueEnvelope(payload)
	if err != nil {
		return fmt.Errorf("%w: source envelope: %v", ErrInvalidPrototypeForwardedGas, err)
	}
	context := envelope.Context
	if !bytes.Equal(context.SourceHolder[:], vmInput.CallerAddr) ||
		!bytes.Equal(context.DestinationHolder[:], outputAccount.Address) ||
		!bytes.Equal(context.DestinationHolder[:], vmInput.Arguments[0]) ||
		!bytes.Equal(context.RegulatedTokenID, vmInput.Arguments[1]) ||
		!bytes.Equal(context.Quantity, vmInput.Arguments[2]) ||
		!bytes.Equal(outputTransfer.SenderAddress, context.SourceHolder[:]) {
		return fmt.Errorf("%w: source envelope route or arguments", ErrInvalidPrototypeForwardedGas)
	}

	reserved, err := prototypeContextGasTotal(context)
	if err != nil || reserved != outputTransfer.GasLimit || vmInput.GasProvided <= reserved {
		return fmt.Errorf("%w: source reserve", ErrInvalidPrototypeForwardedGas)
	}
	return nil
}

func validatePrototypeDestinationGasOutput(
	isCrossShard bool,
	vmInput *vmcommon.ContractCallInput,
	outputAccount *vmcommon.OutputAccount,
	outputTransfer *vmcommon.OutputTransfer,
) error {
	if !isCrossShard || vmInput.NativeCallOrigin != vmcommon.NativeCallOriginDRWAProtocolMessage ||
		vmInput.CallType != vmData.DirectCall || vmInput.GasLocked != 0 || vmInput.CallValue == nil ||
		vmInput.CallValue.Sign() != 0 || len(vmInput.Arguments) != 1 {
		return fmt.Errorf("%w: destination admission shape", ErrInvalidPrototypeForwardedGas)
	}

	envelope, err := drwaprototype.DecodeValueEnvelope(vmInput.Arguments[0])
	if err != nil {
		return fmt.Errorf("%w: destination envelope: %v", ErrInvalidPrototypeForwardedGas, err)
	}
	payload, err := decodePrototypeCall(outputTransfer.Data, PrototypeSettlementReceiptFunction)
	if err != nil {
		return err
	}
	receipt, err := drwaprototype.DecodeSettlementReceipt(payload)
	if err != nil {
		return fmt.Errorf("%w: settlement receipt: %v", ErrInvalidPrototypeForwardedGas, err)
	}
	context := envelope.Context
	if !bytes.Equal(context.SourceHolder[:], outputAccount.Address) ||
		!bytes.Equal(context.SourceHolder[:], vmInput.CallerAddr) ||
		!bytes.Equal(context.DestinationHolder[:], vmInput.RecipientAddr) ||
		!bytes.Equal(outputTransfer.SenderAddress, context.DestinationHolder[:]) ||
		receipt.EffectID != context.EffectID ||
		!bytes.Equal(receipt.DestinationExecutionIdentity[:], vmInput.CurrentTxHash) {
		return fmt.Errorf("%w: destination receipt route or identity", ErrInvalidPrototypeForwardedGas)
	}

	total, err := prototypeContextGasTotal(context)
	if err != nil || vmInput.GasProvided != total {
		return fmt.Errorf("%w: destination total budget", ErrInvalidPrototypeForwardedGas)
	}
	minimumForwarded, err := core.SafeAddUint64(context.RefundGenerationGasLimit, context.SourceCompletionGasLimit)
	if err != nil {
		return fmt.Errorf("%w: destination minimum forwarded gas", ErrInvalidPrototypeForwardedGas)
	}
	maximumForwarded, err := core.SafeAddUint64(minimumForwarded, context.DestinationGateGasLimit)
	if err != nil || outputTransfer.GasLimit < minimumForwarded || outputTransfer.GasLimit >= maximumForwarded {
		return fmt.Errorf("%w: destination forwarded gas", ErrInvalidPrototypeForwardedGas)
	}
	return nil
}

func validatePrototypeDestinationRefundGasOutput(
	isCrossShard bool,
	vmInput *vmcommon.ContractCallInput,
	outputAccount *vmcommon.OutputAccount,
	outputTransfer *vmcommon.OutputTransfer,
) error {
	if !isCrossShard || vmInput.NativeCallOrigin != vmcommon.NativeCallOriginDRWAProtocolMessage ||
		vmInput.CallType != vmData.DirectCall || vmInput.GasLocked != 0 || vmInput.CallValue == nil ||
		vmInput.CallValue.Sign() != 0 || len(vmInput.Arguments) != 1 {
		return fmt.Errorf("%w: destination refund admission shape", ErrInvalidPrototypeForwardedGas)
	}

	envelope, err := drwaprototype.DecodeValueEnvelope(vmInput.Arguments[0])
	if err != nil {
		return fmt.Errorf("%w: destination refund envelope: %v", ErrInvalidPrototypeForwardedGas, err)
	}
	payload, err := decodePrototypeCall(outputTransfer.Data, PrototypeRefundEnvelopeFunction)
	if err != nil {
		return err
	}
	refundEnvelope, err := drwaprototype.DecodeRefundEnvelope(payload)
	if err != nil {
		return fmt.Errorf("%w: refund result: %v", ErrInvalidPrototypeForwardedGas, err)
	}
	context := envelope.Context
	if !bytes.Equal(context.SourceHolder[:], outputAccount.Address) ||
		!bytes.Equal(context.SourceHolder[:], refundEnvelope.RefundTo[:]) ||
		!bytes.Equal(context.DestinationHolder[:], vmInput.RecipientAddr) ||
		!bytes.Equal(outputTransfer.SenderAddress, context.DestinationHolder[:]) ||
		refundEnvelope.EffectID != context.EffectID ||
		!bytes.Equal(refundEnvelope.DestinationExecutionIdentity[:], vmInput.CurrentTxHash) ||
		!bytes.Equal(refundEnvelope.OriginalTransferPayload, envelope.OriginalTransferPayload) {
		return fmt.Errorf("%w: destination refund route or identity", ErrInvalidPrototypeForwardedGas)
	}

	total, err := prototypeContextGasTotal(context)
	if err != nil || vmInput.GasProvided != total {
		return fmt.Errorf("%w: destination refund total budget", ErrInvalidPrototypeForwardedGas)
	}
	expectedForwarded, err := core.SafeAddUint64(context.SuccessReceiptGasLimit, context.SourceCompletionGasLimit)
	if err != nil || outputTransfer.GasLimit != expectedForwarded {
		return fmt.Errorf("%w: destination refund forwarded gas", ErrInvalidPrototypeForwardedGas)
	}
	return nil
}

func decodePrototypeCall(data []byte, expectedFunction string) ([]byte, error) {
	prefix := []byte(expectedFunction + "@")
	if !bytes.HasPrefix(data, prefix) || len(data) == len(prefix) || bytes.IndexByte(data[len(prefix):], '@') >= 0 {
		return nil, fmt.Errorf("%w: function or argument cardinality", ErrInvalidPrototypeForwardedGas)
	}
	hexPayload := data[len(prefix):]
	if len(hexPayload)%2 != 0 {
		return nil, fmt.Errorf("%w: odd payload encoding", ErrInvalidPrototypeForwardedGas)
	}
	payload := make([]byte, hex.DecodedLen(len(hexPayload)))
	decodedLength, err := hex.Decode(payload, hexPayload)
	if err != nil || decodedLength != len(payload) || !bytes.Equal(hexPayload, []byte(hex.EncodeToString(payload))) {
		return nil, fmt.Errorf("%w: non-canonical payload encoding", ErrInvalidPrototypeForwardedGas)
	}
	return payload, nil
}

func prototypeContextGasTotal(context drwaprototype.ValueContext) (uint64, error) {
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
