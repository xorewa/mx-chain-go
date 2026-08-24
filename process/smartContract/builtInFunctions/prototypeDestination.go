package builtInFunctions

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"

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

const (
	// PrototypeSettlementReceiptFunction is the bounded S1 success carrier function.
	PrototypeSettlementReceiptFunction = scrCommon.PrototypeSettlementReceiptFunction
	// PrototypeRefundEnvelopeFunction is the bounded S1 refund carrier function.
	PrototypeRefundEnvelopeFunction = scrCommon.PrototypeRefundEnvelopeFunction
)

var (
	// ErrPrototypeDestinationDenied signals fail-closed rejection before destination credit.
	ErrPrototypeDestinationDenied = errors.New("non-normative DRWA prototype destination denied")
	// ErrPrototypeDestinationMutation signals a failure after destination state may have been journaled.
	ErrPrototypeDestinationMutation = errors.New("non-normative DRWA prototype destination mutation failed")
	// ErrInvalidPrototypeDestinationDelegate signals unusable destination construction dependencies or output.
	ErrInvalidPrototypeDestinationDelegate = errors.New("invalid non-normative DRWA prototype destination delegate")
	// ErrPrototypeReceiverDenied signals a missing, malformed or ineligible S1 receiver binding.
	ErrPrototypeReceiverDenied = errors.New("non-normative DRWA prototype receiver denied")
)

type prototypeRetainedWorkBudgetsProvider func([32]byte) (drwaprototype.WorkBudgets, uint64, error)

type prototypeDestinationArgs struct {
	delegate                    vmcommon.BuiltinFunction
	classifier                  prototypeTokenClassifier
	enableEpochsHandler         vmcommon.EnableEpochsHandler
	shardCoordinator            sharding.Coordinator
	networkDomain               [32]byte
	cebEpoch                    uint32
	retainedWorkBudgetsProvider prototypeRetainedWorkBudgetsProvider
}

type prototypeDestination struct {
	delegate                    vmcommon.BuiltinFunction
	classifier                  prototypeTokenClassifier
	enableEpochsHandler         vmcommon.EnableEpochsHandler
	shardCoordinator            sharding.Coordinator
	networkDomain               [32]byte
	cebEpoch                    uint32
	retainedWorkBudgetsProvider prototypeRetainedWorkBudgetsProvider

	mutBlockchainHook sync.RWMutex
	blockchainHook    vmcommon.BlockchainDataHook
}

func newPrototypeDestination(args prototypeDestinationArgs) (*prototypeDestination, error) {
	if check.IfNil(args.delegate) || args.classifier == nil || check.IfNil(args.enableEpochsHandler) ||
		check.IfNil(args.shardCoordinator) || args.retainedWorkBudgetsProvider == nil {
		return nil, ErrInvalidPrototypeDestinationDelegate
	}

	return &prototypeDestination{
		delegate:                    args.delegate,
		classifier:                  args.classifier,
		enableEpochsHandler:         args.enableEpochsHandler,
		shardCoordinator:            args.shardCoordinator,
		networkDomain:               args.networkDomain,
		cebEpoch:                    args.cebEpoch,
		retainedWorkBudgetsProvider: args.retainedWorkBudgetsProvider,
	}, nil
}

func (destination *prototypeDestination) setBlockchainHook(handler vmcommon.BlockchainDataHook) error {
	if check.IfNil(handler) {
		return ErrInvalidPrototypeDestinationDelegate
	}
	destination.mutBlockchainHook.Lock()
	destination.blockchainHook = handler
	destination.mutBlockchainHook.Unlock()

	return nil
}

// ProcessBuiltinFunction validates and credits one authenticated S1 direct-fungible envelope.
func (destination *prototypeDestination) ProcessBuiltinFunction(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	envelopeBytes, destinationExecutionIdentity, err := destination.validateCarrierAdmission(acntSnd, acntDst, vmInput)
	if err != nil {
		return nil, err
	}
	if destination.networkDomain == ([32]byte{}) || destination.cebEpoch == 0 {
		return nil, fmt.Errorf("%w: unavailable network domain or CEB epoch", ErrPrototypeDestinationDenied)
	}

	envelope, err := drwaprototype.DecodeValueEnvelope(envelopeBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: decode envelope: %w", ErrPrototypeDestinationDenied, err)
	}
	artifacts, err := destination.rederiveAndValidateEnvelope(vmInput, envelopeBytes, envelope)
	if err != nil {
		return nil, err
	}

	refund, refundGas, err := buildPrototypeDestinationRefund(artifacts, destinationExecutionIdentity)
	if err != nil {
		return nil, fmt.Errorf("%w: construct refund: %w", ErrPrototypeDestinationDenied, err)
	}
	if vmInput.GasProvided < refundGas {
		return nil, fmt.Errorf("%w: insufficient gas for truthful refund", ErrPrototypeDestinationDenied)
	}

	currentRound, err := destination.currentRound()
	if err != nil {
		return nil, err
	}
	if currentRound > envelope.Context.SettlementExpiry {
		return buildPrototypeDestinationRefundOutput(
			vmInput.GasProvided,
			refund,
			refundGas,
			envelope.Context.DestinationHolder[:],
			fmt.Errorf("%w: settlement expired", ErrPrototypeDestinationDenied),
		)
	}

	regulatoryErr := destination.validateDestinationProgram(acntDst, envelope, currentRound, vmInput.GasProvided)
	if regulatoryErr != nil {
		if core.IsGetNodeFromDBError(regulatoryErr) || core.IsClosingError(regulatoryErr) {
			return nil, regulatoryErr
		}
		return buildPrototypeDestinationRefundOutput(
			vmInput.GasProvided,
			refund,
			refundGas,
			envelope.Context.DestinationHolder[:],
			regulatoryErr,
		)
	}

	receipt, err := drwaprototype.BuildSettlementReceipt(
		destination.networkDomain,
		artifacts.Envelope.Context.EffectID,
		artifacts.ContextHash,
		destinationExecutionIdentity,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: construct settlement receipt: %w", ErrPrototypeDestinationDenied, err)
	}
	receiptBytes, err := drwaprototype.EncodeSettlementReceipt(receipt)
	if err != nil {
		return nil, fmt.Errorf("%w: encode settlement receipt: %w", ErrPrototypeDestinationDenied, err)
	}
	delegateInput := buildPrototypeDestinationDelegateInput(vmInput, envelope.Context)
	vmOutput, err := destination.delegate.ProcessBuiltinFunction(nil, acntDst, delegateInput)
	if err != nil {
		if core.IsGetNodeFromDBError(err) || core.IsClosingError(err) {
			return nil, err
		}
		return buildPrototypeDestinationRefundOutput(
			vmInput.GasProvided,
			refund,
			refundGas,
			envelope.Context.DestinationHolder[:],
			fmt.Errorf("%w: baseline credit: %v", ErrPrototypeDestinationMutation, err),
		)
	}
	if err = validatePrototypeDestinationOutput(vmOutput, envelope.Context.DestinationGateGasLimit); err != nil {
		return buildPrototypeDestinationRefundOutput(
			vmInput.GasProvided,
			refund,
			refundGas,
			envelope.Context.DestinationHolder[:],
			fmt.Errorf("%w: baseline output: %v", ErrPrototypeDestinationMutation, err),
		)
	}

	return buildPrototypeDestinationSuccessOutput(vmInput.GasProvided, vmOutput, envelope.Context, receiptBytes)
}

func (destination *prototypeDestination) validateCarrierAdmission(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) ([]byte, [prototypeHashLength]byte, error) {
	if !destination.enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag) {
		return nil, [prototypeHashLength]byte{}, fmt.Errorf("%w: activation", ErrPrototypeDestinationDenied)
	}
	if vmInput == nil || !check.IfNil(acntSnd) || check.IfNil(acntDst) {
		return nil, [prototypeHashLength]byte{}, fmt.Errorf("%w: destination account route", ErrPrototypeDestinationDenied)
	}
	caller := vmInput.CallerAddr
	recipient := vmInput.RecipientAddr
	if len(caller) != prototypeAddressLength || len(recipient) != prototypeAddressLength ||
		core.IsSmartContractAddress(caller) || core.IsSmartContractAddress(recipient) ||
		destination.shardCoordinator.ComputeId(caller) == destination.shardCoordinator.SelfId() ||
		destination.shardCoordinator.ComputeId(recipient) != destination.shardCoordinator.SelfId() ||
		!bytes.Equal(acntDst.AddressBytes(), recipient) {
		return nil, [prototypeHashLength]byte{}, fmt.Errorf("%w: cross-shard holder route", ErrPrototypeDestinationDenied)
	}
	if vmInput.NativeCallOrigin != vmcommon.NativeCallOriginDRWAProtocolMessage ||
		vmInput.CallType != vmData.DirectCall ||
		vmInput.Function != vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope ||
		vmInput.CallValue == nil || vmInput.CallValue.Sign() != 0 ||
		vmInput.GasLocked != 0 || vmInput.ReturnCallAfterError ||
		hasPrototypeAsyncArguments(vmInput.AsyncArguments) || len(vmInput.ESDTTransfers) != 0 ||
		len(vmInput.Arguments) != 1 {
		return nil, [prototypeHashLength]byte{}, fmt.Errorf("%w: execution origin", ErrPrototypeDestinationDenied)
	}
	if len(vmInput.CurrentTxHash) != prototypeHashLength ||
		len(vmInput.OriginalTxHash) != prototypeHashLength ||
		len(vmInput.PrevTxHash) != prototypeHashLength ||
		!bytes.Equal(vmInput.OriginalTxHash, vmInput.PrevTxHash) ||
		bytes.Equal(vmInput.CurrentTxHash, make([]byte, prototypeHashLength)) ||
		bytes.Equal(vmInput.OriginalTxHash, make([]byte, prototypeHashLength)) {
		return nil, [prototypeHashLength]byte{}, fmt.Errorf("%w: transaction identity", ErrPrototypeDestinationDenied)
	}

	var executionIdentity [prototypeHashLength]byte
	copy(executionIdentity[:], vmInput.CurrentTxHash)
	return append([]byte(nil), vmInput.Arguments[0]...), executionIdentity, nil
}

func (destination *prototypeDestination) rederiveAndValidateEnvelope(
	vmInput *vmcommon.ContractCallInput,
	envelopeBytes []byte,
	envelope *drwaprototype.ValueEnvelope,
) (*drwaprototype.DirectValueArtifacts, error) {
	context := envelope.Context
	if !bytes.Equal(context.SourceHolder[:], vmInput.CallerAddr) ||
		!bytes.Equal(context.DestinationHolder[:], vmInput.RecipientAddr) ||
		!bytes.Equal(context.OriginExecutionIdentity[:], vmInput.OriginalTxHash) {
		return nil, fmt.Errorf("%w: source, destination or origin binding", ErrPrototypeDestinationDenied)
	}

	artifacts, err := drwaprototype.BuildDirectValueArtifacts(
		destination.networkDomain,
		context.OriginExecutionIdentity,
		drwaprototype.DirectValueIntent{
			RegulatedTokenID:         context.RegulatedTokenID,
			Quantity:                 context.Quantity,
			SourceHolder:             context.SourceHolder,
			DestinationHolder:        context.DestinationHolder,
			CEBEpoch:                 context.CEBEpoch,
			SettlementExpiry:         context.SettlementExpiry,
			GasScheduleIdentity:      context.GasScheduleIdentity,
			DestinationGateGasLimit:  context.DestinationGateGasLimit,
			SuccessReceiptGasLimit:   context.SuccessReceiptGasLimit,
			RefundGenerationGasLimit: context.RefundGenerationGasLimit,
			SourceCompletionGasLimit: context.SourceCompletionGasLimit,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%w: rederive value artifacts: %w", ErrPrototypeDestinationDenied, err)
	}
	expectedEnvelope, err := drwaprototype.EncodeValueEnvelope(artifacts.Envelope)
	if err != nil || !bytes.Equal(expectedEnvelope, envelopeBytes) ||
		!bytes.Equal(artifacts.Envelope.OriginalTransferPayload, envelope.OriginalTransferPayload) ||
		artifacts.Envelope.Context.EffectID != envelope.Context.EffectID {
		return nil, fmt.Errorf("%w: envelope re-derivation mismatch", ErrPrototypeDestinationDenied)
	}

	return artifacts, nil
}

func (destination *prototypeDestination) validateDestinationProgram(
	acntDst vmcommon.UserAccountHandler,
	envelope *drwaprototype.ValueEnvelope,
	currentRound uint64,
	incomingGas uint64,
) error {
	context := envelope.Context
	if context.CEBEpoch != destination.cebEpoch {
		return fmt.Errorf("%w: CEB epoch", ErrPrototypeDestinationDenied)
	}
	regulated, err := destination.classifier(context.RegulatedTokenID)
	if err != nil {
		return fmt.Errorf("%w: classify token: %w", ErrPrototypeDestinationDenied, err)
	}
	if !regulated {
		return fmt.Errorf("%w: token is not prototype regulated", ErrPrototypeDestinationDenied)
	}

	budgets, total, err := destination.retainedWorkBudgetsProvider(context.GasScheduleIdentity)
	if err != nil {
		return fmt.Errorf("%w: retained work budget: %w", ErrPrototypeDestinationDenied, err)
	}
	if budgets.DestinationGate != context.DestinationGateGasLimit ||
		budgets.SuccessReceipt != context.SuccessReceiptGasLimit ||
		budgets.RefundGeneration != context.RefundGenerationGasLimit ||
		budgets.SourceCompletion != context.SourceCompletionGasLimit ||
		incomingGas != total {
		return fmt.Errorf("%w: gas identity, budget or total", ErrPrototypeDestinationDenied)
	}

	err = validatePrototypeReceiver(
		acntDst,
		context.RegulatedTokenID,
		context.DestinationHolder[:],
		context.CEBEpoch,
		currentRound,
	)
	if err != nil {
		return fmt.Errorf("%w: receiver gate: %w", ErrPrototypeDestinationDenied, err)
	}

	return nil
}

func validatePrototypeReceiver(
	account vmcommon.UserAccountHandler,
	tokenID []byte,
	expectedHolder []byte,
	expectedCEBEpoch uint32,
	currentRound uint64,
) error {
	if check.IfNil(account) || len(expectedHolder) != prototypeAddressLength || expectedCEBEpoch == 0 {
		return ErrPrototypeReceiverDenied
	}
	dataHandler := account.AccountDataHandler()
	if check.IfNil(dataHandler) {
		return fmt.Errorf("%w: nil data handler", ErrPrototypeReceiverDenied)
	}
	receiverGate, err := drwaprototype.LoadReceiverGateRecord(dataHandler, tokenID)
	if err != nil {
		return fmt.Errorf("%w: record: %w", ErrPrototypeReceiverDenied, err)
	}
	var holder [prototypeAddressLength]byte
	copy(holder[:], expectedHolder)
	if receiverGate.Holder != holder || receiverGate.CEBEpoch != expectedCEBEpoch ||
		!receiverGate.Admitted || currentRound > receiverGate.ValidThroughRound {
		return ErrPrototypeReceiverDenied
	}

	return nil
}

func (destination *prototypeDestination) currentRound() (uint64, error) {
	destination.mutBlockchainHook.RLock()
	hook := destination.blockchainHook
	destination.mutBlockchainHook.RUnlock()
	if check.IfNil(hook) {
		return 0, fmt.Errorf("%w: unavailable current round", ErrPrototypeDestinationDenied)
	}
	return hook.CurrentRound(), nil
}

func buildPrototypeDestinationRefund(
	artifacts *drwaprototype.DirectValueArtifacts,
	destinationExecutionIdentity [prototypeHashLength]byte,
) (drwaprototype.RefundEnvelope, uint64, error) {
	context := artifacts.Envelope.Context
	refundGas, err := core.SafeAddUint64(context.SuccessReceiptGasLimit, context.SourceCompletionGasLimit)
	if err != nil || refundGas == 0 {
		return drwaprototype.RefundEnvelope{}, 0, ErrInvalidPrototypeDestinationDelegate
	}
	refund := drwaprototype.RefundEnvelope{
		EffectID:                     context.EffectID,
		ContextHash:                  artifacts.ContextHash,
		DestinationExecutionIdentity: destinationExecutionIdentity,
		OriginalTransferPayload:      append([]byte(nil), artifacts.Envelope.OriginalTransferPayload...),
		RefundTo:                     context.SourceHolder,
	}
	_, err = drwaprototype.EncodeRefundEnvelope(refund)
	return refund, refundGas, err
}

func buildPrototypeDestinationRefundOutput(
	gasProvided uint64,
	refund drwaprototype.RefundEnvelope,
	refundGas uint64,
	sender []byte,
	cause error,
) (*vmcommon.VMOutput, error) {
	refundBytes, err := drwaprototype.EncodeRefundEnvelope(refund)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot encode truthful refund: %v", ErrInvalidPrototypeDestinationDelegate, err)
	}
	localGasUsed, err := core.SafeSubUint64(gasProvided, refundGas)
	if err != nil || localGasUsed == 0 {
		return nil, fmt.Errorf("%w: invalid refund gas partition", ErrInvalidPrototypeDestinationDelegate)
	}
	carrier := buildPrototypeDestinationCarrier(
		PrototypeRefundEnvelopeFunction,
		refundBytes,
		refundGas,
		sender,
	)
	return &vmcommon.VMOutput{
		ReturnCode:    vmcommon.UserError,
		ReturnMessage: cause.Error(),
		OutputAccounts: map[string]*vmcommon.OutputAccount{
			string(refund.RefundTo[:]): {
				Address:         append([]byte(nil), refund.RefundTo[:]...),
				OutputTransfers: []vmcommon.OutputTransfer{carrier},
			},
		},
		ProtocolExecution: &vmcommon.ProtocolExecutionInfo{
			MessageKind:  vmData.ProtocolMessageKindDRWA,
			Outcome:      vmcommon.ProtocolExecutionOutcomeRefundEnvelope,
			LocalGasUsed: localGasUsed,
			ForwardedGas: refundGas,
		},
	}, nil
}

func buildPrototypeDestinationDelegateInput(
	vmInput *vmcommon.ContractCallInput,
	context drwaprototype.ValueContext,
) *vmcommon.ContractCallInput {
	delegateInput := *vmInput
	delegateInput.Function = core.BuiltInFunctionESDTTransfer
	delegateInput.Arguments = [][]byte{
		append([]byte(nil), context.RegulatedTokenID...),
		append([]byte(nil), context.Quantity...),
	}
	delegateInput.GasProvided = context.DestinationGateGasLimit
	delegateInput.GasLocked = 0
	delegateInput.ESDTTransfers = nil

	return &delegateInput
}

func validatePrototypeDestinationOutput(vmOutput *vmcommon.VMOutput, delegateGas uint64) error {
	if vmOutput == nil || vmOutput.ReturnCode != vmcommon.Ok || vmOutput.GasRemaining > delegateGas ||
		len(vmOutput.OutputAccounts) != 0 || len(vmOutput.DeletedAccounts) != 0 || len(vmOutput.TouchedAccounts) != 0 {
		return ErrInvalidPrototypeDestinationDelegate
	}
	return nil
}

func buildPrototypeDestinationSuccessOutput(
	gasProvided uint64,
	delegateOutput *vmcommon.VMOutput,
	context drwaprototype.ValueContext,
	receiptBytes []byte,
) (*vmcommon.VMOutput, error) {
	receiptGas, err := core.SafeAddUint64(delegateOutput.GasRemaining, context.RefundGenerationGasLimit)
	if err != nil {
		return nil, fmt.Errorf("%w: receipt gas overflow", ErrInvalidPrototypeDestinationDelegate)
	}
	receiptGas, err = core.SafeAddUint64(receiptGas, context.SourceCompletionGasLimit)
	if err != nil {
		return nil, fmt.Errorf("%w: receipt gas overflow", ErrInvalidPrototypeDestinationDelegate)
	}
	localGasUsed, err := core.SafeSubUint64(gasProvided, receiptGas)
	if err != nil || localGasUsed == 0 {
		return nil, fmt.Errorf("%w: invalid success gas partition", ErrInvalidPrototypeDestinationDelegate)
	}
	carrier := buildPrototypeDestinationCarrier(
		PrototypeSettlementReceiptFunction,
		receiptBytes,
		receiptGas,
		context.DestinationHolder[:],
	)
	delegateOutput.GasRemaining = 0
	delegateOutput.OutputAccounts = map[string]*vmcommon.OutputAccount{
		string(context.SourceHolder[:]): {
			Address:         append([]byte(nil), context.SourceHolder[:]...),
			OutputTransfers: []vmcommon.OutputTransfer{carrier},
		},
	}
	delegateOutput.ProtocolExecution = &vmcommon.ProtocolExecutionInfo{
		MessageKind:  vmData.ProtocolMessageKindDRWA,
		Outcome:      vmcommon.ProtocolExecutionOutcomeSettlementReceipt,
		LocalGasUsed: localGasUsed,
		ForwardedGas: receiptGas,
	}
	return delegateOutput, nil
}

func buildPrototypeDestinationCarrier(
	function string,
	payload []byte,
	gasLimit uint64,
	sender []byte,
) vmcommon.OutputTransfer {
	data := make([]byte, 0, len(function)+1+hex.EncodedLen(len(payload)))
	data = append(data, function...)
	data = append(data, '@')
	hexPayload := make([]byte, hex.EncodedLen(len(payload)))
	hex.Encode(hexPayload, payload)
	data = append(data, hexPayload...)

	return vmcommon.OutputTransfer{
		Index:               1,
		Value:               big.NewInt(0),
		GasLimit:            gasLimit,
		Data:                data,
		CallType:            vmData.DirectCall,
		ProtocolMessageKind: vmData.ProtocolMessageKindDRWA,
		SenderAddress:       append([]byte(nil), sender...),
	}
}

// SetNewGasConfig preserves the baseline delegate's built-in contract.
func (destination *prototypeDestination) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	destination.delegate.SetNewGasConfig(gasCost)
}

// IsActive keeps transaction classification disabled before the DRWA enforcement flag.
func (destination *prototypeDestination) IsActive() bool {
	return destination != nil && destination.enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag)
}

// IsInterfaceNil returns true for a nil destination handler.
func (destination *prototypeDestination) IsInterfaceNil() bool {
	return destination == nil
}
