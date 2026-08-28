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
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
	"github.com/multiversx/mx-chain-go/process/smartContract/scrCommon"
	"github.com/multiversx/mx-chain-go/sharding"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

const (
	// DRWASettlementReceiptFunction is the bounded S1 success carrier function.
	DRWASettlementReceiptFunction = scrCommon.DRWASettlementReceiptFunction
	// DRWARefundEnvelopeFunction is the bounded S1 refund carrier function.
	DRWARefundEnvelopeFunction = scrCommon.DRWARefundEnvelopeFunction
)

var (
	// ErrDRWADestinationDenied signals fail-closed rejection before destination credit.
	ErrDRWADestinationDenied = errors.New("non-normative DRWA prototype destination denied")
	// ErrDRWADestinationMutation signals a failure after destination state may have been journaled.
	ErrDRWADestinationMutation = errors.New("non-normative DRWA prototype destination mutation failed")
	// ErrInvalidDRWADestinationDelegate signals unusable destination construction dependencies or output.
	ErrInvalidDRWADestinationDelegate = errors.New("invalid non-normative DRWA prototype destination delegate")
	// ErrDRWAReceiverDenied signals a missing, malformed or ineligible S1 receiver binding.
	ErrDRWAReceiverDenied = errors.New("non-normative DRWA prototype receiver denied")
)

type drwaRetainedWorkBudgetsProvider func([32]byte) (drwa.WorkBudgets, uint64, error)

type drwaDestinationArgs struct {
	delegate                    vmcommon.BuiltinFunction
	classifier                  drwaTokenClassifier
	enableEpochsHandler         vmcommon.EnableEpochsHandler
	shardCoordinator            sharding.Coordinator
	networkDomain               [32]byte
	cebEpoch                    uint32
	retainedWorkBudgetsProvider drwaRetainedWorkBudgetsProvider
}

type drwaDestination struct {
	delegate                    vmcommon.BuiltinFunction
	classifier                  drwaTokenClassifier
	enableEpochsHandler         vmcommon.EnableEpochsHandler
	shardCoordinator            sharding.Coordinator
	networkDomain               [32]byte
	cebEpoch                    uint32
	retainedWorkBudgetsProvider drwaRetainedWorkBudgetsProvider
	qualificationBarrier        *s1QualificationDestinationBarrier

	mutBlockchainHook sync.RWMutex
	blockchainHook    vmcommon.BlockchainDataHook
}

func newDRWADestination(args drwaDestinationArgs) (*drwaDestination, error) {
	if check.IfNil(args.delegate) || args.classifier == nil || check.IfNil(args.enableEpochsHandler) ||
		check.IfNil(args.shardCoordinator) || args.retainedWorkBudgetsProvider == nil {
		return nil, ErrInvalidDRWADestinationDelegate
	}

	barrier, err := newS1QualificationDestinationBarrier()
	if err != nil {
		return nil, err
	}

	return &drwaDestination{
		delegate:                    args.delegate,
		classifier:                  args.classifier,
		enableEpochsHandler:         args.enableEpochsHandler,
		shardCoordinator:            args.shardCoordinator,
		networkDomain:               args.networkDomain,
		cebEpoch:                    args.cebEpoch,
		retainedWorkBudgetsProvider: args.retainedWorkBudgetsProvider,
		qualificationBarrier:        barrier,
	}, nil
}

func (destination *drwaDestination) setBlockchainHook(handler vmcommon.BlockchainDataHook) error {
	if check.IfNil(handler) {
		return ErrInvalidDRWADestinationDelegate
	}
	destination.mutBlockchainHook.Lock()
	destination.blockchainHook = handler
	destination.mutBlockchainHook.Unlock()

	return nil
}

// ProcessBuiltinFunction validates and credits one authenticated S1 direct-fungible envelope.
func (destination *drwaDestination) ProcessBuiltinFunction(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	envelopeBytes, destinationExecutionIdentity, err := destination.validateCarrierAdmission(acntSnd, acntDst, vmInput)
	if err != nil {
		return nil, err
	}
	if destination.networkDomain == ([32]byte{}) || destination.cebEpoch == 0 {
		return nil, fmt.Errorf("%w: unavailable network domain or CEB epoch", ErrDRWADestinationDenied)
	}

	envelope, err := drwa.DecodeValueEnvelope(envelopeBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: decode envelope: %w", ErrDRWADestinationDenied, err)
	}
	artifacts, err := destination.rederiveAndValidateEnvelope(vmInput, envelopeBytes, envelope)
	if err != nil {
		return nil, err
	}

	refund, refundGas, err := buildDRWADestinationRefund(artifacts, destinationExecutionIdentity)
	if err != nil {
		return nil, fmt.Errorf("%w: construct refund: %w", ErrDRWADestinationDenied, err)
	}
	if vmInput.GasProvided < refundGas {
		return nil, fmt.Errorf("%w: insufficient gas for truthful refund", ErrDRWADestinationDenied)
	}

	currentRound, err := destination.currentRound()
	if err != nil {
		return nil, err
	}
	if currentRound > envelope.Context.SettlementExpiry {
		return buildDRWADestinationRefundOutput(
			vmInput.GasProvided,
			refund,
			refundGas,
			envelope.Context.DestinationHolder[:],
			fmt.Errorf("%w: settlement expired", ErrDRWADestinationDenied),
		)
	}

	regulatoryErr := destination.validateDestinationProgram(acntDst, envelope, currentRound, vmInput.GasProvided)
	if regulatoryErr != nil {
		if core.IsGetNodeFromDBError(regulatoryErr) || core.IsClosingError(regulatoryErr) {
			return nil, regulatoryErr
		}
		return buildDRWADestinationRefundOutput(
			vmInput.GasProvided,
			refund,
			refundGas,
			envelope.Context.DestinationHolder[:],
			regulatoryErr,
		)
	}

	receipt, err := drwa.BuildSettlementReceipt(
		destination.networkDomain,
		artifacts.Envelope.Context.EffectID,
		artifacts.ContextHash,
		destinationExecutionIdentity,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: construct settlement receipt: %w", ErrDRWADestinationDenied, err)
	}
	receiptBytes, err := drwa.EncodeSettlementReceipt(receipt)
	if err != nil {
		return nil, fmt.Errorf("%w: encode settlement receipt: %w", ErrDRWADestinationDenied, err)
	}
	delegateInput := buildDRWADestinationDelegateInput(vmInput, envelope.Context)
	vmOutput, err := destination.delegate.ProcessBuiltinFunction(nil, acntDst, delegateInput)
	if err != nil {
		if core.IsGetNodeFromDBError(err) || core.IsClosingError(err) {
			return nil, err
		}
		return buildDRWADestinationRefundOutput(
			vmInput.GasProvided,
			refund,
			refundGas,
			envelope.Context.DestinationHolder[:],
			fmt.Errorf("%w: baseline credit: %v", ErrDRWADestinationMutation, err),
		)
	}
	if err = validateDRWADestinationOutput(vmOutput, envelope.Context.DestinationGateGasLimit); err != nil {
		return buildDRWADestinationRefundOutput(
			vmInput.GasProvided,
			refund,
			refundGas,
			envelope.Context.DestinationHolder[:],
			fmt.Errorf("%w: baseline output: %v", ErrDRWADestinationMutation, err),
		)
	}
	if err = destination.qualificationBarrier.reach(
		vmInput,
		envelope.Context.EffectID,
		artifacts.ContextHash,
		destination.networkDomain,
		uint32(vmData.ProtocolMessageKindDRWA),
	); err != nil {
		return nil, fmt.Errorf("%w: qualification barrier: %v", ErrDRWADestinationMutation, err)
	}

	return buildDRWADestinationSuccessOutput(vmInput.GasProvided, vmOutput, envelope.Context, receiptBytes)
}

func (destination *drwaDestination) validateCarrierAdmission(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) ([]byte, [drwaHashLength]byte, error) {
	if !destination.enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag) {
		return nil, [drwaHashLength]byte{}, fmt.Errorf("%w: activation", ErrDRWADestinationDenied)
	}
	if vmInput == nil || !check.IfNil(acntSnd) || check.IfNil(acntDst) {
		return nil, [drwaHashLength]byte{}, fmt.Errorf("%w: destination account route", ErrDRWADestinationDenied)
	}
	caller := vmInput.CallerAddr
	recipient := vmInput.RecipientAddr
	if len(caller) != drwaAddressLength || len(recipient) != drwaAddressLength ||
		core.IsSmartContractAddress(caller) || core.IsSmartContractAddress(recipient) ||
		destination.shardCoordinator.ComputeId(caller) == destination.shardCoordinator.SelfId() ||
		destination.shardCoordinator.ComputeId(recipient) != destination.shardCoordinator.SelfId() ||
		!bytes.Equal(acntDst.AddressBytes(), recipient) {
		return nil, [drwaHashLength]byte{}, fmt.Errorf("%w: cross-shard holder route", ErrDRWADestinationDenied)
	}
	if vmInput.NativeCallOrigin != vmcommon.NativeCallOriginDRWAProtocolMessage ||
		vmInput.CallType != vmData.DirectCall ||
		vmInput.Function != vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope ||
		vmInput.CallValue == nil || vmInput.CallValue.Sign() != 0 ||
		vmInput.GasLocked != 0 || vmInput.ReturnCallAfterError ||
		hasDRWAAsyncArguments(vmInput.AsyncArguments) || len(vmInput.ESDTTransfers) != 0 ||
		len(vmInput.Arguments) != 1 {
		return nil, [drwaHashLength]byte{}, fmt.Errorf("%w: execution origin", ErrDRWADestinationDenied)
	}
	if len(vmInput.CurrentTxHash) != drwaHashLength ||
		len(vmInput.OriginalTxHash) != drwaHashLength ||
		len(vmInput.PrevTxHash) != drwaHashLength ||
		!bytes.Equal(vmInput.OriginalTxHash, vmInput.PrevTxHash) ||
		bytes.Equal(vmInput.CurrentTxHash, make([]byte, drwaHashLength)) ||
		bytes.Equal(vmInput.OriginalTxHash, make([]byte, drwaHashLength)) {
		return nil, [drwaHashLength]byte{}, fmt.Errorf("%w: transaction identity", ErrDRWADestinationDenied)
	}

	var executionIdentity [drwaHashLength]byte
	copy(executionIdentity[:], vmInput.CurrentTxHash)
	return append([]byte(nil), vmInput.Arguments[0]...), executionIdentity, nil
}

func (destination *drwaDestination) rederiveAndValidateEnvelope(
	vmInput *vmcommon.ContractCallInput,
	envelopeBytes []byte,
	envelope *drwa.ValueEnvelope,
) (*drwa.DirectValueArtifacts, error) {
	context := envelope.Context
	if !bytes.Equal(context.SourceHolder[:], vmInput.CallerAddr) ||
		!bytes.Equal(context.DestinationHolder[:], vmInput.RecipientAddr) ||
		!bytes.Equal(context.OriginExecutionIdentity[:], vmInput.OriginalTxHash) {
		return nil, fmt.Errorf("%w: source, destination or origin binding", ErrDRWADestinationDenied)
	}

	artifacts, err := drwa.BuildDirectValueArtifacts(
		destination.networkDomain,
		context.OriginExecutionIdentity,
		drwa.DirectValueIntent{
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
		return nil, fmt.Errorf("%w: rederive value artifacts: %w", ErrDRWADestinationDenied, err)
	}
	expectedEnvelope, err := drwa.EncodeValueEnvelope(artifacts.Envelope)
	if err != nil || !bytes.Equal(expectedEnvelope, envelopeBytes) ||
		!bytes.Equal(artifacts.Envelope.OriginalTransferPayload, envelope.OriginalTransferPayload) ||
		artifacts.Envelope.Context.EffectID != envelope.Context.EffectID {
		return nil, fmt.Errorf("%w: envelope re-derivation mismatch", ErrDRWADestinationDenied)
	}

	return artifacts, nil
}

func (destination *drwaDestination) validateDestinationProgram(
	acntDst vmcommon.UserAccountHandler,
	envelope *drwa.ValueEnvelope,
	currentRound uint64,
	incomingGas uint64,
) error {
	context := envelope.Context
	if context.CEBEpoch != destination.cebEpoch {
		return fmt.Errorf("%w: CEB epoch", ErrDRWADestinationDenied)
	}
	regulated, err := destination.classifier(context.RegulatedTokenID)
	if err != nil {
		return fmt.Errorf("%w: classify token: %w", ErrDRWADestinationDenied, err)
	}
	if !regulated {
		return fmt.Errorf("%w: token is not prototype regulated", ErrDRWADestinationDenied)
	}

	budgets, total, err := destination.retainedWorkBudgetsProvider(context.GasScheduleIdentity)
	if err != nil {
		return fmt.Errorf("%w: retained work budget: %w", ErrDRWADestinationDenied, err)
	}
	if budgets.DestinationGate != context.DestinationGateGasLimit ||
		budgets.SuccessReceipt != context.SuccessReceiptGasLimit ||
		budgets.RefundGeneration != context.RefundGenerationGasLimit ||
		budgets.SourceCompletion != context.SourceCompletionGasLimit ||
		incomingGas != total {
		return fmt.Errorf("%w: gas identity, budget or total", ErrDRWADestinationDenied)
	}

	err = validateDRWAReceiver(
		acntDst,
		context.RegulatedTokenID,
		context.DestinationHolder[:],
		context.CEBEpoch,
		currentRound,
	)
	if err != nil {
		return fmt.Errorf("%w: receiver gate: %w", ErrDRWADestinationDenied, err)
	}

	return nil
}

func validateDRWAReceiver(
	account vmcommon.UserAccountHandler,
	tokenID []byte,
	expectedHolder []byte,
	expectedCEBEpoch uint32,
	currentRound uint64,
) error {
	if check.IfNil(account) || len(expectedHolder) != drwaAddressLength || expectedCEBEpoch == 0 {
		return ErrDRWAReceiverDenied
	}
	dataHandler := account.AccountDataHandler()
	if check.IfNil(dataHandler) {
		return fmt.Errorf("%w: nil data handler", ErrDRWAReceiverDenied)
	}
	receiverGate, err := drwa.LoadReceiverGateRecord(dataHandler, tokenID)
	if err != nil {
		return fmt.Errorf("%w: record: %w", ErrDRWAReceiverDenied, err)
	}
	var holder [drwaAddressLength]byte
	copy(holder[:], expectedHolder)
	if receiverGate.Holder != holder || receiverGate.CEBEpoch != expectedCEBEpoch ||
		!receiverGate.Admitted || currentRound > receiverGate.ValidThroughRound {
		return ErrDRWAReceiverDenied
	}

	return nil
}

func (destination *drwaDestination) currentRound() (uint64, error) {
	destination.mutBlockchainHook.RLock()
	hook := destination.blockchainHook
	destination.mutBlockchainHook.RUnlock()
	if check.IfNil(hook) {
		return 0, fmt.Errorf("%w: unavailable current round", ErrDRWADestinationDenied)
	}
	return hook.CurrentRound(), nil
}

func buildDRWADestinationRefund(
	artifacts *drwa.DirectValueArtifacts,
	destinationExecutionIdentity [drwaHashLength]byte,
) (drwa.RefundEnvelope, uint64, error) {
	context := artifacts.Envelope.Context
	refundGas, err := core.SafeAddUint64(context.SuccessReceiptGasLimit, context.SourceCompletionGasLimit)
	if err != nil || refundGas == 0 {
		return drwa.RefundEnvelope{}, 0, ErrInvalidDRWADestinationDelegate
	}
	refund := drwa.RefundEnvelope{
		EffectID:                     context.EffectID,
		ContextHash:                  artifacts.ContextHash,
		DestinationExecutionIdentity: destinationExecutionIdentity,
		OriginalTransferPayload:      append([]byte(nil), artifacts.Envelope.OriginalTransferPayload...),
		RefundTo:                     context.SourceHolder,
	}
	_, err = drwa.EncodeRefundEnvelope(refund)
	return refund, refundGas, err
}

func buildDRWADestinationRefundOutput(
	gasProvided uint64,
	refund drwa.RefundEnvelope,
	refundGas uint64,
	sender []byte,
	cause error,
) (*vmcommon.VMOutput, error) {
	refundBytes, err := drwa.EncodeRefundEnvelope(refund)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot encode truthful refund: %v", ErrInvalidDRWADestinationDelegate, err)
	}
	localGasUsed, err := core.SafeSubUint64(gasProvided, refundGas)
	if err != nil || localGasUsed == 0 {
		return nil, fmt.Errorf("%w: invalid refund gas partition", ErrInvalidDRWADestinationDelegate)
	}
	carrier := buildDRWADestinationCarrier(
		DRWARefundEnvelopeFunction,
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

func buildDRWADestinationDelegateInput(
	vmInput *vmcommon.ContractCallInput,
	context drwa.ValueContext,
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

func validateDRWADestinationOutput(vmOutput *vmcommon.VMOutput, delegateGas uint64) error {
	if vmOutput == nil || vmOutput.ReturnCode != vmcommon.Ok || vmOutput.GasRemaining > delegateGas ||
		len(vmOutput.OutputAccounts) != 0 || len(vmOutput.DeletedAccounts) != 0 || len(vmOutput.TouchedAccounts) != 0 {
		return ErrInvalidDRWADestinationDelegate
	}
	return nil
}

func buildDRWADestinationSuccessOutput(
	gasProvided uint64,
	delegateOutput *vmcommon.VMOutput,
	context drwa.ValueContext,
	receiptBytes []byte,
) (*vmcommon.VMOutput, error) {
	receiptGas, err := core.SafeAddUint64(delegateOutput.GasRemaining, context.RefundGenerationGasLimit)
	if err != nil {
		return nil, fmt.Errorf("%w: receipt gas overflow", ErrInvalidDRWADestinationDelegate)
	}
	receiptGas, err = core.SafeAddUint64(receiptGas, context.SourceCompletionGasLimit)
	if err != nil {
		return nil, fmt.Errorf("%w: receipt gas overflow", ErrInvalidDRWADestinationDelegate)
	}
	localGasUsed, err := core.SafeSubUint64(gasProvided, receiptGas)
	if err != nil || localGasUsed == 0 {
		return nil, fmt.Errorf("%w: invalid success gas partition", ErrInvalidDRWADestinationDelegate)
	}
	carrier := buildDRWADestinationCarrier(
		DRWASettlementReceiptFunction,
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

func buildDRWADestinationCarrier(
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
func (destination *drwaDestination) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	destination.delegate.SetNewGasConfig(gasCost)
}

// IsActive keeps transaction classification disabled before the DRWA enforcement flag.
func (destination *drwaDestination) IsActive() bool {
	return destination != nil && destination.enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag)
}

// IsInterfaceNil returns true for a nil destination handler.
func (destination *drwaDestination) IsInterfaceNil() bool {
	return destination == nil
}
