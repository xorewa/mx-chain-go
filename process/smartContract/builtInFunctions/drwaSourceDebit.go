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
	// DRWASourceDebitFunction is the bounded S1 source-only entry point.
	DRWASourceDebitFunction = scrCommon.DRWASourceDebitFunction
	drwaAddressLength       = 32
	drwaHashLength          = 32
)

var (
	// ErrDRWASourceDebitDenied signals fail-closed rejection before source mutation.
	ErrDRWASourceDebitDenied = errors.New("non-normative DRWA prototype source debit denied")
	// ErrDRWASourceDebitMutation signals an error after protected state may have been journaled.
	ErrDRWASourceDebitMutation = errors.New("non-normative DRWA prototype source debit mutation failed")
	// ErrInvalidDRWASourceDebitDelegate signals unusable source-debit construction dependencies.
	ErrInvalidDRWASourceDebitDelegate = errors.New("invalid non-normative DRWA prototype source debit delegate")
)

type drwaCurrentWorkBudgetsProvider func() ([32]byte, drwa.WorkBudgets, uint64, error)
type drwaOpenEffectCreator func(vmcommon.AccountDataHandler, drwa.OpenEffect) error

type drwaSourceDebitArgs struct {
	delegate                   vmcommon.BuiltinFunction
	classifier                 drwaTokenClassifier
	enableEpochsHandler        vmcommon.EnableEpochsHandler
	shardCoordinator           sharding.Coordinator
	networkDomain              [32]byte
	cebEpoch                   uint32
	settlementLifetimeRounds   uint64
	currentWorkBudgetsProvider drwaCurrentWorkBudgetsProvider
	createOpenEffect           drwaOpenEffectCreator
}

type drwaSourceDebit struct {
	delegate                   vmcommon.BuiltinFunction
	classifier                 drwaTokenClassifier
	enableEpochsHandler        vmcommon.EnableEpochsHandler
	shardCoordinator           sharding.Coordinator
	networkDomain              [32]byte
	cebEpoch                   uint32
	settlementLifetimeRounds   uint64
	currentWorkBudgetsProvider drwaCurrentWorkBudgetsProvider
	createOpenEffect           drwaOpenEffectCreator

	mutBlockchainHook sync.RWMutex
	blockchainHook    vmcommon.BlockchainDataHook
}

func newDRWASourceDebit(args drwaSourceDebitArgs) (*drwaSourceDebit, error) {
	if check.IfNil(args.delegate) ||
		args.classifier == nil ||
		check.IfNil(args.enableEpochsHandler) ||
		check.IfNil(args.shardCoordinator) ||
		args.currentWorkBudgetsProvider == nil {
		return nil, ErrInvalidDRWASourceDebitDelegate
	}
	createOpenEffect := args.createOpenEffect
	if createOpenEffect == nil {
		createOpenEffect = drwa.CreateOpenEffect
	}

	return &drwaSourceDebit{
		delegate:                   args.delegate,
		classifier:                 args.classifier,
		enableEpochsHandler:        args.enableEpochsHandler,
		shardCoordinator:           args.shardCoordinator,
		networkDomain:              args.networkDomain,
		cebEpoch:                   args.cebEpoch,
		settlementLifetimeRounds:   args.settlementLifetimeRounds,
		currentWorkBudgetsProvider: args.currentWorkBudgetsProvider,
		createOpenEffect:           createOpenEffect,
	}, nil
}

func (sourceDebit *drwaSourceDebit) setBlockchainHook(handler vmcommon.BlockchainDataHook) error {
	if check.IfNil(handler) {
		return ErrInvalidDRWASourceDebitDelegate
	}

	sourceDebit.mutBlockchainHook.Lock()
	sourceDebit.blockchainHook = handler
	sourceDebit.mutBlockchainHook.Unlock()

	return nil
}

// ProcessBuiltinFunction performs one bounded S1 source debit and emits one authenticated carrier.
func (sourceDebit *drwaSourceDebit) ProcessBuiltinFunction(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	destination, tokenID, quantity, originHash, err := sourceDebit.validateAdmission(acntSnd, acntDst, vmInput)
	if err != nil {
		return nil, err
	}

	regulated, err := sourceDebit.classifier(tokenID)
	if err != nil {
		return nil, fmt.Errorf("%w: classify token: %w", ErrDRWASourceDebitDenied, err)
	}
	if !regulated {
		return nil, fmt.Errorf("%w: token is not prototype regulated", ErrDRWASourceDebitDenied)
	}
	if sourceDebit.networkDomain == ([32]byte{}) {
		return nil, fmt.Errorf("%w: zero network domain", ErrDRWASourceDebitDenied)
	}
	if sourceDebit.cebEpoch == 0 || sourceDebit.settlementLifetimeRounds == 0 {
		return nil, fmt.Errorf("%w: unavailable CEB epoch or settlement lifetime", ErrDRWASourceDebitDenied)
	}

	gasIdentity, budgets, reservedTotal, err := sourceDebit.currentWorkBudgetsProvider()
	if err != nil {
		return nil, fmt.Errorf("%w: work budget: %w", ErrDRWASourceDebitDenied, err)
	}
	if vmInput.GasProvided <= reservedTotal {
		return nil, fmt.Errorf("%w: gas does not exceed reserved work", ErrDRWASourceDebitDenied)
	}
	delegateGas, err := core.SafeSubUint64(vmInput.GasProvided, reservedTotal)
	if err != nil {
		return nil, fmt.Errorf("%w: subtract reserved work: %w", ErrDRWASourceDebitDenied, err)
	}

	currentRound, err := sourceDebit.currentRound()
	if err != nil {
		return nil, err
	}
	settlementExpiry, err := core.SafeAddUint64(currentRound, sourceDebit.settlementLifetimeRounds)
	if err != nil || settlementExpiry == 0 {
		return nil, fmt.Errorf("%w: settlement expiry overflow", ErrDRWASourceDebitDenied)
	}

	var sourceHolder [drwaAddressLength]byte
	copy(sourceHolder[:], acntSnd.AddressBytes())
	var destinationHolder [drwaAddressLength]byte
	copy(destinationHolder[:], destination)
	artifacts, err := drwa.BuildDirectValueArtifacts(
		sourceDebit.networkDomain,
		originHash,
		drwa.DirectValueIntent{
			RegulatedTokenID:         tokenID,
			Quantity:                 quantity,
			SourceHolder:             sourceHolder,
			DestinationHolder:        destinationHolder,
			CEBEpoch:                 sourceDebit.cebEpoch,
			SettlementExpiry:         settlementExpiry,
			GasScheduleIdentity:      gasIdentity,
			DestinationGateGasLimit:  budgets.DestinationGate,
			SuccessReceiptGasLimit:   budgets.SuccessReceipt,
			RefundGenerationGasLimit: budgets.RefundGeneration,
			SourceCompletionGasLimit: budgets.SourceCompletion,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%w: construct value artifacts: %w", ErrDRWASourceDebitDenied, err)
	}
	envelopeBytes, err := drwa.EncodeValueEnvelope(artifacts.Envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: encode envelope: %w", ErrDRWASourceDebitDenied, err)
	}
	_, err = drwa.EncodeOpenEffect(artifacts.OpenEffect)
	if err != nil {
		return nil, fmt.Errorf("%w: encode OpenEffect: %w", ErrDRWASourceDebitDenied, err)
	}

	delegateInput := sourceDebit.buildDelegateInput(vmInput, destination, tokenID, quantity, delegateGas)
	carrier := buildDRWASourceCarrier(acntSnd.AddressBytes(), envelopeBytes, reservedTotal)
	dataHandler := acntSnd.AccountDataHandler()
	if check.IfNil(dataHandler) {
		return nil, fmt.Errorf("%w: nil source data handler", ErrDRWASourceDebitDenied)
	}

	err = sourceDebit.createOpenEffect(dataHandler, artifacts.OpenEffect)
	if err != nil {
		return nil, fmt.Errorf("%w: create OpenEffect: %w", ErrDRWASourceDebitMutation, err)
	}
	vmOutput, err := sourceDebit.delegate.ProcessBuiltinFunction(acntSnd, nil, delegateInput)
	if err != nil {
		return nil, fmt.Errorf("%w: baseline debit: %w", ErrDRWASourceDebitMutation, err)
	}
	err = validateDRWASourceDebitOutput(vmOutput, delegateGas)
	if err != nil {
		return nil, fmt.Errorf("%w: baseline output: %w", ErrDRWASourceDebitMutation, err)
	}
	localGasUsed, err := core.SafeSubUint64(delegateGas, vmOutput.GasRemaining)
	if err != nil || localGasUsed == 0 {
		return nil, fmt.Errorf("%w: baseline gas partition", ErrDRWASourceDebitMutation)
	}

	vmOutput.OutputAccounts = map[string]*vmcommon.OutputAccount{
		string(destination): {
			Address:         append([]byte(nil), destination...),
			OutputTransfers: []vmcommon.OutputTransfer{carrier},
		},
	}
	vmOutput.ProtocolExecution = &vmcommon.ProtocolExecutionInfo{
		MessageKind:  vmData.ProtocolMessageKindDRWA,
		Outcome:      vmcommon.ProtocolExecutionOutcomeForward,
		LocalGasUsed: localGasUsed,
		ForwardedGas: reservedTotal,
	}

	return vmOutput, nil
}

func (sourceDebit *drwaSourceDebit) validateAdmission(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) ([]byte, []byte, []byte, [drwaHashLength]byte, error) {
	if !sourceDebit.enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag) {
		return nil, nil, nil, [drwaHashLength]byte{}, fmt.Errorf("%w: activation", ErrDRWASourceDebitDenied)
	}
	if vmInput == nil || check.IfNil(acntSnd) || check.IfNil(acntDst) {
		return nil, nil, nil, [drwaHashLength]byte{}, fmt.Errorf("%w: missing input or source account", ErrDRWASourceDebitDenied)
	}
	sourceAddress := acntSnd.AddressBytes()
	if len(sourceAddress) != drwaAddressLength ||
		!bytes.Equal(acntDst.AddressBytes(), sourceAddress) ||
		!bytes.Equal(vmInput.CallerAddr, sourceAddress) ||
		!bytes.Equal(vmInput.RecipientAddr, sourceAddress) {
		return nil, nil, nil, [drwaHashLength]byte{}, fmt.Errorf("%w: source route", ErrDRWASourceDebitDenied)
	}
	if sourceDebit.shardCoordinator.ComputeId(sourceAddress) != sourceDebit.shardCoordinator.SelfId() ||
		core.IsSmartContractAddress(sourceAddress) {
		return nil, nil, nil, [drwaHashLength]byte{}, fmt.Errorf("%w: source account class", ErrDRWASourceDebitDenied)
	}
	if vmInput.NativeCallOrigin != vmcommon.NativeCallOriginOriginalUserTransaction ||
		vmInput.CallType != vmData.DirectCall ||
		vmInput.Function != DRWASourceDebitFunction ||
		vmInput.CallValue == nil || vmInput.CallValue.Sign() != 0 ||
		vmInput.GasLocked != 0 || vmInput.ReturnCallAfterError ||
		hasDRWAAsyncArguments(vmInput.AsyncArguments) || len(vmInput.ESDTTransfers) != 0 {
		return nil, nil, nil, [drwaHashLength]byte{}, fmt.Errorf("%w: execution origin", ErrDRWASourceDebitDenied)
	}
	if len(vmInput.CurrentTxHash) != drwaHashLength ||
		len(vmInput.OriginalTxHash) != drwaHashLength ||
		len(vmInput.PrevTxHash) != drwaHashLength ||
		!bytes.Equal(vmInput.CurrentTxHash, vmInput.OriginalTxHash) ||
		!bytes.Equal(vmInput.CurrentTxHash, vmInput.PrevTxHash) ||
		bytes.Equal(vmInput.CurrentTxHash, make([]byte, drwaHashLength)) {
		return nil, nil, nil, [drwaHashLength]byte{}, fmt.Errorf("%w: transaction identity", ErrDRWASourceDebitDenied)
	}
	if len(vmInput.Arguments) != 3 {
		return nil, nil, nil, [drwaHashLength]byte{}, fmt.Errorf("%w: argument count", ErrDRWASourceDebitDenied)
	}
	destination := vmInput.Arguments[0]
	tokenID := vmInput.Arguments[1]
	quantity := vmInput.Arguments[2]
	if len(destination) != drwaAddressLength || core.IsSmartContractAddress(destination) ||
		sourceDebit.shardCoordinator.ComputeId(destination) == sourceDebit.shardCoordinator.SelfId() {
		return nil, nil, nil, [drwaHashLength]byte{}, fmt.Errorf("%w: destination route", ErrDRWASourceDebitDenied)
	}
	if !vmcommon.ValidateToken(tokenID) || len(tokenID) > 64 ||
		len(quantity) == 0 || len(quantity) > 32 || quantity[0] == 0 || new(big.Int).SetBytes(quantity).Sign() <= 0 {
		return nil, nil, nil, [drwaHashLength]byte{}, fmt.Errorf("%w: transfer arguments", ErrDRWASourceDebitDenied)
	}

	var originHash [drwaHashLength]byte
	copy(originHash[:], vmInput.CurrentTxHash)
	return append([]byte(nil), destination...), append([]byte(nil), tokenID...), append([]byte(nil), quantity...), originHash, nil
}

func hasDRWAAsyncArguments(arguments *vmcommon.AsyncArguments) bool {
	return arguments != nil &&
		(len(arguments.CallID) != 0 ||
			len(arguments.CallerCallID) != 0 ||
			len(arguments.CallbackAsyncInitiatorCallID) != 0 ||
			arguments.GasAccumulated != 0)
}

func (sourceDebit *drwaSourceDebit) currentRound() (uint64, error) {
	sourceDebit.mutBlockchainHook.RLock()
	hook := sourceDebit.blockchainHook
	sourceDebit.mutBlockchainHook.RUnlock()
	if check.IfNil(hook) {
		return 0, fmt.Errorf("%w: unavailable current round", ErrDRWASourceDebitDenied)
	}

	return hook.CurrentRound(), nil
}

func (sourceDebit *drwaSourceDebit) buildDelegateInput(
	vmInput *vmcommon.ContractCallInput,
	destination, tokenID, quantity []byte,
	delegateGas uint64,
) *vmcommon.ContractCallInput {
	delegateInput := *vmInput
	delegateInput.Function = core.BuiltInFunctionESDTTransfer
	delegateInput.RecipientAddr = append([]byte(nil), destination...)
	delegateInput.Arguments = [][]byte{
		append([]byte(nil), tokenID...),
		append([]byte(nil), quantity...),
	}
	delegateInput.GasProvided = delegateGas
	delegateInput.GasLocked = 0

	return &delegateInput
}

func buildDRWASourceCarrier(
	source, envelope []byte,
	reservedTotal uint64,
) vmcommon.OutputTransfer {
	data := make([]byte, 0, len(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope)+1+hex.EncodedLen(len(envelope)))
	data = append(data, vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope...)
	data = append(data, '@')
	hexEnvelope := make([]byte, hex.EncodedLen(len(envelope)))
	hex.Encode(hexEnvelope, envelope)
	data = append(data, hexEnvelope...)

	return vmcommon.OutputTransfer{
		Index:               1,
		Value:               big.NewInt(0),
		GasLimit:            reservedTotal,
		GasLocked:           0,
		Data:                data,
		CallType:            vmData.DirectCall,
		ProtocolMessageKind: vmData.ProtocolMessageKindDRWA,
		SenderAddress:       append([]byte(nil), source...),
	}
}

func validateDRWASourceDebitOutput(vmOutput *vmcommon.VMOutput, delegateGas uint64) error {
	if vmOutput == nil || vmOutput.ReturnCode != vmcommon.Ok {
		return ErrInvalidDRWASourceDebitDelegate
	}
	if vmOutput.GasRemaining > delegateGas || len(vmOutput.OutputAccounts) != 0 ||
		len(vmOutput.DeletedAccounts) != 0 || len(vmOutput.TouchedAccounts) != 0 {
		return ErrInvalidDRWASourceDebitDelegate
	}

	return nil
}

// SetNewGasConfig preserves the baseline delegate's built-in contract.
func (sourceDebit *drwaSourceDebit) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	sourceDebit.delegate.SetNewGasConfig(gasCost)
}

// IsActive keeps transaction classification disabled before the DRWA enforcement flag.
func (sourceDebit *drwaSourceDebit) IsActive() bool {
	return sourceDebit != nil && sourceDebit.enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag)
}

// IsInterfaceNil returns true for a nil source-debit wrapper.
func (sourceDebit *drwaSourceDebit) IsInterfaceNil() bool {
	return sourceDebit == nil
}
