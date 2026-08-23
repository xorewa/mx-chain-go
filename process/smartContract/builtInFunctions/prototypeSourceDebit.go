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
	"github.com/multiversx/mx-chain-go/sharding"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

const (
	// PrototypeSourceDebitFunction is the bounded S1 source-only entry point.
	PrototypeSourceDebitFunction = "DRWAPrototypeTransfer"
	prototypeAddressLength       = 32
	prototypeHashLength          = 32
)

var (
	// ErrPrototypeSourceDebitDenied signals fail-closed rejection before source mutation.
	ErrPrototypeSourceDebitDenied = errors.New("non-normative DRWA prototype source debit denied")
	// ErrPrototypeSourceDebitMutation signals an error after protected state may have been journaled.
	ErrPrototypeSourceDebitMutation = errors.New("non-normative DRWA prototype source debit mutation failed")
	// ErrInvalidPrototypeSourceDebitDelegate signals unusable source-debit construction dependencies.
	ErrInvalidPrototypeSourceDebitDelegate = errors.New("invalid non-normative DRWA prototype source debit delegate")
)

type prototypeCurrentWorkBudgetsProvider func() ([32]byte, drwaprototype.WorkBudgets, uint64, error)

type prototypeSourceDebitArgs struct {
	delegate                   vmcommon.BuiltinFunction
	classifier                 prototypeTokenClassifier
	enableEpochsHandler        vmcommon.EnableEpochsHandler
	shardCoordinator           sharding.Coordinator
	networkDomain              [32]byte
	cebEpoch                   uint32
	settlementLifetimeRounds   uint64
	currentWorkBudgetsProvider prototypeCurrentWorkBudgetsProvider
}

type prototypeSourceDebit struct {
	delegate                   vmcommon.BuiltinFunction
	classifier                 prototypeTokenClassifier
	enableEpochsHandler        vmcommon.EnableEpochsHandler
	shardCoordinator           sharding.Coordinator
	networkDomain              [32]byte
	cebEpoch                   uint32
	settlementLifetimeRounds   uint64
	currentWorkBudgetsProvider prototypeCurrentWorkBudgetsProvider

	mutBlockchainHook sync.RWMutex
	blockchainHook    vmcommon.BlockchainDataHook
}

func newPrototypeSourceDebit(args prototypeSourceDebitArgs) (*prototypeSourceDebit, error) {
	if check.IfNil(args.delegate) ||
		args.classifier == nil ||
		check.IfNil(args.enableEpochsHandler) ||
		check.IfNil(args.shardCoordinator) ||
		args.currentWorkBudgetsProvider == nil {
		return nil, ErrInvalidPrototypeSourceDebitDelegate
	}

	return &prototypeSourceDebit{
		delegate:                   args.delegate,
		classifier:                 args.classifier,
		enableEpochsHandler:        args.enableEpochsHandler,
		shardCoordinator:           args.shardCoordinator,
		networkDomain:              args.networkDomain,
		cebEpoch:                   args.cebEpoch,
		settlementLifetimeRounds:   args.settlementLifetimeRounds,
		currentWorkBudgetsProvider: args.currentWorkBudgetsProvider,
	}, nil
}

func (sourceDebit *prototypeSourceDebit) setBlockchainHook(handler vmcommon.BlockchainDataHook) error {
	if check.IfNil(handler) {
		return ErrInvalidPrototypeSourceDebitDelegate
	}

	sourceDebit.mutBlockchainHook.Lock()
	sourceDebit.blockchainHook = handler
	sourceDebit.mutBlockchainHook.Unlock()

	return nil
}

// ProcessBuiltinFunction performs one bounded S1 source debit and emits one authenticated carrier.
func (sourceDebit *prototypeSourceDebit) ProcessBuiltinFunction(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	destination, tokenID, quantity, originHash, err := sourceDebit.validateAdmission(acntSnd, acntDst, vmInput)
	if err != nil {
		return nil, err
	}

	regulated, err := sourceDebit.classifier(tokenID)
	if err != nil {
		return nil, fmt.Errorf("%w: classify token: %w", ErrPrototypeSourceDebitDenied, err)
	}
	if !regulated {
		return nil, fmt.Errorf("%w: token is not prototype regulated", ErrPrototypeSourceDebitDenied)
	}
	if sourceDebit.networkDomain == ([32]byte{}) {
		return nil, fmt.Errorf("%w: zero network domain", ErrPrototypeSourceDebitDenied)
	}
	if sourceDebit.cebEpoch == 0 || sourceDebit.settlementLifetimeRounds == 0 {
		return nil, fmt.Errorf("%w: unavailable CEB epoch or settlement lifetime", ErrPrototypeSourceDebitDenied)
	}

	gasIdentity, budgets, reservedTotal, err := sourceDebit.currentWorkBudgetsProvider()
	if err != nil {
		return nil, fmt.Errorf("%w: work budget: %w", ErrPrototypeSourceDebitDenied, err)
	}
	if vmInput.GasProvided <= reservedTotal {
		return nil, fmt.Errorf("%w: gas does not exceed reserved work", ErrPrototypeSourceDebitDenied)
	}
	delegateGas, err := core.SafeSubUint64(vmInput.GasProvided, reservedTotal)
	if err != nil {
		return nil, fmt.Errorf("%w: subtract reserved work: %w", ErrPrototypeSourceDebitDenied, err)
	}

	currentRound, err := sourceDebit.currentRound()
	if err != nil {
		return nil, err
	}
	settlementExpiry, err := core.SafeAddUint64(currentRound, sourceDebit.settlementLifetimeRounds)
	if err != nil || settlementExpiry == 0 {
		return nil, fmt.Errorf("%w: settlement expiry overflow", ErrPrototypeSourceDebitDenied)
	}

	var sourceHolder [prototypeAddressLength]byte
	copy(sourceHolder[:], acntSnd.AddressBytes())
	var destinationHolder [prototypeAddressLength]byte
	copy(destinationHolder[:], destination)
	artifacts, err := drwaprototype.BuildDirectValueArtifacts(
		sourceDebit.networkDomain,
		originHash,
		drwaprototype.DirectValueIntent{
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
		return nil, fmt.Errorf("%w: construct value artifacts: %w", ErrPrototypeSourceDebitDenied, err)
	}
	envelopeBytes, err := drwaprototype.EncodeValueEnvelope(artifacts.Envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: encode envelope: %w", ErrPrototypeSourceDebitDenied, err)
	}
	_, err = drwaprototype.EncodeOpenEffect(artifacts.OpenEffect)
	if err != nil {
		return nil, fmt.Errorf("%w: encode OpenEffect: %w", ErrPrototypeSourceDebitDenied, err)
	}

	delegateInput := sourceDebit.buildDelegateInput(vmInput, destination, tokenID, quantity, delegateGas)
	carrier := buildPrototypeSourceCarrier(acntSnd.AddressBytes(), envelopeBytes, reservedTotal)
	dataHandler := acntSnd.AccountDataHandler()
	if check.IfNil(dataHandler) {
		return nil, fmt.Errorf("%w: nil source data handler", ErrPrototypeSourceDebitDenied)
	}

	err = drwaprototype.CreateOpenEffect(dataHandler, artifacts.OpenEffect)
	if err != nil {
		return nil, fmt.Errorf("%w: create OpenEffect: %w", ErrPrototypeSourceDebitMutation, err)
	}
	vmOutput, err := sourceDebit.delegate.ProcessBuiltinFunction(acntSnd, nil, delegateInput)
	if err != nil {
		return nil, fmt.Errorf("%w: baseline debit: %w", ErrPrototypeSourceDebitMutation, err)
	}
	err = validatePrototypeSourceDebitOutput(vmOutput, delegateGas)
	if err != nil {
		return nil, fmt.Errorf("%w: baseline output: %w", ErrPrototypeSourceDebitMutation, err)
	}

	vmOutput.OutputAccounts = map[string]*vmcommon.OutputAccount{
		string(destination): {
			Address:         append([]byte(nil), destination...),
			OutputTransfers: []vmcommon.OutputTransfer{carrier},
		},
	}

	return vmOutput, nil
}

func (sourceDebit *prototypeSourceDebit) validateAdmission(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) ([]byte, []byte, []byte, [prototypeHashLength]byte, error) {
	if !sourceDebit.enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag) {
		return nil, nil, nil, [prototypeHashLength]byte{}, fmt.Errorf("%w: activation", ErrPrototypeSourceDebitDenied)
	}
	if vmInput == nil || check.IfNil(acntSnd) || check.IfNil(acntDst) {
		return nil, nil, nil, [prototypeHashLength]byte{}, fmt.Errorf("%w: missing input or source account", ErrPrototypeSourceDebitDenied)
	}
	sourceAddress := acntSnd.AddressBytes()
	if len(sourceAddress) != prototypeAddressLength ||
		!bytes.Equal(acntDst.AddressBytes(), sourceAddress) ||
		!bytes.Equal(vmInput.CallerAddr, sourceAddress) ||
		!bytes.Equal(vmInput.RecipientAddr, sourceAddress) {
		return nil, nil, nil, [prototypeHashLength]byte{}, fmt.Errorf("%w: source route", ErrPrototypeSourceDebitDenied)
	}
	if sourceDebit.shardCoordinator.ComputeId(sourceAddress) != sourceDebit.shardCoordinator.SelfId() ||
		core.IsSmartContractAddress(sourceAddress) {
		return nil, nil, nil, [prototypeHashLength]byte{}, fmt.Errorf("%w: source account class", ErrPrototypeSourceDebitDenied)
	}
	if vmInput.NativeCallOrigin != vmcommon.NativeCallOriginOriginalUserTransaction ||
		vmInput.CallType != vmData.DirectCall ||
		vmInput.Function != PrototypeSourceDebitFunction ||
		vmInput.CallValue == nil || vmInput.CallValue.Sign() != 0 ||
		vmInput.GasLocked != 0 || vmInput.ReturnCallAfterError ||
		hasPrototypeAsyncArguments(vmInput.AsyncArguments) || len(vmInput.ESDTTransfers) != 0 {
		return nil, nil, nil, [prototypeHashLength]byte{}, fmt.Errorf("%w: execution origin", ErrPrototypeSourceDebitDenied)
	}
	if len(vmInput.CurrentTxHash) != prototypeHashLength ||
		len(vmInput.OriginalTxHash) != prototypeHashLength ||
		len(vmInput.PrevTxHash) != prototypeHashLength ||
		!bytes.Equal(vmInput.CurrentTxHash, vmInput.OriginalTxHash) ||
		!bytes.Equal(vmInput.CurrentTxHash, vmInput.PrevTxHash) ||
		bytes.Equal(vmInput.CurrentTxHash, make([]byte, prototypeHashLength)) {
		return nil, nil, nil, [prototypeHashLength]byte{}, fmt.Errorf("%w: transaction identity", ErrPrototypeSourceDebitDenied)
	}
	if len(vmInput.Arguments) != 3 {
		return nil, nil, nil, [prototypeHashLength]byte{}, fmt.Errorf("%w: argument count", ErrPrototypeSourceDebitDenied)
	}
	destination := vmInput.Arguments[0]
	tokenID := vmInput.Arguments[1]
	quantity := vmInput.Arguments[2]
	if len(destination) != prototypeAddressLength || core.IsSmartContractAddress(destination) ||
		sourceDebit.shardCoordinator.ComputeId(destination) == sourceDebit.shardCoordinator.SelfId() {
		return nil, nil, nil, [prototypeHashLength]byte{}, fmt.Errorf("%w: destination route", ErrPrototypeSourceDebitDenied)
	}
	if !vmcommon.ValidateToken(tokenID) || len(tokenID) > 64 ||
		len(quantity) == 0 || len(quantity) > 32 || quantity[0] == 0 || new(big.Int).SetBytes(quantity).Sign() <= 0 {
		return nil, nil, nil, [prototypeHashLength]byte{}, fmt.Errorf("%w: transfer arguments", ErrPrototypeSourceDebitDenied)
	}

	var originHash [prototypeHashLength]byte
	copy(originHash[:], vmInput.CurrentTxHash)
	return append([]byte(nil), destination...), append([]byte(nil), tokenID...), append([]byte(nil), quantity...), originHash, nil
}

func hasPrototypeAsyncArguments(arguments *vmcommon.AsyncArguments) bool {
	return arguments != nil &&
		(len(arguments.CallID) != 0 ||
			len(arguments.CallerCallID) != 0 ||
			len(arguments.CallbackAsyncInitiatorCallID) != 0 ||
			arguments.GasAccumulated != 0)
}

func (sourceDebit *prototypeSourceDebit) currentRound() (uint64, error) {
	sourceDebit.mutBlockchainHook.RLock()
	hook := sourceDebit.blockchainHook
	sourceDebit.mutBlockchainHook.RUnlock()
	if check.IfNil(hook) {
		return 0, fmt.Errorf("%w: unavailable current round", ErrPrototypeSourceDebitDenied)
	}

	return hook.CurrentRound(), nil
}

func (sourceDebit *prototypeSourceDebit) buildDelegateInput(
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

func buildPrototypeSourceCarrier(
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

func validatePrototypeSourceDebitOutput(vmOutput *vmcommon.VMOutput, delegateGas uint64) error {
	if vmOutput == nil || vmOutput.ReturnCode != vmcommon.Ok {
		return ErrInvalidPrototypeSourceDebitDelegate
	}
	if vmOutput.GasRemaining > delegateGas || len(vmOutput.OutputAccounts) != 0 ||
		len(vmOutput.DeletedAccounts) != 0 || len(vmOutput.TouchedAccounts) != 0 {
		return ErrInvalidPrototypeSourceDebitDelegate
	}

	return nil
}

// SetNewGasConfig preserves the baseline delegate's built-in contract.
func (sourceDebit *prototypeSourceDebit) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	sourceDebit.delegate.SetNewGasConfig(gasCost)
}

// IsActive keeps transaction classification disabled before the DRWA enforcement flag.
func (sourceDebit *prototypeSourceDebit) IsActive() bool {
	return sourceDebit != nil && sourceDebit.enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag)
}

// IsInterfaceNil returns true for a nil source-debit wrapper.
func (sourceDebit *prototypeSourceDebit) IsInterfaceNil() bool {
	return sourceDebit == nil
}
