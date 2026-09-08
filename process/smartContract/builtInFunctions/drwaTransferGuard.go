package builtInFunctions

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
	"github.com/multiversx/mx-chain-go/sharding"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B
//
// These guards exist only to keep S1-S5 prototype-marked tokens out of ordinary transfer entry
// points. They are not the permanent classifier or the positive DRWA value path.

const drwaArgumentsPerMultiTransfer = 3

var (
	// ErrDRWARegulatedTransferRequiresDRWA denies an ordinary transfer for a DRWA-marked token.
	ErrDRWARegulatedTransferRequiresDRWA = errors.New("non-normative DRWA prototype regulated token requires the DRWA transfer path")
	// ErrInvalidDRWATransferGuardDelegate signals a baseline transfer that cannot preserve required factory behavior.
	ErrInvalidDRWATransferGuardDelegate = errors.New("invalid non-normative DRWA prototype transfer guard delegate")
	// ErrDRWASameShardTransferDenied signals fail-closed rejection of a marked local fungible route.
	ErrDRWASameShardTransferDenied = errors.New("non-normative DRWA prototype same-shard transfer denied")
)

type drwaTokenClassifier func(tokenID []byte) (bool, error)
type drwaCurrentRoundProvider func() (uint64, error)

type drwaTransferGuard struct {
	functionName         string
	delegate             vmcommon.BuiltinFunction
	classifier           drwaTokenClassifier
	enableEpochsHandler  vmcommon.EnableEpochsHandler
	shardCoordinator     sharding.Coordinator
	cebEpoch             uint32
	currentRoundProvider drwaCurrentRoundProvider
}

func newDRWATransferGuard(
	functionName string,
	delegate vmcommon.BuiltinFunction,
	classifier drwaTokenClassifier,
	enableEpochsHandler vmcommon.EnableEpochsHandler,
	shardCoordinator sharding.Coordinator,
	cebEpoch uint32,
	currentRoundProvider drwaCurrentRoundProvider,
) (*drwaTransferGuard, error) {
	if check.IfNil(delegate) || classifier == nil || check.IfNil(enableEpochsHandler) ||
		check.IfNil(shardCoordinator) || currentRoundProvider == nil {
		return nil, ErrInvalidDRWATransferGuardDelegate
	}
	_, ok := delegate.(vmcommon.AcceptPayableChecker)
	if !ok {
		return nil, ErrInvalidDRWATransferGuardDelegate
	}

	return &drwaTransferGuard{
		functionName:         functionName,
		delegate:             delegate,
		classifier:           classifier,
		enableEpochsHandler:  enableEpochsHandler,
		shardCoordinator:     shardCoordinator,
		cebEpoch:             cebEpoch,
		currentRoundProvider: currentRoundProvider,
	}, nil
}

// ProcessBuiltinFunction blocks DRWA-regulated tokens from ordinary transfer entry points.
func (guard *drwaTransferGuard) ProcessBuiltinFunction(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	if !guard.enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag) {
		return guard.delegate.ProcessBuiltinFunction(acntSnd, acntDst, vmInput)
	}

	tokenIDs, identifiable := drwaTransferTokenIDs(guard.functionName, vmInput)
	if !identifiable {
		return guard.delegate.ProcessBuiltinFunction(acntSnd, acntDst, vmInput)
	}
	for _, tokenID := range tokenIDs {
		if !vmcommon.ValidateToken(tokenID) {
			continue
		}
		regulated, err := guard.classifier(tokenID)
		if err != nil {
			return nil, fmt.Errorf("classify ordinary transfer token for non-normative DRWA prototype: %w", err)
		}
		if regulated {
			if guard.isSameShardFungibleCandidate(acntSnd, acntDst, vmInput) {
				return guard.processSameShardFungible(acntSnd, acntDst, vmInput, tokenID)
			}
			return nil, ErrDRWARegulatedTransferRequiresDRWA
		}
	}

	return guard.delegate.ProcessBuiltinFunction(acntSnd, acntDst, vmInput)
}

func (guard *drwaTransferGuard) isSameShardFungibleCandidate(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) bool {
	if guard.functionName != core.BuiltInFunctionESDTTransfer || vmInput == nil ||
		check.IfNil(acntSnd) || check.IfNil(acntDst) {
		return false
	}
	source := acntSnd.AddressBytes()
	destination := acntDst.AddressBytes()
	return guard.shardCoordinator.ComputeId(source) == guard.shardCoordinator.SelfId() &&
		guard.shardCoordinator.ComputeId(destination) == guard.shardCoordinator.SelfId()
}

func (guard *drwaTransferGuard) processSameShardFungible(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
	tokenID []byte,
) (*vmcommon.VMOutput, error) {
	err := guard.validateSameShardAdmission(acntSnd, acntDst, vmInput, tokenID)
	if err != nil {
		return nil, err
	}
	currentRound, err := guard.currentRoundProvider()
	if err != nil {
		return nil, fmt.Errorf("%w: current round: %w", ErrDRWASameShardTransferDenied, err)
	}
	err = validateDRWAReceiver(acntDst, tokenID, acntDst.AddressBytes(), guard.cebEpoch, currentRound)
	if err != nil {
		return nil, fmt.Errorf("%w: receiver: %w", ErrDRWASameShardTransferDenied, err)
	}

	return guard.delegate.ProcessBuiltinFunction(acntSnd, acntDst, vmInput)
}

func (guard *drwaTransferGuard) validateSameShardAdmission(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
	tokenID []byte,
) error {
	if guard.cebEpoch == 0 || len(vmInput.Arguments) != 2 ||
		vmInput.Function != core.BuiltInFunctionESDTTransfer ||
		vmInput.NativeCallOrigin != vmcommon.NativeCallOriginOriginalUserTransaction ||
		vmInput.CallType != vmData.DirectCall || vmInput.CallValue == nil || vmInput.CallValue.Sign() != 0 ||
		vmInput.GasLocked != 0 || vmInput.ReturnCallAfterError || hasDRWAAsyncArguments(vmInput.AsyncArguments) ||
		len(vmInput.ESDTTransfers) != 0 {
		return fmt.Errorf("%w: execution origin", ErrDRWASameShardTransferDenied)
	}
	source := acntSnd.AddressBytes()
	destination := acntDst.AddressBytes()
	if len(source) != drwaAddressLength || len(destination) != drwaAddressLength ||
		bytes.Equal(source, destination) || core.IsSmartContractAddress(source) || core.IsSmartContractAddress(destination) ||
		!bytes.Equal(vmInput.CallerAddr, source) || !bytes.Equal(vmInput.RecipientAddr, destination) ||
		guard.shardCoordinator.ComputeId(source) != guard.shardCoordinator.SelfId() ||
		guard.shardCoordinator.ComputeId(destination) != guard.shardCoordinator.SelfId() {
		return fmt.Errorf("%w: holder route", ErrDRWASameShardTransferDenied)
	}
	if len(vmInput.CurrentTxHash) != drwaHashLength || len(vmInput.OriginalTxHash) != drwaHashLength ||
		len(vmInput.PrevTxHash) != drwaHashLength ||
		!bytes.Equal(vmInput.CurrentTxHash, vmInput.OriginalTxHash) ||
		!bytes.Equal(vmInput.CurrentTxHash, vmInput.PrevTxHash) ||
		bytes.Equal(vmInput.CurrentTxHash, make([]byte, drwaHashLength)) {
		return fmt.Errorf("%w: transaction identity", ErrDRWASameShardTransferDenied)
	}
	quantity := vmInput.Arguments[1]
	if !bytes.Equal(vmInput.Arguments[0], tokenID) || !vmcommon.ValidateToken(tokenID) || len(tokenID) > 64 ||
		len(quantity) == 0 || len(quantity) > 32 || quantity[0] == 0 || new(big.Int).SetBytes(quantity).Sign() <= 0 {
		return fmt.Errorf("%w: transfer arguments", ErrDRWASameShardTransferDenied)
	}

	return nil
}

// SetNewGasConfig forwards gas schedule changes to the original transfer built-in.
func (guard *drwaTransferGuard) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	guard.delegate.SetNewGasConfig(gasCost)
}

// IsActive preserves the original transfer built-in activation behavior.
func (guard *drwaTransferGuard) IsActive() bool {
	return guard.delegate.IsActive()
}

// SetPayableChecker preserves the creator's post-construction payable-checker injection.
func (guard *drwaTransferGuard) SetPayableChecker(payableChecker vmcommon.PayableChecker) error {
	delegate, ok := guard.delegate.(vmcommon.AcceptPayableChecker)
	if !ok {
		return ErrInvalidDRWATransferGuardDelegate
	}

	return delegate.SetPayableChecker(payableChecker)
}

// IsInterfaceNil returns true for a nil guard.
func (guard *drwaTransferGuard) IsInterfaceNil() bool {
	return guard == nil
}

func drwaTransferTokenIDs(functionName string, vmInput *vmcommon.ContractCallInput) ([][]byte, bool) {
	if vmInput == nil {
		return nil, false
	}

	switch functionName {
	case core.BuiltInFunctionESDTTransfer, core.BuiltInFunctionESDTNFTTransfer:
		if len(vmInput.Arguments) == 0 {
			return nil, false
		}
		return [][]byte{vmInput.Arguments[0]}, true
	case core.BuiltInFunctionMultiESDTNFTTransfer:
		return drwaMultiTransferTokenIDs(vmInput)
	default:
		return nil, false
	}
}

func drwaMultiTransferTokenIDs(vmInput *vmcommon.ContractCallInput) ([][]byte, bool) {
	countIndex := 0
	firstTokenIndex := 1
	if bytes.Equal(vmInput.CallerAddr, vmInput.RecipientAddr) {
		countIndex = 1
		firstTokenIndex = 2
	}
	if len(vmInput.Arguments) <= firstTokenIndex || countIndex >= len(vmInput.Arguments) {
		return nil, false
	}

	countValue := new(big.Int).SetBytes(vmInput.Arguments[countIndex])
	if !countValue.IsUint64() {
		return nil, false
	}
	declaredCount := countValue.Uint64()
	maximumCountFromArguments := uint64((len(vmInput.Arguments) - firstTokenIndex) / drwaArgumentsPerMultiTransfer)
	if declaredCount == 0 || declaredCount > maximumCountFromArguments {
		return nil, false
	}

	tokenIDs := make([][]byte, 0, int(declaredCount))
	for index := uint64(0); index < declaredCount; index++ {
		tokenIndex := firstTokenIndex + int(index)*drwaArgumentsPerMultiTransfer
		tokenIDs = append(tokenIDs, vmInput.Arguments[tokenIndex])
	}

	return tokenIDs, true
}

type drwaGuardedBuiltInFunctionFactory struct {
	delegate                     vmcommon.BuiltInFunctionFactory
	accounts                     vmcommon.AccountsAdapter
	enableEpochsHandler          vmcommon.EnableEpochsHandler
	drwaNetworkDomain            [32]byte
	drwaGasScheduleCatalog       *drwa.GasScheduleCatalog
	gasScheduleNotifier          core.GasScheduleNotifier
	drwaCEBEpoch                 uint32
	drwaSettlementLifetimeRounds uint64
	shardCoordinator             sharding.Coordinator
	drwaSourceDebit              *drwaSourceDebit
	drwaDestination              *drwaDestination
	drwaSourceCompletion         *drwaSourceCompletion
	mutBlockchainHook            sync.RWMutex
	blockchainHook               vmcommon.BlockchainDataHook
}

// DRWANetworkDomain returns the immutable value injected into this DRWA factory.
func (factory *drwaGuardedBuiltInFunctionFactory) DRWANetworkDomain() [32]byte {
	if factory == nil {
		return [32]byte{}
	}
	return factory.drwaNetworkDomain
}

// DRWAGasScheduleCatalogIdentity returns the sealed configured timeline identity.
func (factory *drwaGuardedBuiltInFunctionFactory) DRWAGasScheduleCatalogIdentity() ([32]byte, error) {
	if factory == nil || factory.drwaGasScheduleCatalog == nil {
		return [32]byte{}, ErrDRWAGasScheduleUnavailable
	}
	return factory.drwaGasScheduleCatalog.Identity()
}

// DRWACurrentGasScheduleIdentity verifies that the notifier's current map is retained.
func (factory *drwaGuardedBuiltInFunctionFactory) DRWACurrentGasScheduleIdentity() ([32]byte, error) {
	if factory == nil || factory.drwaGasScheduleCatalog == nil || factory.gasScheduleNotifier == nil {
		return [32]byte{}, ErrDRWAGasScheduleUnavailable
	}
	provider, ok := factory.gasScheduleNotifier.(drwaConfiguredGasScheduleProvider)
	if !ok {
		return [32]byte{}, ErrDRWAGasScheduleUnavailable
	}
	return currentDRWAGasScheduleIdentity(provider, factory.drwaGasScheduleCatalog)
}

// DRWACurrentWorkBudgets returns the retained current identity and conservative S1 work reserve.
func (factory *drwaGuardedBuiltInFunctionFactory) DRWACurrentWorkBudgets() (
	[32]byte,
	drwa.WorkBudgets,
	uint64,
	error,
) {
	if factory == nil || factory.drwaGasScheduleCatalog == nil || factory.gasScheduleNotifier == nil {
		return [32]byte{}, drwa.WorkBudgets{}, 0, ErrDRWAGasScheduleUnavailable
	}
	provider, ok := factory.gasScheduleNotifier.(drwaConfiguredGasScheduleProvider)
	if !ok {
		return [32]byte{}, drwa.WorkBudgets{}, 0, ErrDRWAGasScheduleUnavailable
	}

	return currentDRWAWorkBudgets(provider, factory.drwaGasScheduleCatalog)
}

// DRWARetainedWorkBudgets validates one pinned identity and returns the approved maxima.
func (factory *drwaGuardedBuiltInFunctionFactory) DRWARetainedWorkBudgets(
	identity [32]byte,
) (drwa.WorkBudgets, uint64, error) {
	if factory == nil {
		return drwa.WorkBudgets{}, 0, ErrDRWAGasScheduleUnavailable
	}
	return retainedDRWAWorkBudgets(identity, factory.drwaGasScheduleCatalog)
}

func (factory *drwaGuardedBuiltInFunctionFactory) ESDTGlobalSettingsHandler() vmcommon.ESDTGlobalSettingsHandler {
	return factory.delegate.ESDTGlobalSettingsHandler()
}

func (factory *drwaGuardedBuiltInFunctionFactory) NFTStorageHandler() vmcommon.SimpleESDTNFTStorageHandler {
	return factory.delegate.NFTStorageHandler()
}

func (factory *drwaGuardedBuiltInFunctionFactory) BuiltInFunctionContainer() vmcommon.BuiltInFunctionContainer {
	return factory.delegate.BuiltInFunctionContainer()
}

func (factory *drwaGuardedBuiltInFunctionFactory) SetPayableHandler(handler vmcommon.PayableHandler) error {
	return factory.delegate.SetPayableHandler(handler)
}

func (factory *drwaGuardedBuiltInFunctionFactory) SetBlockchainHook(handler vmcommon.BlockchainDataHook) error {
	err := factory.delegate.SetBlockchainHook(handler)
	if err != nil {
		return err
	}
	if check.IfNil(handler) {
		return ErrInvalidDRWATransferGuardDelegate
	}
	factory.mutBlockchainHook.Lock()
	factory.blockchainHook = handler
	factory.mutBlockchainHook.Unlock()
	if factory.drwaSourceDebit != nil {
		err = factory.drwaSourceDebit.setBlockchainHook(handler)
		if err != nil {
			return err
		}
	}
	if factory.drwaDestination != nil {
		return factory.drwaDestination.setBlockchainHook(handler)
	}
	return nil
}

func (factory *drwaGuardedBuiltInFunctionFactory) drwaCurrentRound() (uint64, error) {
	factory.mutBlockchainHook.RLock()
	hook := factory.blockchainHook
	factory.mutBlockchainHook.RUnlock()
	if check.IfNil(hook) {
		return 0, ErrDRWASameShardTransferDenied
	}

	return hook.CurrentRound(), nil
}

func (factory *drwaGuardedBuiltInFunctionFactory) CreateBuiltInFunctionContainer() error {
	err := factory.delegate.CreateBuiltInFunctionContainer()
	if err != nil {
		return err
	}

	return factory.installDRWATransferGuards()
}

func (factory *drwaGuardedBuiltInFunctionFactory) IsInterfaceNil() bool {
	return factory == nil
}

func (factory *drwaGuardedBuiltInFunctionFactory) installDRWATransferGuards() error {
	container := factory.delegate.BuiltInFunctionContainer()
	sourceDebitDelegate, err := container.Get(core.BuiltInFunctionESDTTransfer)
	if err != nil {
		return err
	}
	classifier := func(tokenID []byte) (bool, error) {
		return drwa.IsDRWARegulatedToken(factory.accounts, tokenID)
	}
	functionNames := []string{
		core.BuiltInFunctionESDTTransfer,
		core.BuiltInFunctionESDTNFTTransfer,
		core.BuiltInFunctionMultiESDTNFTTransfer,
	}

	for _, functionName := range functionNames {
		delegate, err := container.Get(functionName)
		if err != nil {
			return err
		}
		guard, err := newDRWATransferGuard(
			functionName,
			delegate,
			classifier,
			factory.enableEpochsHandler,
			factory.shardCoordinator,
			factory.drwaCEBEpoch,
			factory.drwaCurrentRound,
		)
		if err != nil {
			return err
		}
		err = container.Replace(functionName, guard)
		if err != nil {
			return err
		}
	}

	factory.drwaSourceDebit, err = newDRWASourceDebit(drwaSourceDebitArgs{
		delegate:                   sourceDebitDelegate,
		classifier:                 classifier,
		enableEpochsHandler:        factory.enableEpochsHandler,
		shardCoordinator:           factory.shardCoordinator,
		networkDomain:              factory.drwaNetworkDomain,
		cebEpoch:                   factory.drwaCEBEpoch,
		settlementLifetimeRounds:   factory.drwaSettlementLifetimeRounds,
		currentWorkBudgetsProvider: factory.DRWACurrentWorkBudgets,
	})
	if err != nil {
		return err
	}

	err = container.Add(DRWASourceDebitFunction, factory.drwaSourceDebit)
	if err != nil {
		return err
	}

	factory.drwaDestination, err = newDRWADestination(drwaDestinationArgs{
		delegate:                    sourceDebitDelegate,
		classifier:                  classifier,
		enableEpochsHandler:         factory.enableEpochsHandler,
		shardCoordinator:            factory.shardCoordinator,
		networkDomain:               factory.drwaNetworkDomain,
		cebEpoch:                    factory.drwaCEBEpoch,
		retainedWorkBudgetsProvider: factory.DRWARetainedWorkBudgets,
	})
	if err != nil {
		return err
	}

	err = container.Add(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope, factory.drwaDestination)
	if err != nil {
		return err
	}

	factory.drwaSourceCompletion, err = newDRWASourceCompletion(drwaSourceCompletionArgs{
		delegate:                    sourceDebitDelegate,
		enableEpochsHandler:         factory.enableEpochsHandler,
		shardCoordinator:            factory.shardCoordinator,
		networkDomain:               factory.drwaNetworkDomain,
		retainedWorkBudgetsProvider: factory.DRWARetainedWorkBudgets,
	})
	if err != nil {
		return err
	}
	err = container.Add(DRWASettlementReceiptFunction, factory.drwaSourceCompletion)
	if err != nil {
		return err
	}
	err = container.Add(DRWARefundEnvelopeFunction, factory.drwaSourceCompletion)
	if err != nil {
		return err
	}

	factory.mutBlockchainHook.RLock()
	hook := factory.blockchainHook
	factory.mutBlockchainHook.RUnlock()
	if check.IfNil(hook) {
		return nil
	}
	err = factory.drwaSourceDebit.setBlockchainHook(hook)
	if err != nil {
		return err
	}
	return factory.drwaDestination.setBlockchainHook(hook)
}
