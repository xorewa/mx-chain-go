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
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/sharding"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B
//
// These guards exist only to keep S1-S5 prototype-marked tokens out of ordinary transfer entry
// points. They are not the permanent classifier or the positive DRWA value path.

const prototypeArgumentsPerMultiTransfer = 3

var (
	// ErrPrototypeRegulatedTransferRequiresDRWA denies an ordinary transfer for a prototype-marked token.
	ErrPrototypeRegulatedTransferRequiresDRWA = errors.New("non-normative DRWA prototype regulated token requires the DRWA transfer path")
	// ErrInvalidPrototypeTransferGuardDelegate signals a baseline transfer that cannot preserve required factory behavior.
	ErrInvalidPrototypeTransferGuardDelegate = errors.New("invalid non-normative DRWA prototype transfer guard delegate")
	// ErrPrototypeSameShardTransferDenied signals fail-closed rejection of a marked local fungible route.
	ErrPrototypeSameShardTransferDenied = errors.New("non-normative DRWA prototype same-shard transfer denied")
)

type prototypeTokenClassifier func(tokenID []byte) (bool, error)
type prototypeCurrentRoundProvider func() (uint64, error)

type prototypeTransferGuard struct {
	functionName         string
	delegate             vmcommon.BuiltinFunction
	classifier           prototypeTokenClassifier
	enableEpochsHandler  vmcommon.EnableEpochsHandler
	shardCoordinator     sharding.Coordinator
	cebEpoch             uint32
	currentRoundProvider prototypeCurrentRoundProvider
}

func newPrototypeTransferGuard(
	functionName string,
	delegate vmcommon.BuiltinFunction,
	classifier prototypeTokenClassifier,
	enableEpochsHandler vmcommon.EnableEpochsHandler,
	shardCoordinator sharding.Coordinator,
	cebEpoch uint32,
	currentRoundProvider prototypeCurrentRoundProvider,
) (*prototypeTransferGuard, error) {
	if check.IfNil(delegate) || classifier == nil || check.IfNil(enableEpochsHandler) ||
		check.IfNil(shardCoordinator) || currentRoundProvider == nil {
		return nil, ErrInvalidPrototypeTransferGuardDelegate
	}
	_, ok := delegate.(vmcommon.AcceptPayableChecker)
	if !ok {
		return nil, ErrInvalidPrototypeTransferGuardDelegate
	}

	return &prototypeTransferGuard{
		functionName:         functionName,
		delegate:             delegate,
		classifier:           classifier,
		enableEpochsHandler:  enableEpochsHandler,
		shardCoordinator:     shardCoordinator,
		cebEpoch:             cebEpoch,
		currentRoundProvider: currentRoundProvider,
	}, nil
}

// ProcessBuiltinFunction blocks prototype-regulated tokens from ordinary transfer entry points.
func (guard *prototypeTransferGuard) ProcessBuiltinFunction(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	if !guard.enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag) {
		return guard.delegate.ProcessBuiltinFunction(acntSnd, acntDst, vmInput)
	}

	tokenIDs, identifiable := prototypeTransferTokenIDs(guard.functionName, vmInput)
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
			return nil, ErrPrototypeRegulatedTransferRequiresDRWA
		}
	}

	return guard.delegate.ProcessBuiltinFunction(acntSnd, acntDst, vmInput)
}

func (guard *prototypeTransferGuard) isSameShardFungibleCandidate(
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

func (guard *prototypeTransferGuard) processSameShardFungible(
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
		return nil, fmt.Errorf("%w: current round: %w", ErrPrototypeSameShardTransferDenied, err)
	}
	err = validatePrototypeReceiver(acntDst, tokenID, acntDst.AddressBytes(), guard.cebEpoch, currentRound)
	if err != nil {
		return nil, fmt.Errorf("%w: receiver: %w", ErrPrototypeSameShardTransferDenied, err)
	}

	return guard.delegate.ProcessBuiltinFunction(acntSnd, acntDst, vmInput)
}

func (guard *prototypeTransferGuard) validateSameShardAdmission(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
	tokenID []byte,
) error {
	if guard.cebEpoch == 0 || len(vmInput.Arguments) != 2 ||
		vmInput.Function != core.BuiltInFunctionESDTTransfer ||
		vmInput.NativeCallOrigin != vmcommon.NativeCallOriginOriginalUserTransaction ||
		vmInput.CallType != vmData.DirectCall || vmInput.CallValue == nil || vmInput.CallValue.Sign() != 0 ||
		vmInput.GasLocked != 0 || vmInput.ReturnCallAfterError || hasPrototypeAsyncArguments(vmInput.AsyncArguments) ||
		len(vmInput.ESDTTransfers) != 0 {
		return fmt.Errorf("%w: execution origin", ErrPrototypeSameShardTransferDenied)
	}
	source := acntSnd.AddressBytes()
	destination := acntDst.AddressBytes()
	if len(source) != prototypeAddressLength || len(destination) != prototypeAddressLength ||
		bytes.Equal(source, destination) || core.IsSmartContractAddress(source) || core.IsSmartContractAddress(destination) ||
		!bytes.Equal(vmInput.CallerAddr, source) || !bytes.Equal(vmInput.RecipientAddr, destination) ||
		guard.shardCoordinator.ComputeId(source) != guard.shardCoordinator.SelfId() ||
		guard.shardCoordinator.ComputeId(destination) != guard.shardCoordinator.SelfId() {
		return fmt.Errorf("%w: holder route", ErrPrototypeSameShardTransferDenied)
	}
	if len(vmInput.CurrentTxHash) != prototypeHashLength || len(vmInput.OriginalTxHash) != prototypeHashLength ||
		len(vmInput.PrevTxHash) != prototypeHashLength ||
		!bytes.Equal(vmInput.CurrentTxHash, vmInput.OriginalTxHash) ||
		!bytes.Equal(vmInput.CurrentTxHash, vmInput.PrevTxHash) ||
		bytes.Equal(vmInput.CurrentTxHash, make([]byte, prototypeHashLength)) {
		return fmt.Errorf("%w: transaction identity", ErrPrototypeSameShardTransferDenied)
	}
	quantity := vmInput.Arguments[1]
	if !bytes.Equal(vmInput.Arguments[0], tokenID) || !vmcommon.ValidateToken(tokenID) || len(tokenID) > 64 ||
		len(quantity) == 0 || len(quantity) > 32 || quantity[0] == 0 || new(big.Int).SetBytes(quantity).Sign() <= 0 {
		return fmt.Errorf("%w: transfer arguments", ErrPrototypeSameShardTransferDenied)
	}

	return nil
}

// SetNewGasConfig forwards gas schedule changes to the original transfer built-in.
func (guard *prototypeTransferGuard) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	guard.delegate.SetNewGasConfig(gasCost)
}

// IsActive preserves the original transfer built-in activation behavior.
func (guard *prototypeTransferGuard) IsActive() bool {
	return guard.delegate.IsActive()
}

// SetPayableChecker preserves the creator's post-construction payable-checker injection.
func (guard *prototypeTransferGuard) SetPayableChecker(payableChecker vmcommon.PayableChecker) error {
	delegate, ok := guard.delegate.(vmcommon.AcceptPayableChecker)
	if !ok {
		return ErrInvalidPrototypeTransferGuardDelegate
	}

	return delegate.SetPayableChecker(payableChecker)
}

// IsInterfaceNil returns true for a nil guard.
func (guard *prototypeTransferGuard) IsInterfaceNil() bool {
	return guard == nil
}

func prototypeTransferTokenIDs(functionName string, vmInput *vmcommon.ContractCallInput) ([][]byte, bool) {
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
		return prototypeMultiTransferTokenIDs(vmInput)
	default:
		return nil, false
	}
}

func prototypeMultiTransferTokenIDs(vmInput *vmcommon.ContractCallInput) ([][]byte, bool) {
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
	maximumCountFromArguments := uint64((len(vmInput.Arguments) - firstTokenIndex) / prototypeArgumentsPerMultiTransfer)
	if declaredCount == 0 || declaredCount > maximumCountFromArguments {
		return nil, false
	}

	tokenIDs := make([][]byte, 0, int(declaredCount))
	for index := uint64(0); index < declaredCount; index++ {
		tokenIndex := firstTokenIndex + int(index)*prototypeArgumentsPerMultiTransfer
		tokenIDs = append(tokenIDs, vmInput.Arguments[tokenIndex])
	}

	return tokenIDs, true
}

type prototypeGuardedBuiltInFunctionFactory struct {
	delegate                              vmcommon.BuiltInFunctionFactory
	accounts                              vmcommon.AccountsAdapter
	enableEpochsHandler                   vmcommon.EnableEpochsHandler
	prototypeDRWANetworkDomain            [32]byte
	prototypeGasScheduleCatalog           *drwaprototype.GasScheduleCatalog
	gasScheduleNotifier                   core.GasScheduleNotifier
	prototypeDRWACEBEpoch                 uint32
	prototypeDRWASettlementLifetimeRounds uint64
	shardCoordinator                      sharding.Coordinator
	prototypeSourceDebit                  *prototypeSourceDebit
	prototypeDestination                  *prototypeDestination
	prototypeSourceCompletion             *prototypeSourceCompletion
	mutBlockchainHook                     sync.RWMutex
	blockchainHook                        vmcommon.BlockchainDataHook
}

// PrototypeDRWANetworkDomain returns the immutable value injected into this prototype factory.
func (factory *prototypeGuardedBuiltInFunctionFactory) PrototypeDRWANetworkDomain() [32]byte {
	if factory == nil {
		return [32]byte{}
	}
	return factory.prototypeDRWANetworkDomain
}

// PrototypeGasScheduleCatalogIdentity returns the sealed configured timeline identity.
func (factory *prototypeGuardedBuiltInFunctionFactory) PrototypeGasScheduleCatalogIdentity() ([32]byte, error) {
	if factory == nil || factory.prototypeGasScheduleCatalog == nil {
		return [32]byte{}, ErrPrototypeGasScheduleUnavailable
	}
	return factory.prototypeGasScheduleCatalog.Identity()
}

// PrototypeCurrentGasScheduleIdentity verifies that the notifier's current map is retained.
func (factory *prototypeGuardedBuiltInFunctionFactory) PrototypeCurrentGasScheduleIdentity() ([32]byte, error) {
	if factory == nil || factory.prototypeGasScheduleCatalog == nil || factory.gasScheduleNotifier == nil {
		return [32]byte{}, ErrPrototypeGasScheduleUnavailable
	}
	provider, ok := factory.gasScheduleNotifier.(prototypeConfiguredGasScheduleProvider)
	if !ok {
		return [32]byte{}, ErrPrototypeGasScheduleUnavailable
	}
	return currentPrototypeGasScheduleIdentity(provider, factory.prototypeGasScheduleCatalog)
}

// PrototypeCurrentWorkBudgets returns the retained current identity and conservative S1 work reserve.
func (factory *prototypeGuardedBuiltInFunctionFactory) PrototypeCurrentWorkBudgets() (
	[32]byte,
	drwaprototype.WorkBudgets,
	uint64,
	error,
) {
	if factory == nil || factory.prototypeGasScheduleCatalog == nil || factory.gasScheduleNotifier == nil {
		return [32]byte{}, drwaprototype.WorkBudgets{}, 0, ErrPrototypeGasScheduleUnavailable
	}
	provider, ok := factory.gasScheduleNotifier.(prototypeConfiguredGasScheduleProvider)
	if !ok {
		return [32]byte{}, drwaprototype.WorkBudgets{}, 0, ErrPrototypeGasScheduleUnavailable
	}

	return currentPrototypeWorkBudgets(provider, factory.prototypeGasScheduleCatalog)
}

// PrototypeRetainedWorkBudgets validates one pinned identity and returns the approved maxima.
func (factory *prototypeGuardedBuiltInFunctionFactory) PrototypeRetainedWorkBudgets(
	identity [32]byte,
) (drwaprototype.WorkBudgets, uint64, error) {
	if factory == nil {
		return drwaprototype.WorkBudgets{}, 0, ErrPrototypeGasScheduleUnavailable
	}
	return retainedPrototypeWorkBudgets(identity, factory.prototypeGasScheduleCatalog)
}

func (factory *prototypeGuardedBuiltInFunctionFactory) ESDTGlobalSettingsHandler() vmcommon.ESDTGlobalSettingsHandler {
	return factory.delegate.ESDTGlobalSettingsHandler()
}

func (factory *prototypeGuardedBuiltInFunctionFactory) NFTStorageHandler() vmcommon.SimpleESDTNFTStorageHandler {
	return factory.delegate.NFTStorageHandler()
}

func (factory *prototypeGuardedBuiltInFunctionFactory) BuiltInFunctionContainer() vmcommon.BuiltInFunctionContainer {
	return factory.delegate.BuiltInFunctionContainer()
}

func (factory *prototypeGuardedBuiltInFunctionFactory) SetPayableHandler(handler vmcommon.PayableHandler) error {
	return factory.delegate.SetPayableHandler(handler)
}

func (factory *prototypeGuardedBuiltInFunctionFactory) SetBlockchainHook(handler vmcommon.BlockchainDataHook) error {
	err := factory.delegate.SetBlockchainHook(handler)
	if err != nil {
		return err
	}
	if check.IfNil(handler) {
		return ErrInvalidPrototypeTransferGuardDelegate
	}
	factory.mutBlockchainHook.Lock()
	factory.blockchainHook = handler
	factory.mutBlockchainHook.Unlock()
	if factory.prototypeSourceDebit != nil {
		err = factory.prototypeSourceDebit.setBlockchainHook(handler)
		if err != nil {
			return err
		}
	}
	if factory.prototypeDestination != nil {
		return factory.prototypeDestination.setBlockchainHook(handler)
	}
	return nil
}

func (factory *prototypeGuardedBuiltInFunctionFactory) prototypeCurrentRound() (uint64, error) {
	factory.mutBlockchainHook.RLock()
	hook := factory.blockchainHook
	factory.mutBlockchainHook.RUnlock()
	if check.IfNil(hook) {
		return 0, ErrPrototypeSameShardTransferDenied
	}

	return hook.CurrentRound(), nil
}

func (factory *prototypeGuardedBuiltInFunctionFactory) CreateBuiltInFunctionContainer() error {
	err := factory.delegate.CreateBuiltInFunctionContainer()
	if err != nil {
		return err
	}

	return factory.installPrototypeTransferGuards()
}

func (factory *prototypeGuardedBuiltInFunctionFactory) IsInterfaceNil() bool {
	return factory == nil
}

func (factory *prototypeGuardedBuiltInFunctionFactory) installPrototypeTransferGuards() error {
	container := factory.delegate.BuiltInFunctionContainer()
	sourceDebitDelegate, err := container.Get(core.BuiltInFunctionESDTTransfer)
	if err != nil {
		return err
	}
	classifier := func(tokenID []byte) (bool, error) {
		return drwaprototype.IsPrototypeRegulatedToken(factory.accounts, tokenID)
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
		guard, err := newPrototypeTransferGuard(
			functionName,
			delegate,
			classifier,
			factory.enableEpochsHandler,
			factory.shardCoordinator,
			factory.prototypeDRWACEBEpoch,
			factory.prototypeCurrentRound,
		)
		if err != nil {
			return err
		}
		err = container.Replace(functionName, guard)
		if err != nil {
			return err
		}
	}

	factory.prototypeSourceDebit, err = newPrototypeSourceDebit(prototypeSourceDebitArgs{
		delegate:                   sourceDebitDelegate,
		classifier:                 classifier,
		enableEpochsHandler:        factory.enableEpochsHandler,
		shardCoordinator:           factory.shardCoordinator,
		networkDomain:              factory.prototypeDRWANetworkDomain,
		cebEpoch:                   factory.prototypeDRWACEBEpoch,
		settlementLifetimeRounds:   factory.prototypeDRWASettlementLifetimeRounds,
		currentWorkBudgetsProvider: factory.PrototypeCurrentWorkBudgets,
	})
	if err != nil {
		return err
	}

	err = container.Add(PrototypeSourceDebitFunction, factory.prototypeSourceDebit)
	if err != nil {
		return err
	}

	factory.prototypeDestination, err = newPrototypeDestination(prototypeDestinationArgs{
		delegate:                    sourceDebitDelegate,
		classifier:                  classifier,
		enableEpochsHandler:         factory.enableEpochsHandler,
		shardCoordinator:            factory.shardCoordinator,
		networkDomain:               factory.prototypeDRWANetworkDomain,
		cebEpoch:                    factory.prototypeDRWACEBEpoch,
		retainedWorkBudgetsProvider: factory.PrototypeRetainedWorkBudgets,
	})
	if err != nil {
		return err
	}

	err = container.Add(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope, factory.prototypeDestination)
	if err != nil {
		return err
	}

	factory.prototypeSourceCompletion, err = newPrototypeSourceCompletion(prototypeSourceCompletionArgs{
		delegate:                    sourceDebitDelegate,
		enableEpochsHandler:         factory.enableEpochsHandler,
		shardCoordinator:            factory.shardCoordinator,
		networkDomain:               factory.prototypeDRWANetworkDomain,
		retainedWorkBudgetsProvider: factory.PrototypeRetainedWorkBudgets,
	})
	if err != nil {
		return err
	}
	err = container.Add(PrototypeSettlementReceiptFunction, factory.prototypeSourceCompletion)
	if err != nil {
		return err
	}
	err = container.Add(PrototypeRefundEnvelopeFunction, factory.prototypeSourceCompletion)
	if err != nil {
		return err
	}

	factory.mutBlockchainHook.RLock()
	hook := factory.blockchainHook
	factory.mutBlockchainHook.RUnlock()
	if check.IfNil(hook) {
		return nil
	}
	err = factory.prototypeSourceDebit.setBlockchainHook(hook)
	if err != nil {
		return err
	}
	return factory.prototypeDestination.setBlockchainHook(hook)
}
