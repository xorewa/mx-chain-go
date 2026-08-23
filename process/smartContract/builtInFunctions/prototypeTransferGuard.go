package builtInFunctions

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
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
)

type prototypeTokenClassifier func(tokenID []byte) (bool, error)

type prototypeTransferGuard struct {
	functionName        string
	delegate            vmcommon.BuiltinFunction
	classifier          prototypeTokenClassifier
	enableEpochsHandler vmcommon.EnableEpochsHandler
}

func newPrototypeTransferGuard(
	functionName string,
	delegate vmcommon.BuiltinFunction,
	classifier prototypeTokenClassifier,
	enableEpochsHandler vmcommon.EnableEpochsHandler,
) (*prototypeTransferGuard, error) {
	if check.IfNil(delegate) || classifier == nil || check.IfNil(enableEpochsHandler) {
		return nil, ErrInvalidPrototypeTransferGuardDelegate
	}
	_, ok := delegate.(vmcommon.AcceptPayableChecker)
	if !ok {
		return nil, ErrInvalidPrototypeTransferGuardDelegate
	}

	return &prototypeTransferGuard{
		functionName:        functionName,
		delegate:            delegate,
		classifier:          classifier,
		enableEpochsHandler: enableEpochsHandler,
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
			return nil, ErrPrototypeRegulatedTransferRequiresDRWA
		}
	}

	return guard.delegate.ProcessBuiltinFunction(acntSnd, acntDst, vmInput)
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
	delegate                   vmcommon.BuiltInFunctionFactory
	accounts                   vmcommon.AccountsAdapter
	enableEpochsHandler        vmcommon.EnableEpochsHandler
	prototypeDRWANetworkDomain [32]byte
}

// PrototypeDRWANetworkDomain returns the immutable value injected into this prototype factory.
func (factory *prototypeGuardedBuiltInFunctionFactory) PrototypeDRWANetworkDomain() [32]byte {
	if factory == nil {
		return [32]byte{}
	}
	return factory.prototypeDRWANetworkDomain
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
	return factory.delegate.SetBlockchainHook(handler)
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
		guard, err := newPrototypeTransferGuard(functionName, delegate, classifier, factory.enableEpochsHandler)
		if err != nil {
			return err
		}
		err = container.Replace(functionName, guard)
		if err != nil {
			return err
		}
	}

	return nil
}
