package builtInFunctions

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/multiversx/mx-chain-go/testscommon/vmcommonMocks"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmcommonBuiltInFunctions "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	vmcommonMock "github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

func TestPrototypeSourceDebitUsesBaselineESDTDelegateForActualDebit(t *testing.T) {
	t.Parallel()

	sourceAddress := bytes.Repeat([]byte{0x11}, prototypeAddressLength)
	destination := bytes.Repeat([]byte{0x22}, prototypeAddressLength)
	tokenID := []byte("TOKEN-abcdef")
	marshaller := &vmcommonMock.MarshalizerMock{}
	delegate, err := vmcommonBuiltInFunctions.NewESDTTransferFunc(
		5,
		marshaller,
		&vmcommonMock.GlobalSettingsHandlerStub{},
		&vmcommonMock.ShardCoordinatorStub{ComputeIdCalled: func(address []byte) uint32 {
			if bytes.Equal(address, destination) {
				return 1
			}
			return 0
		}},
		&vmcommonMock.ESDTRoleHandlerStub{},
		&vmcommonMock.EnableEpochsHandlerStub{},
	)
	require.NoError(t, err)
	sourceAccount := vmcommonMock.NewUserAccount(sourceAddress)
	esdtKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...)
	encodedToken, err := marshaller.Marshal(&esdt.ESDigitalToken{Value: big.NewInt(100)})
	require.NoError(t, err)
	require.NoError(t, sourceAccount.SaveKeyValue(esdtKey, encodedToken))

	sourceDebit := newPrototypeSourceDebitForTest(t, delegate, func(_ []byte) (bool, error) { return true, nil })
	require.NoError(t, sourceDebit.setBlockchainHook(&testscommon.BlockChainHookStub{CurrentRoundCalled: func() uint64 { return 7 }}))
	output, err := sourceDebit.ProcessBuiltinFunction(sourceAccount, sourceAccount, newPrototypeSourceInput(sourceAddress, destination))
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, output.ReturnCode)
	require.Equal(t, uint64(45), output.GasRemaining)

	encodedToken, _, err = sourceAccount.RetrieveValue(esdtKey)
	require.NoError(t, err)
	actualToken := &esdt.ESDigitalToken{}
	require.NoError(t, marshaller.Unmarshal(actualToken, encodedToken))
	require.Zero(t, actualToken.Value.Cmp(big.NewInt(98)))
	require.Len(t, output.OutputAccounts[string(destination)].OutputTransfers, 1)
}

func TestPrototypeSourceDebitCreatesOpenEffectThenDebitsAndEmitsOneCarrier(t *testing.T) {
	t.Parallel()

	events := make([]string, 0, 2)
	stored := make(map[string][]byte)
	dataHandler := newPrototypeSourceDataHandler(stored, func() { events = append(events, "open-effect") })
	sourceAddress := bytes.Repeat([]byte{0x11}, prototypeAddressLength)
	destination := bytes.Repeat([]byte{0x22}, prototypeAddressLength)
	sourceAccount := newPrototypeSourceAccount(sourceAddress, dataHandler)
	delegateCalled := false
	delegate := &processMock.BuiltInFunctionStub{
		ProcessBuiltinFunctionCalled: func(actualSource, actualDestination vmcommon.UserAccountHandler, input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
			delegateCalled = true
			events = append(events, "debit")
			require.Same(t, sourceAccount, actualSource)
			require.Nil(t, actualDestination)
			require.Equal(t, "ESDTTransfer", input.Function)
			require.Equal(t, destination, input.RecipientAddr)
			require.Equal(t, [][]byte{[]byte("TOKEN-abcdef"), {0x02}}, input.Arguments)
			require.Equal(t, uint64(50), input.GasProvided)
			return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 49}, nil
		},
	}
	sourceDebit := newPrototypeSourceDebitForTest(t, delegate, func(_ []byte) (bool, error) { return true, nil })
	require.NoError(t, sourceDebit.setBlockchainHook(&testscommon.BlockChainHookStub{
		CurrentRoundCalled: func() uint64 { return 7 },
	}))
	input := newPrototypeSourceInput(sourceAddress, destination)
	input.AsyncArguments = &vmcommon.AsyncArguments{}

	output, err := sourceDebit.ProcessBuiltinFunction(sourceAccount, sourceAccount, input)
	require.NoError(t, err)
	require.True(t, delegateCalled)
	require.Equal(t, []string{"open-effect", "debit"}, events)
	require.Equal(t, uint64(49), output.GasRemaining)
	require.Len(t, output.OutputAccounts, 1)
	outputAccount := output.OutputAccounts[string(destination)]
	require.NotNil(t, outputAccount)
	require.Equal(t, destination, outputAccount.Address)
	require.Len(t, outputAccount.OutputTransfers, 1)
	carrier := outputAccount.OutputTransfers[0]
	require.Equal(t, uint32(1), carrier.Index)
	require.Zero(t, carrier.Value.Sign())
	require.Equal(t, uint64(100), carrier.GasLimit)
	require.Zero(t, carrier.GasLocked)
	require.Equal(t, vmData.DirectCall, carrier.CallType)
	require.Equal(t, vmData.ProtocolMessageKindDRWA, carrier.ProtocolMessageKind)
	require.Equal(t, sourceAddress, carrier.SenderAddress)

	prefix := []byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope + "@")
	require.True(t, bytes.HasPrefix(carrier.Data, prefix))
	envelopeBytes, err := hex.DecodeString(string(carrier.Data[len(prefix):]))
	require.NoError(t, err)
	envelope, err := drwaprototype.DecodeValueEnvelope(envelopeBytes)
	require.NoError(t, err)
	require.Equal(t, uint64(107), envelope.Context.SettlementExpiry)
	require.Equal(t, uint32(9), envelope.Context.CEBEpoch)
	require.Equal(t, destination, envelope.Context.DestinationHolder[:])
	require.Equal(t, sourceAddress, envelope.Context.SourceHolder[:])
	require.Equal(t, uint64(10), envelope.Context.DestinationGateGasLimit)
	require.Equal(t, uint64(20), envelope.Context.SuccessReceiptGasLimit)
	require.Equal(t, uint64(30), envelope.Context.RefundGenerationGasLimit)
	require.Equal(t, uint64(40), envelope.Context.SourceCompletionGasLimit)

	effect, err := drwaprototype.LoadOpenEffect(dataHandler, envelope.Context.EffectID)
	require.NoError(t, err)
	require.Equal(t, envelope.Context.EffectID, effect.EffectID)
	require.Equal(t, envelope.Context.GasScheduleIdentity, effect.GasScheduleIdentity)
	require.NoError(t, drwaprototype.ValidateDirectValueOpenEffectContext([32]byte{1}, *effect, envelope.Context))
}

func TestPrototypeSourceDebitDeniesAdmissionAndAvailabilityBeforeMutation(t *testing.T) {
	t.Parallel()

	errBudgetUnavailable := errors.New("budget unavailable")
	tests := []struct {
		name   string
		mutate func(sourceDebit *prototypeSourceDebit, input *vmcommon.ContractCallInput)
	}{
		{name: "activation disabled", mutate: func(sourceDebit *prototypeSourceDebit, _ *vmcommon.ContractCallInput) {
			sourceDebit.enableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
		}},
		{name: "unknown origin", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) {
			input.NativeCallOrigin = vmcommon.NativeCallOriginUnknown
		}},
		{name: "callback", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) {
			input.CallType = vmData.AsynchronousCallBack
		}},
		{name: "nil call value", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) { input.CallValue = nil }},
		{name: "nonzero EGLD", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) { input.CallValue = big.NewInt(1) }},
		{name: "gas locked", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) { input.GasLocked = 1 }},
		{name: "wrong function", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) { input.Function = "ESDTTransfer" }},
		{name: "caller not source", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) { input.CallerAddr[0] ^= 0xff }},
		{name: "recipient not source", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) { input.RecipientAddr[0] ^= 0xff }},
		{name: "return after error", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) { input.ReturnCallAfterError = true }},
		{name: "async arguments", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) {
			input.AsyncArguments = &vmcommon.AsyncArguments{CallID: []byte{1}}
		}},
		{name: "parsed ESDT transfers", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) {
			input.ESDTTransfers = []*vmcommon.ESDTTransfer{{}}
		}},
		{name: "unequal hashes", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) { input.PrevTxHash[0] ^= 0xff }},
		{name: "zero hashes", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) {
			zeroHash := make([]byte, prototypeHashLength)
			input.CurrentTxHash = append([]byte(nil), zeroHash...)
			input.OriginalTxHash = append([]byte(nil), zeroHash...)
			input.PrevTxHash = append([]byte(nil), zeroHash...)
		}},
		{name: "wrong hash length", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) {
			input.CurrentTxHash = input.CurrentTxHash[:prototypeHashLength-1]
		}},
		{name: "wrong argument count", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) {
			input.Arguments = input.Arguments[:2]
		}},
		{name: "same shard destination", mutate: func(sourceDebit *prototypeSourceDebit, input *vmcommon.ContractCallInput) {
			sourceDebit.shardCoordinator = testscommon.NewMultiShardsCoordinatorMock(1)
		}},
		{name: "smart contract destination", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) {
			input.Arguments[0] = make([]byte, prototypeAddressLength)
		}},
		{name: "invalid token", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) {
			input.Arguments[1] = []byte("invalid")
		}},
		{name: "nonminimal quantity", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) { input.Arguments[2] = []byte{0, 1} }},
		{name: "zero network domain", mutate: func(sourceDebit *prototypeSourceDebit, _ *vmcommon.ContractCallInput) {
			sourceDebit.networkDomain = [32]byte{}
		}},
		{name: "zero CEB", mutate: func(sourceDebit *prototypeSourceDebit, _ *vmcommon.ContractCallInput) { sourceDebit.cebEpoch = 0 }},
		{name: "zero lifetime", mutate: func(sourceDebit *prototypeSourceDebit, _ *vmcommon.ContractCallInput) {
			sourceDebit.settlementLifetimeRounds = 0
		}},
		{name: "budget unavailable", mutate: func(sourceDebit *prototypeSourceDebit, _ *vmcommon.ContractCallInput) {
			sourceDebit.currentWorkBudgetsProvider = func() ([32]byte, drwaprototype.WorkBudgets, uint64, error) {
				return [32]byte{}, drwaprototype.WorkBudgets{}, 0, errBudgetUnavailable
			}
		}},
		{name: "gas equals reserve", mutate: func(_ *prototypeSourceDebit, input *vmcommon.ContractCallInput) { input.GasProvided = 100 }},
		{name: "round unavailable", mutate: func(sourceDebit *prototypeSourceDebit, _ *vmcommon.ContractCallInput) {
			sourceDebit.blockchainHook = nil
		}},
		{name: "expiry overflow", mutate: func(sourceDebit *prototypeSourceDebit, _ *vmcommon.ContractCallInput) {
			require.NoError(t, sourceDebit.setBlockchainHook(&testscommon.BlockChainHookStub{CurrentRoundCalled: func() uint64 { return math.MaxUint64 }}))
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stored := make(map[string][]byte)
			writeCount := 0
			dataHandler := newPrototypeSourceDataHandler(stored, func() { writeCount++ })
			sourceAddress := bytes.Repeat([]byte{0x11}, prototypeAddressLength)
			destination := bytes.Repeat([]byte{0x22}, prototypeAddressLength)
			sourceAccount := newPrototypeSourceAccount(sourceAddress, dataHandler)
			delegateCalled := false
			delegate := &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
			}}
			sourceDebit := newPrototypeSourceDebitForTest(t, delegate, func(_ []byte) (bool, error) { return true, nil })
			require.NoError(t, sourceDebit.setBlockchainHook(&testscommon.BlockChainHookStub{CurrentRoundCalled: func() uint64 { return 7 }}))
			input := newPrototypeSourceInput(sourceAddress, destination)
			test.mutate(sourceDebit, input)

			_, err := sourceDebit.ProcessBuiltinFunction(sourceAccount, sourceAccount, input)
			require.ErrorIs(t, err, ErrPrototypeSourceDebitDenied)
			if test.name == "budget unavailable" {
				require.ErrorIs(t, err, errBudgetUnavailable)
			}
			require.False(t, delegateCalled)
			require.Zero(t, writeCount)
			require.Empty(t, stored)
		})
	}
}

func TestPrototypeSourceDebitDeniesUnregulatedAndClassificationFailureBeforeMutation(t *testing.T) {
	t.Parallel()

	classificationFailure := errors.New("classification failed")
	tests := []struct {
		name       string
		classifier prototypeTokenClassifier
		wantCause  error
	}{
		{name: "ordinary token", classifier: func(_ []byte) (bool, error) { return false, nil }},
		{name: "observation failure", classifier: func(_ []byte) (bool, error) { return false, classificationFailure }, wantCause: classificationFailure},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stored := make(map[string][]byte)
			dataHandler := newPrototypeSourceDataHandler(stored, nil)
			sourceAddress := bytes.Repeat([]byte{0x11}, prototypeAddressLength)
			destination := bytes.Repeat([]byte{0x22}, prototypeAddressLength)
			sourceAccount := newPrototypeSourceAccount(sourceAddress, dataHandler)
			delegateCalled := false
			delegate := &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				return nil, nil
			}}
			sourceDebit := newPrototypeSourceDebitForTest(t, delegate, test.classifier)
			require.NoError(t, sourceDebit.setBlockchainHook(&testscommon.BlockChainHookStub{}))

			_, err := sourceDebit.ProcessBuiltinFunction(sourceAccount, sourceAccount, newPrototypeSourceInput(sourceAddress, destination))
			require.ErrorIs(t, err, ErrPrototypeSourceDebitDenied)
			if test.wantCause != nil {
				require.ErrorIs(t, err, test.wantCause)
			}
			require.False(t, delegateCalled)
			require.Empty(t, stored)
		})
	}
}

func TestPrototypeSourceDebitDeniesInvalidAccountRoutesBeforeMutation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		invoke func(sourceDebit *prototypeSourceDebit, dataHandler vmcommon.AccountDataHandler) (*vmcommon.VMOutput, error)
	}{
		{name: "nil input", invoke: func(sourceDebit *prototypeSourceDebit, dataHandler vmcommon.AccountDataHandler) (*vmcommon.VMOutput, error) {
			source := bytes.Repeat([]byte{0x11}, prototypeAddressLength)
			account := newPrototypeSourceAccount(source, dataHandler)
			return sourceDebit.ProcessBuiltinFunction(account, account, nil)
		}},
		{name: "nil source account", invoke: func(sourceDebit *prototypeSourceDebit, _ vmcommon.AccountDataHandler) (*vmcommon.VMOutput, error) {
			source := bytes.Repeat([]byte{0x11}, prototypeAddressLength)
			return sourceDebit.ProcessBuiltinFunction(nil, newPrototypeSourceAccount(source, nil), newPrototypeSourceInput(source, bytes.Repeat([]byte{0x22}, prototypeAddressLength)))
		}},
		{name: "nil destination account", invoke: func(sourceDebit *prototypeSourceDebit, dataHandler vmcommon.AccountDataHandler) (*vmcommon.VMOutput, error) {
			source := bytes.Repeat([]byte{0x11}, prototypeAddressLength)
			return sourceDebit.ProcessBuiltinFunction(newPrototypeSourceAccount(source, dataHandler), nil, newPrototypeSourceInput(source, bytes.Repeat([]byte{0x22}, prototypeAddressLength)))
		}},
		{name: "destination account not source", invoke: func(sourceDebit *prototypeSourceDebit, dataHandler vmcommon.AccountDataHandler) (*vmcommon.VMOutput, error) {
			source := bytes.Repeat([]byte{0x11}, prototypeAddressLength)
			other := bytes.Repeat([]byte{0x44}, prototypeAddressLength)
			return sourceDebit.ProcessBuiltinFunction(newPrototypeSourceAccount(source, dataHandler), newPrototypeSourceAccount(other, nil), newPrototypeSourceInput(source, bytes.Repeat([]byte{0x22}, prototypeAddressLength)))
		}},
		{name: "wrong source address length", invoke: func(sourceDebit *prototypeSourceDebit, dataHandler vmcommon.AccountDataHandler) (*vmcommon.VMOutput, error) {
			source := bytes.Repeat([]byte{0x11}, prototypeAddressLength-1)
			account := newPrototypeSourceAccount(source, dataHandler)
			return sourceDebit.ProcessBuiltinFunction(account, account, newPrototypeSourceInput(source, bytes.Repeat([]byte{0x22}, prototypeAddressLength)))
		}},
		{name: "smart contract source", invoke: func(sourceDebit *prototypeSourceDebit, dataHandler vmcommon.AccountDataHandler) (*vmcommon.VMOutput, error) {
			source := make([]byte, prototypeAddressLength)
			account := newPrototypeSourceAccount(source, dataHandler)
			return sourceDebit.ProcessBuiltinFunction(account, account, newPrototypeSourceInput(source, bytes.Repeat([]byte{0x22}, prototypeAddressLength)))
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			stored := make(map[string][]byte)
			writeCount := 0
			dataHandler := newPrototypeSourceDataHandler(stored, func() { writeCount++ })
			delegateCalled := false
			delegate := &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				return nil, nil
			}}
			sourceDebit := newPrototypeSourceDebitForTest(t, delegate, func(_ []byte) (bool, error) { return true, nil })

			output, err := test.invoke(sourceDebit, dataHandler)
			require.Nil(t, output)
			require.ErrorIs(t, err, ErrPrototypeSourceDebitDenied)
			require.False(t, delegateCalled)
			require.Zero(t, writeCount)
			require.Empty(t, stored)
		})
	}
}

func TestPrototypeSourceDebitReturnsMutationErrorForStorageDelegateAndPostDebitFailures(t *testing.T) {
	t.Parallel()

	injectedStorage := errors.New("storage failure")
	injectedDelegate := errors.New("delegate failure")
	tests := []struct {
		name        string
		dataHandler vmcommon.AccountDataHandler
		delegate    vmcommon.BuiltinFunction
		wantCause   error
	}{
		{
			name: "storage",
			dataHandler: &trieMock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) { return nil, 0, nil },
				SaveKeyValueCalled:  func(_, _ []byte) error { return injectedStorage },
			},
			delegate:  &processMock.BuiltInFunctionStub{},
			wantCause: injectedStorage,
		},
		{
			name:        "baseline debit",
			dataHandler: newPrototypeSourceDataHandler(make(map[string][]byte), nil),
			delegate: &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				return nil, injectedDelegate
			}},
			wantCause: injectedDelegate,
		},
		{
			name:        "post debit output validation",
			dataHandler: newPrototypeSourceDataHandler(make(map[string][]byte), nil),
			delegate: &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, OutputAccounts: map[string]*vmcommon.OutputAccount{"unexpected": {}}}, nil
			}},
			wantCause: ErrInvalidPrototypeSourceDebitDelegate,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			sourceAddress := bytes.Repeat([]byte{0x11}, prototypeAddressLength)
			destination := bytes.Repeat([]byte{0x22}, prototypeAddressLength)
			sourceAccount := newPrototypeSourceAccount(sourceAddress, test.dataHandler)
			sourceDebit := newPrototypeSourceDebitForTest(t, test.delegate, func(_ []byte) (bool, error) { return true, nil })
			require.NoError(t, sourceDebit.setBlockchainHook(&testscommon.BlockChainHookStub{}))

			output, err := sourceDebit.ProcessBuiltinFunction(sourceAccount, sourceAccount, newPrototypeSourceInput(sourceAddress, destination))
			require.Nil(t, output)
			require.ErrorIs(t, err, ErrPrototypeSourceDebitMutation)
			require.ErrorIs(t, err, test.wantCause)
		})
	}
}

func TestPrototypeSourceDebitLifecycleAndConstruction(t *testing.T) {
	t.Parallel()

	_, err := newPrototypeSourceDebit(prototypeSourceDebitArgs{})
	require.ErrorIs(t, err, ErrInvalidPrototypeSourceDebitDelegate)

	gasForwarded := false
	delegate := &processMock.BuiltInFunctionStub{SetNewGasConfigCalled: func(_ *vmcommon.GasCost) { gasForwarded = true }}
	sourceDebit := newPrototypeSourceDebitForTest(t, delegate, func(_ []byte) (bool, error) { return true, nil })
	require.True(t, sourceDebit.IsActive())
	sourceDebit.SetNewGasConfig(&vmcommon.GasCost{})
	require.True(t, gasForwarded)
	require.ErrorIs(t, sourceDebit.setBlockchainHook(nil), ErrInvalidPrototypeSourceDebitDelegate)
	require.False(t, sourceDebit.IsInterfaceNil())
	var nilSourceDebit *prototypeSourceDebit
	require.True(t, nilSourceDebit.IsInterfaceNil())
}

func newPrototypeSourceDebitForTest(
	t *testing.T,
	delegate vmcommon.BuiltinFunction,
	classifier prototypeTokenClassifier,
) *prototypeSourceDebit {
	t.Helper()
	coordinator := &testscommon.ShardsCoordinatorMock{
		NoShards:     2,
		CurrentShard: 0,
		ComputeIdCalled: func(address []byte) uint32 {
			if len(address) > 0 && address[0] == 0x22 {
				return 1
			}
			return 0
		},
	}
	sourceDebit, err := newPrototypeSourceDebit(prototypeSourceDebitArgs{
		delegate:                 delegate,
		classifier:               classifier,
		enableEpochsHandler:      enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.DRWAEnforcementFlag),
		shardCoordinator:         coordinator,
		networkDomain:            [32]byte{1},
		cebEpoch:                 9,
		settlementLifetimeRounds: 100,
		currentWorkBudgetsProvider: func() ([32]byte, drwaprototype.WorkBudgets, uint64, error) {
			return [32]byte{2}, drwaprototype.WorkBudgets{
				DestinationGate:  10,
				SuccessReceipt:   20,
				RefundGeneration: 30,
				SourceCompletion: 40,
			}, 100, nil
		},
	})
	require.NoError(t, err)

	return sourceDebit
}

func newPrototypeSourceInput(source, destination []byte) *vmcommon.ContractCallInput {
	txHash := bytes.Repeat([]byte{0x33}, prototypeHashLength)
	return &vmcommon.ContractCallInput{
		RecipientAddr: append([]byte(nil), source...),
		Function:      PrototypeSourceDebitFunction,
		VMInput: vmcommon.VMInput{
			NativeCallOrigin: vmcommon.NativeCallOriginOriginalUserTransaction,
			CallerAddr:       append([]byte(nil), source...),
			Arguments: [][]byte{
				append([]byte(nil), destination...),
				[]byte("TOKEN-abcdef"),
				{0x02},
			},
			CallValue:      big.NewInt(0),
			CallType:       vmData.DirectCall,
			GasProvided:    150,
			CurrentTxHash:  append([]byte(nil), txHash...),
			OriginalTxHash: append([]byte(nil), txHash...),
			PrevTxHash:     append([]byte(nil), txHash...),
		},
	}
}

func newPrototypeSourceAccount(address []byte, dataHandler vmcommon.AccountDataHandler) *vmcommonMocks.UserAccountStub {
	return &vmcommonMocks.UserAccountStub{
		AddressBytesCalled:       func() []byte { return address },
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler { return dataHandler },
	}
}

func newPrototypeSourceDataHandler(stored map[string][]byte, onSave func()) *trieMock.DataTrieTrackerStub {
	return &trieMock.DataTrieTrackerStub{
		RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
			return append([]byte(nil), stored[string(key)]...), 0, nil
		},
		SaveKeyValueCalled: func(key, value []byte) error {
			if onSave != nil {
				onSave()
			}
			stored[string(key)] = append([]byte(nil), value...)
			return nil
		},
	}
}
