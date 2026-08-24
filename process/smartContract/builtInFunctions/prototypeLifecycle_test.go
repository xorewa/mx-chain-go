package builtInFunctions

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestPrototypeLifecycleSourceDestinationReceiptCompletion(t *testing.T) {
	sourceAddress := bytes.Repeat([]byte{0x11}, prototypeAddressLength)
	destinationAddress := bytes.Repeat([]byte{0x22}, prototypeAddressLength)
	budgets := drwaprototype.WorkBudgets{DestinationGate: 10, SuccessReceipt: 20, RefundGeneration: 30, SourceCompletion: 40}
	enableEpochs := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.DRWAEnforcementFlag)

	sourceStored := make(map[string][]byte)
	sourceHandler := newPrototypeSourceDataHandler(sourceStored, nil)
	sourceAccount := newPrototypeSourceAccount(sourceAddress, sourceHandler)
	sourceDelegate := &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(
		_, _ vmcommon.UserAccountHandler,
		_ *vmcommon.ContractCallInput,
	) (*vmcommon.VMOutput, error) {
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 49}, nil
	}}
	sourceDebit := newPrototypeSourceDebitForTest(t, sourceDelegate, func(_ []byte) (bool, error) { return true, nil })
	require.NoError(t, sourceDebit.setBlockchainHook(&testscommon.BlockChainHookStub{CurrentRoundCalled: func() uint64 { return 7 }}))
	sourceInput := newPrototypeSourceInput(sourceAddress, destinationAddress)
	sourceOutput, err := sourceDebit.ProcessBuiltinFunction(sourceAccount, sourceAccount, sourceInput)
	require.NoError(t, err)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeForward, sourceOutput.ProtocolExecution.Outcome)
	require.Equal(t, uint64(1), sourceOutput.ProtocolExecution.LocalGasUsed)
	require.Equal(t, uint64(100), sourceOutput.ProtocolExecution.ForwardedGas)
	sourceCarrier := sourceOutput.OutputAccounts[string(destinationAddress)].OutputTransfers[0]
	envelopeBytes := decodePrototypeCarrierPayload(t, sourceCarrier.Data, vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope)
	envelope, err := drwaprototype.DecodeValueEnvelope(envelopeBytes)
	require.NoError(t, err)

	receiverBytes, err := drwaprototype.EncodeReceiverGateRecord(drwaprototype.ReceiverGateRecord{
		Holder:            bytesToPrototypeAddress(destinationAddress),
		CEBEpoch:          9,
		Admitted:          true,
		ValidThroughRound: 100,
	})
	require.NoError(t, err)
	destinationStored := map[string][]byte{
		string(drwaprototype.ReceiverGateStorageKey(envelope.Context.RegulatedTokenID)): receiverBytes,
	}
	destinationAccount := newPrototypeSourceAccount(
		destinationAddress,
		newPrototypeSourceDataHandler(destinationStored, nil),
	)
	destinationCoordinator := &testscommon.ShardsCoordinatorMock{NoShards: 2, CurrentShard: 1, ComputeIdCalled: func(address []byte) uint32 {
		if bytes.Equal(address, sourceAddress) {
			return 0
		}
		return 1
	}}
	destination, err := newPrototypeDestination(prototypeDestinationArgs{
		delegate: &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(
			_, _ vmcommon.UserAccountHandler,
			_ *vmcommon.ContractCallInput,
		) (*vmcommon.VMOutput, error) {
			return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 5}, nil
		}},
		classifier:          func(_ []byte) (bool, error) { return true, nil },
		enableEpochsHandler: enableEpochs,
		shardCoordinator:    destinationCoordinator,
		networkDomain:       [32]byte{1},
		cebEpoch:            9,
		retainedWorkBudgetsProvider: func(_ [32]byte) (drwaprototype.WorkBudgets, uint64, error) {
			return budgets, 100, nil
		},
	})
	require.NoError(t, err)
	require.NoError(t, destination.setBlockchainHook(&testscommon.BlockChainHookStub{CurrentRoundCalled: func() uint64 { return 8 }}))
	destinationIdentity := bytes.Repeat([]byte{0x44}, prototypeHashLength)
	destinationInput := &vmcommon.ContractCallInput{
		RecipientAddr: destinationAddress,
		Function:      vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope,
		VMInput: vmcommon.VMInput{
			NativeCallOrigin: vmcommon.NativeCallOriginDRWAProtocolMessage,
			CallerAddr:       sourceAddress,
			Arguments:        [][]byte{envelopeBytes},
			CallValue:        big.NewInt(0),
			CallType:         vmData.DirectCall,
			GasProvided:      sourceCarrier.GasLimit,
			CurrentTxHash:    destinationIdentity,
			OriginalTxHash:   sourceInput.OriginalTxHash,
			PrevTxHash:       sourceInput.OriginalTxHash,
		},
	}
	destinationOutput, err := destination.ProcessBuiltinFunction(nil, destinationAccount, destinationInput)
	require.NoError(t, err)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeSettlementReceipt, destinationOutput.ProtocolExecution.Outcome)
	require.Equal(t, uint64(25), destinationOutput.ProtocolExecution.LocalGasUsed)
	require.Equal(t, uint64(75), destinationOutput.ProtocolExecution.ForwardedGas)
	receiptCarrier := destinationOutput.OutputAccounts[string(sourceAddress)].OutputTransfers[0]
	receiptBytes := decodePrototypeCarrierPayload(t, receiptCarrier.Data, PrototypeSettlementReceiptFunction)

	sourceCoordinator := &testscommon.ShardsCoordinatorMock{NoShards: 2, CurrentShard: 0, ComputeIdCalled: func(address []byte) uint32 {
		if bytes.Equal(address, destinationAddress) {
			return 1
		}
		return 0
	}}
	completion, err := newPrototypeSourceCompletion(prototypeSourceCompletionArgs{
		delegate:            sourceDelegate,
		enableEpochsHandler: enableEpochs,
		shardCoordinator:    sourceCoordinator,
		networkDomain:       [32]byte{1},
		retainedWorkBudgetsProvider: func(_ [32]byte) (drwaprototype.WorkBudgets, uint64, error) {
			return budgets, 100, nil
		},
	})
	require.NoError(t, err)
	completionInput := &vmcommon.ContractCallInput{
		RecipientAddr: sourceAddress,
		Function:      PrototypeSettlementReceiptFunction,
		VMInput: vmcommon.VMInput{
			NativeCallOrigin: vmcommon.NativeCallOriginDRWAProtocolMessage,
			CallerAddr:       destinationAddress,
			Arguments:        [][]byte{receiptBytes},
			CallValue:        big.NewInt(0),
			CallType:         vmData.DirectCall,
			GasProvided:      receiptCarrier.GasLimit,
			CurrentTxHash:    bytes.Repeat([]byte{0x55}, prototypeHashLength),
			OriginalTxHash:   sourceInput.OriginalTxHash,
			PrevTxHash:       destinationIdentity,
		},
	}
	completionOutput, err := completion.ProcessBuiltinFunction(nil, sourceAccount, completionInput)
	require.NoError(t, err)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeSourceSettled, completionOutput.ProtocolExecution.Outcome)
	require.Equal(t, uint64(40), completionOutput.ProtocolExecution.LocalGasUsed)
	require.Equal(t, uint64(35), completionOutput.GasRemaining)
	require.Equal(t, sourceAddress, completionOutput.ProtocolExecution.GasRefundRecipient)
	_, err = drwaprototype.LoadOpenEffect(sourceHandler, envelope.Context.EffectID)
	require.ErrorIs(t, err, drwaprototype.ErrOpenEffectNotFound)
}

func TestPrototypeLifecycleDestinationDenialRefundCompletion(t *testing.T) {
	destination, destinationInput, destinationAccount, artifacts := newPrototypeDestinationFixture(t, false)
	destinationOutput, err := destination.ProcessBuiltinFunction(nil, destinationAccount, destinationInput)
	require.NoError(t, err)
	require.Equal(t, vmcommon.UserError, destinationOutput.ReturnCode)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeRefundEnvelope, destinationOutput.ProtocolExecution.Outcome)
	sourceAddress := artifacts.Envelope.Context.SourceHolder[:]
	destinationAddress := artifacts.Envelope.Context.DestinationHolder[:]
	refundCarrier := destinationOutput.OutputAccounts[string(sourceAddress)].OutputTransfers[0]
	refundBytes := decodePrototypeCarrierPayload(t, refundCarrier.Data, PrototypeRefundEnvelopeFunction)

	effectBytes, err := drwaprototype.EncodeOpenEffect(artifacts.OpenEffect)
	require.NoError(t, err)
	stored := map[string][]byte{
		string(drwaprototype.OpenEffectStorageKey(artifacts.OpenEffect.EffectID)): effectBytes,
	}
	sourceHandler := newPrototypeSourceDataHandler(stored, nil)
	sourceAccount := newPrototypeSourceAccount(sourceAddress, sourceHandler)
	refundApplied := false
	completion, err := newPrototypeSourceCompletion(prototypeSourceCompletionArgs{
		delegate: &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(
			_, actualDestination vmcommon.UserAccountHandler,
			delegateInput *vmcommon.ContractCallInput,
		) (*vmcommon.VMOutput, error) {
			refundApplied = true
			require.Equal(t, sourceAccount, actualDestination)
			require.Equal(t, [][]byte{artifacts.Envelope.Context.RegulatedTokenID, artifacts.Envelope.Context.Quantity}, delegateInput.Arguments)
			require.True(t, delegateInput.ReturnCallAfterError)
			return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
		}},
		enableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.DRWAEnforcementFlag),
		shardCoordinator: &testscommon.ShardsCoordinatorMock{NoShards: 2, CurrentShard: 0, ComputeIdCalled: func(address []byte) uint32 {
			if bytes.Equal(address, destinationAddress) {
				return 1
			}
			return 0
		}},
		networkDomain: [32]byte{1},
		retainedWorkBudgetsProvider: func(_ [32]byte) (drwaprototype.WorkBudgets, uint64, error) {
			return drwaprototype.WorkBudgets{DestinationGate: 10, SuccessReceipt: 20, RefundGeneration: 30, SourceCompletion: 40}, 100, nil
		},
	})
	require.NoError(t, err)
	completionOutput, err := completion.ProcessBuiltinFunction(nil, sourceAccount, &vmcommon.ContractCallInput{
		RecipientAddr: sourceAddress,
		Function:      PrototypeRefundEnvelopeFunction,
		VMInput: vmcommon.VMInput{
			NativeCallOrigin: vmcommon.NativeCallOriginDRWAProtocolMessage,
			CallerAddr:       destinationAddress,
			Arguments:        [][]byte{refundBytes},
			CallValue:        big.NewInt(0),
			CallType:         vmData.DirectCall,
			GasProvided:      refundCarrier.GasLimit,
			CurrentTxHash:    bytes.Repeat([]byte{0x66}, prototypeHashLength),
			OriginalTxHash:   artifacts.OpenEffect.OriginExecutionIdentity[:],
			PrevTxHash:       destinationInput.CurrentTxHash,
		},
	})
	require.NoError(t, err)
	require.True(t, refundApplied)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeSourceRefunded, completionOutput.ProtocolExecution.Outcome)
	require.Equal(t, uint64(20), completionOutput.GasRemaining)
	require.Equal(t, sourceAddress, completionOutput.ProtocolExecution.GasRefundRecipient)
	_, err = drwaprototype.LoadOpenEffect(sourceHandler, artifacts.OpenEffect.EffectID)
	require.ErrorIs(t, err, drwaprototype.ErrOpenEffectNotFound)
}

func decodePrototypeCarrierPayload(t *testing.T, data []byte, function string) []byte {
	t.Helper()
	prefix := []byte(function + "@")
	require.True(t, bytes.HasPrefix(data, prefix))
	payload, err := hex.DecodeString(string(data[len(prefix):]))
	require.NoError(t, err)
	return payload
}
