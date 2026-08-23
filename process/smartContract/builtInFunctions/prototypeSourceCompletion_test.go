package builtInFunctions

import (
	"bytes"
	"errors"
	"fmt"
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

func TestPrototypeSourceCompletionReceiptRemovesExactEffect(t *testing.T) {
	completion, input, account, stored, artifacts := newPrototypeSourceCompletionFixture(t, false)

	output, err := completion.ProcessBuiltinFunction(nil, account, input)
	require.NoError(t, err)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeSourceSettled, output.ProtocolExecution.Outcome)
	require.Equal(t, uint64(40), output.ProtocolExecution.LocalGasUsed)
	require.Equal(t, uint64(30), output.GasRemaining)
	require.Empty(t, stored[string(drwaprototype.OpenEffectStorageKey(artifacts.OpenEffect.EffectID))])
}

func TestPrototypeSourceCompletionReceiptReturnsBoundedUnusedDestinationGas(t *testing.T) {
	completion, input, account, stored, artifacts := newPrototypeSourceCompletionFixture(t, false)
	input.GasProvided = 75

	output, err := completion.ProcessBuiltinFunction(nil, account, input)
	require.NoError(t, err)
	require.Equal(t, uint64(40), output.ProtocolExecution.LocalGasUsed)
	require.Equal(t, uint64(35), output.GasRemaining)
	require.Empty(t, stored[string(drwaprototype.OpenEffectStorageKey(artifacts.OpenEffect.EffectID))])
}

func TestPrototypeSourceCompletionReceiptRejectsGasOutsideRuledBounds(t *testing.T) {
	for _, gasProvided := range []uint64{69, 81} {
		t.Run(fmt.Sprintf("gas_%d", gasProvided), func(t *testing.T) {
			completion, input, account, stored, artifacts := newPrototypeSourceCompletionFixture(t, false)
			input.GasProvided = gasProvided

			output, err := completion.ProcessBuiltinFunction(nil, account, input)
			require.Nil(t, output)
			require.ErrorIs(t, err, ErrPrototypeSourceCompletionDenied)
			require.NotEmpty(t, stored[string(drwaprototype.OpenEffectStorageKey(artifacts.OpenEffect.EffectID))])
		})
	}
}

func TestPrototypeSourceCompletionRefundUsesBaselineReturnThenRemovesEffect(t *testing.T) {
	completion, input, account, stored, artifacts := newPrototypeSourceCompletionFixture(t, true)
	delegateCalled := false
	completion.delegate = &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(
		acntSnd, acntDst vmcommon.UserAccountHandler,
		delegateInput *vmcommon.ContractCallInput,
	) (*vmcommon.VMOutput, error) {
		delegateCalled = true
		require.Nil(t, acntSnd)
		require.Equal(t, account, acntDst)
		require.Equal(t, coreESDTTransfer, delegateInput.Function)
		require.Equal(t, [][]byte{[]byte("TOKEN-abcdef"), {2}}, delegateInput.Arguments)
		require.True(t, delegateInput.ReturnCallAfterError)
		return &vmcommon.VMOutput{
			ReturnCode: vmcommon.Ok,
			Logs:       []*vmcommon.LogEntry{{Identifier: []byte("ESDTTransfer")}},
		}, nil
	}}

	output, err := completion.ProcessBuiltinFunction(nil, account, input)
	require.NoError(t, err)
	require.True(t, delegateCalled)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeSourceRefunded, output.ProtocolExecution.Outcome)
	require.Equal(t, uint64(40), output.ProtocolExecution.LocalGasUsed)
	require.Equal(t, uint64(20), output.GasRemaining)
	require.Len(t, output.Logs, 1)
	require.Equal(t, []byte("ESDTTransfer"), output.Logs[0].Identifier)
	require.Empty(t, stored[string(drwaprototype.OpenEffectStorageKey(artifacts.OpenEffect.EffectID))])
}

func TestPrototypeSourceCompletionRejectsMismatchBeforeMutation(t *testing.T) {
	completion, input, account, stored, artifacts := newPrototypeSourceCompletionFixture(t, false)
	receipt, err := drwaprototype.DecodeSettlementReceipt(input.Arguments[0])
	require.NoError(t, err)
	receipt.ContextHash[0] ^= 0xff
	input.Arguments[0], err = drwaprototype.EncodeSettlementReceipt(*receipt)
	require.NoError(t, err)

	output, err := completion.ProcessBuiltinFunction(nil, account, input)
	require.Nil(t, output)
	require.ErrorIs(t, err, ErrPrototypeSourceCompletionDenied)
	require.NotEmpty(t, stored[string(drwaprototype.OpenEffectStorageKey(artifacts.OpenEffect.EffectID))])
}

func TestPrototypeSourceCompletionRefundFailureDoesNotRemoveEffect(t *testing.T) {
	completion, input, account, stored, artifacts := newPrototypeSourceCompletionFixture(t, true)
	completion.delegate = &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(
		_, _ vmcommon.UserAccountHandler,
		_ *vmcommon.ContractCallInput,
	) (*vmcommon.VMOutput, error) {
		return nil, errors.New("injected refund failure")
	}}

	output, err := completion.ProcessBuiltinFunction(nil, account, input)
	require.Nil(t, output)
	require.ErrorIs(t, err, ErrPrototypeSourceCompletionMutation)
	require.NotEmpty(t, stored[string(drwaprototype.OpenEffectStorageKey(artifacts.OpenEffect.EffectID))])
}

func TestPrototypeSourceCompletionRejectsRefundDelegateOutputDrift(t *testing.T) {
	completion, input, account, stored, artifacts := newPrototypeSourceCompletionFixture(t, true)
	completion.delegate = &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(
		_, _ vmcommon.UserAccountHandler,
		_ *vmcommon.ContractCallInput,
	) (*vmcommon.VMOutput, error) {
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 1}, nil
	}}

	output, err := completion.ProcessBuiltinFunction(nil, account, input)
	require.Nil(t, output)
	require.ErrorIs(t, err, ErrPrototypeSourceCompletionMutation)
	require.NotEmpty(t, stored[string(drwaprototype.OpenEffectStorageKey(artifacts.OpenEffect.EffectID))])
}

const coreESDTTransfer = "ESDTTransfer"

func newPrototypeSourceCompletionFixture(
	t *testing.T,
	refund bool,
) (*prototypeSourceCompletion, *vmcommon.ContractCallInput, vmcommon.UserAccountHandler, map[string][]byte, *drwaprototype.DirectValueArtifacts) {
	t.Helper()
	source := bytesToPrototypeAddress(bytes.Repeat([]byte{0x11}, prototypeAddressLength))
	destination := bytesToPrototypeAddress(bytes.Repeat([]byte{0x22}, prototypeAddressLength))
	originIdentity := [32]byte{3}
	destinationIdentity := [32]byte{4}
	budgets := drwaprototype.WorkBudgets{DestinationGate: 10, SuccessReceipt: 20, RefundGeneration: 30, SourceCompletion: 40}
	artifacts, err := drwaprototype.BuildDirectValueArtifacts([32]byte{1}, originIdentity, drwaprototype.DirectValueIntent{
		RegulatedTokenID:         []byte("TOKEN-abcdef"),
		Quantity:                 []byte{2},
		SourceHolder:             source,
		DestinationHolder:        destination,
		CEBEpoch:                 9,
		SettlementExpiry:         100,
		GasScheduleIdentity:      [32]byte{2},
		DestinationGateGasLimit:  budgets.DestinationGate,
		SuccessReceiptGasLimit:   budgets.SuccessReceipt,
		RefundGenerationGasLimit: budgets.RefundGeneration,
		SourceCompletionGasLimit: budgets.SourceCompletion,
	})
	require.NoError(t, err)
	effectBytes, err := drwaprototype.EncodeOpenEffect(artifacts.OpenEffect)
	require.NoError(t, err)
	stored := map[string][]byte{string(drwaprototype.OpenEffectStorageKey(artifacts.OpenEffect.EffectID)): effectBytes}
	dataHandler := newPrototypeSourceDataHandler(stored, nil)
	account := newPrototypeSourceAccount(source[:], dataHandler)
	coordinator := &testscommon.ShardsCoordinatorMock{NoShards: 2, CurrentShard: 0, ComputeIdCalled: func(address []byte) uint32 {
		if bytes.Equal(address, destination[:]) {
			return 1
		}
		return 0
	}}
	completion, err := newPrototypeSourceCompletion(prototypeSourceCompletionArgs{
		delegate:            &processMock.BuiltInFunctionStub{},
		enableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.DRWAEnforcementFlag),
		shardCoordinator:    coordinator,
		networkDomain:       [32]byte{1},
		retainedWorkBudgetsProvider: func(identity [32]byte) (drwaprototype.WorkBudgets, uint64, error) {
			require.Equal(t, [32]byte{2}, identity)
			return budgets, 100, nil
		},
	})
	require.NoError(t, err)

	function := PrototypeSettlementReceiptFunction
	gasProvided := uint64(70)
	receipt, err := drwaprototype.BuildSettlementReceipt(
		[32]byte{1}, artifacts.OpenEffect.EffectID, artifacts.ContextHash, destinationIdentity,
	)
	require.NoError(t, err)
	payload, err := drwaprototype.EncodeSettlementReceipt(receipt)
	require.NoError(t, err)
	if refund {
		function = PrototypeRefundEnvelopeFunction
		gasProvided = 60
		payload, err = drwaprototype.EncodeRefundEnvelope(drwaprototype.RefundEnvelope{
			EffectID:                     artifacts.OpenEffect.EffectID,
			ContextHash:                  artifacts.ContextHash,
			DestinationExecutionIdentity: destinationIdentity,
			OriginalTransferPayload:      artifacts.Envelope.OriginalTransferPayload,
			RefundTo:                     source,
		})
		require.NoError(t, err)
	}
	input := &vmcommon.ContractCallInput{
		RecipientAddr: source[:],
		Function:      function,
		VMInput: vmcommon.VMInput{
			NativeCallOrigin: vmcommon.NativeCallOriginDRWAProtocolMessage,
			CallerAddr:       destination[:],
			Arguments:        [][]byte{payload},
			CallValue:        big.NewInt(0),
			CallType:         vmData.DirectCall,
			GasProvided:      gasProvided,
			CurrentTxHash:    bytes.Repeat([]byte{5}, prototypeHashLength),
			OriginalTxHash:   originIdentity[:],
			PrevTxHash:       destinationIdentity[:],
		},
	}
	return completion, input, account, stored, artifacts
}
