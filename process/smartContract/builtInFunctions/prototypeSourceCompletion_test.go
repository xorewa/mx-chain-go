package builtInFunctions

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
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
	require.Equal(t, input.RecipientAddr, output.ProtocolExecution.GasRefundRecipient)
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
	require.Equal(t, input.RecipientAddr, output.ProtocolExecution.GasRefundRecipient)
	require.Len(t, output.Logs, 1)
	require.Equal(t, []byte("ESDTTransfer"), output.Logs[0].Identifier)
	require.Empty(t, stored[string(drwaprototype.OpenEffectStorageKey(artifacts.OpenEffect.EffectID))])
}

func TestBuildPrototypeCompletionOutputRefundRecipientContract(t *testing.T) {
	recipient := bytes.Repeat([]byte{0x44}, prototypeAddressLength)
	output := buildPrototypeCompletionOutput(
		vmcommon.ProtocolExecutionOutcomeSourceSettled,
		40,
		30,
		recipient,
	)
	require.Equal(t, recipient, output.ProtocolExecution.GasRefundRecipient)

	recipient[0] ^= 0xff
	require.NotEqual(t, recipient, output.ProtocolExecution.GasRefundRecipient)

	zeroRemainder := buildPrototypeCompletionOutput(
		vmcommon.ProtocolExecutionOutcomeSourceSettled,
		40,
		0,
		bytes.Repeat([]byte{0x55}, prototypeAddressLength),
	)
	require.Empty(t, zeroRemainder.ProtocolExecution.GasRefundRecipient)
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

func TestPrototypeSourceCompletionRejectsWrongShardAndLoadedAccountBeforeMutation(t *testing.T) {
	t.Run("recipient is not local to source shard", func(t *testing.T) {
		completion, input, account, stored, artifacts := newPrototypeSourceCompletionFixture(t, false)
		completion.shardCoordinator = &testscommon.ShardsCoordinatorMock{
			NoShards:     2,
			CurrentShard: 0,
			ComputeIdCalled: func(_ []byte) uint32 {
				return 1
			},
		}

		output, err := completion.ProcessBuiltinFunction(nil, account, input)
		require.Nil(t, output)
		require.ErrorIs(t, err, ErrPrototypeSourceCompletionDenied)
		require.NotEmpty(t, stored[string(drwaprototype.OpenEffectStorageKey(artifacts.OpenEffect.EffectID))])
	})

	t.Run("loaded account differs from recipient", func(t *testing.T) {
		completion, input, account, stored, artifacts := newPrototypeSourceCompletionFixture(t, false)
		wrongAccount := newPrototypeSourceAccount(
			bytes.Repeat([]byte{0x33}, prototypeAddressLength),
			account.AccountDataHandler(),
		)

		output, err := completion.ProcessBuiltinFunction(nil, wrongAccount, input)
		require.Nil(t, output)
		require.ErrorIs(t, err, ErrPrototypeSourceCompletionDenied)
		require.NotEmpty(t, stored[string(drwaprototype.OpenEffectStorageKey(artifacts.OpenEffect.EffectID))])
	})
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

func TestPrototypeSourceCompletionRefundDelegateGasMatchesFeatureProfile(t *testing.T) {
	tests := []struct {
		name                 string
		flagEnabled          bool
		delegateGasRemaining uint64
		wantSuccess          bool
	}{
		{name: "disabled accepts zero", delegateGasRemaining: 0, wantSuccess: true},
		{name: "enabled accepts exact source completion", flagEnabled: true, delegateGasRemaining: 40, wantSuccess: true},
		{name: "disabled rejects full remainder", delegateGasRemaining: 40},
		{name: "enabled rejects zero", flagEnabled: true, delegateGasRemaining: 0},
		{name: "enabled rejects partial remainder", flagEnabled: true, delegateGasRemaining: 1},
		{name: "enabled rejects excessive remainder", flagEnabled: true, delegateGasRemaining: 41},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			completion, input, account, stored, artifacts := newPrototypeSourceCompletionFixture(t, true)
			flags := []core.EnableEpochFlag{common.DRWAEnforcementFlag}
			if test.flagEnabled {
				flags = append(flags, common.EGLDInESDTMultiTransferFlag)
			}
			completion.enableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(flags...)
			completion.delegate = &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(
				_, _ vmcommon.UserAccountHandler,
				_ *vmcommon.ContractCallInput,
			) (*vmcommon.VMOutput, error) {
				return &vmcommon.VMOutput{
					ReturnCode:   vmcommon.Ok,
					GasRemaining: test.delegateGasRemaining,
				}, nil
			}}

			output, err := completion.ProcessBuiltinFunction(nil, account, input)
			storedEffect := stored[string(drwaprototype.OpenEffectStorageKey(artifacts.OpenEffect.EffectID))]
			if test.wantSuccess {
				require.NoError(t, err)
				require.Equal(t, vmcommon.ProtocolExecutionOutcomeSourceRefunded, output.ProtocolExecution.Outcome)
				require.Equal(t, uint64(40), output.ProtocolExecution.LocalGasUsed)
				require.Equal(t, uint64(20), output.GasRemaining)
				require.Empty(t, storedEffect)
				return
			}

			require.Nil(t, output)
			require.ErrorIs(t, err, ErrPrototypeSourceCompletionMutation)
			require.NotEmpty(t, storedEffect)
		})
	}
}

func TestIsValidPrototypeRefundDelegateOutputRejectsMalformedShape(t *testing.T) {
	validOutput := func() *vmcommon.VMOutput {
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 40}
	}
	tests := []struct {
		name   string
		mutate func(*vmcommon.VMOutput) *vmcommon.VMOutput
	}{
		{name: "nil output", mutate: func(_ *vmcommon.VMOutput) *vmcommon.VMOutput { return nil }},
		{name: "non-ok return", mutate: func(output *vmcommon.VMOutput) *vmcommon.VMOutput {
			output.ReturnCode = vmcommon.UserError
			return output
		}},
		{name: "nested protocol contract", mutate: func(output *vmcommon.VMOutput) *vmcommon.VMOutput {
			output.ProtocolExecution = &vmcommon.ProtocolExecutionInfo{}
			return output
		}},
		{name: "output account", mutate: func(output *vmcommon.VMOutput) *vmcommon.VMOutput {
			output.OutputAccounts = map[string]*vmcommon.OutputAccount{"unexpected": {}}
			return output
		}},
		{name: "deleted account", mutate: func(output *vmcommon.VMOutput) *vmcommon.VMOutput {
			output.DeletedAccounts = [][]byte{{1}}
			return output
		}},
		{name: "touched account", mutate: func(output *vmcommon.VMOutput) *vmcommon.VMOutput {
			output.TouchedAccounts = [][]byte{{1}}
			return output
		}},
		{name: "return data", mutate: func(output *vmcommon.VMOutput) *vmcommon.VMOutput {
			output.ReturnData = [][]byte{{1}}
			return output
		}},
		{name: "gas refund", mutate: func(output *vmcommon.VMOutput) *vmcommon.VMOutput {
			output.GasRefund = big.NewInt(1)
			return output
		}},
	}

	require.True(t, isValidPrototypeRefundDelegateOutput(validOutput(), 40))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.False(t, isValidPrototypeRefundDelegateOutput(test.mutate(validOutput()), 40))
		})
	}
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
