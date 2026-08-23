package builtInFunctions

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/multiversx/mx-chain-go/testscommon/vmcommonMocks"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestPrototypeDestinationSuccessProducesOneReceiptWithExactGas(t *testing.T) {
	destination, input, account, artifacts := newPrototypeDestinationFixture(t, true)
	output, err := destination.ProcessBuiltinFunction(nil, account, input)
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, output.ReturnCode)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeSettlementReceipt, output.ProtocolExecution.Outcome)
	require.Equal(t, uint64(25), output.ProtocolExecution.LocalGasUsed)
	require.Equal(t, uint64(75), output.ProtocolExecution.ForwardedGas)
	require.Zero(t, output.GasRemaining)
	require.Len(t, output.OutputAccounts, 1)
	outAccount := output.OutputAccounts[string(artifacts.Envelope.Context.SourceHolder[:])]
	require.NotNil(t, outAccount)
	require.Len(t, outAccount.OutputTransfers, 1)
	carrier := outAccount.OutputTransfers[0]
	require.Equal(t, uint64(75), carrier.GasLimit)
	require.Equal(t, vmData.ProtocolMessageKindDRWA, carrier.ProtocolMessageKind)
	require.Equal(t, vmData.DirectCall, carrier.CallType)
	prefix := []byte(PrototypeSettlementReceiptFunction + "@")
	require.True(t, bytes.HasPrefix(carrier.Data, prefix))
}

func TestPrototypeDestinationReceiverDenialProducesTypedSingleRefund(t *testing.T) {
	destination, input, account, artifacts := newPrototypeDestinationFixture(t, false)
	output, err := destination.ProcessBuiltinFunction(nil, account, input)
	require.NoError(t, err)
	require.Equal(t, vmcommon.UserError, output.ReturnCode)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeRefundEnvelope, output.ProtocolExecution.Outcome)
	require.Equal(t, uint64(40), output.ProtocolExecution.LocalGasUsed)
	require.Equal(t, uint64(60), output.ProtocolExecution.ForwardedGas)
	carrier := output.OutputAccounts[string(artifacts.Envelope.Context.SourceHolder[:])].OutputTransfers[0]
	encoded := carrier.Data[len(PrototypeRefundEnvelopeFunction)+1:]
	refundBytes := make([]byte, hex.DecodedLen(len(encoded)))
	_, err = hex.Decode(refundBytes, encoded)
	require.NoError(t, err)
	refund, err := drwaprototype.DecodeRefundEnvelope(refundBytes)
	require.NoError(t, err)
	require.Equal(t, artifacts.Envelope.Context.EffectID, refund.EffectID)
	require.Equal(t, artifacts.ContextHash, refund.ContextHash)
	require.Equal(t, artifacts.Envelope.Context.SourceHolder, refund.RefundTo)
}

func TestPrototypeDestinationPostCreditFailureCarriesRefundForProcessorRollback(t *testing.T) {
	destination, input, account, _ := newPrototypeDestinationFixture(t, true)
	destination.delegate = &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		return nil, errors.New("injected baseline credit failure")
	}}
	output, err := destination.ProcessBuiltinFunction(nil, account, input)
	require.NoError(t, err)
	require.Equal(t, vmcommon.UserError, output.ReturnCode)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeRefundEnvelope, output.ProtocolExecution.Outcome)
	require.Contains(t, output.ReturnMessage, ErrPrototypeDestinationMutation.Error())
}

func TestPrototypeDestinationUntrustedIngressCannotRequestRefund(t *testing.T) {
	destination, input, account, _ := newPrototypeDestinationFixture(t, true)
	input.NativeCallOrigin = vmcommon.NativeCallOriginOriginalUserTransaction
	output, err := destination.ProcessBuiltinFunction(nil, account, input)
	require.Nil(t, output)
	require.ErrorIs(t, err, ErrPrototypeDestinationDenied)
}

func newPrototypeDestinationFixture(
	t *testing.T,
	admitted bool,
) (*prototypeDestination, *vmcommon.ContractCallInput, vmcommon.UserAccountHandler, *drwaprototype.DirectValueArtifacts) {
	t.Helper()
	source := [32]byte{}
	destinationHolder := [32]byte{}
	for index := range source {
		source[index] = 0x11
		destinationHolder[index] = 0x22
	}
	networkDomain := [32]byte{1}
	originIdentity := [32]byte{3}
	gasIdentity := [32]byte{2}
	budgets := drwaprototype.WorkBudgets{DestinationGate: 10, SuccessReceipt: 20, RefundGeneration: 30, SourceCompletion: 40}
	artifacts, err := drwaprototype.BuildDirectValueArtifacts(networkDomain, originIdentity, drwaprototype.DirectValueIntent{
		RegulatedTokenID:         []byte("TOKEN-abcdef"),
		Quantity:                 []byte{2},
		SourceHolder:             source,
		DestinationHolder:        destinationHolder,
		CEBEpoch:                 9,
		SettlementExpiry:         100,
		GasScheduleIdentity:      gasIdentity,
		DestinationGateGasLimit:  budgets.DestinationGate,
		SuccessReceiptGasLimit:   budgets.SuccessReceipt,
		RefundGenerationGasLimit: budgets.RefundGeneration,
		SourceCompletionGasLimit: budgets.SourceCompletion,
	})
	require.NoError(t, err)
	envelopeBytes, err := drwaprototype.EncodeValueEnvelope(artifacts.Envelope)
	require.NoError(t, err)
	receiverBytes, err := drwaprototype.EncodeReceiverGateRecord(drwaprototype.ReceiverGateRecord{
		Holder:            destinationHolder,
		CEBEpoch:          9,
		Admitted:          admitted,
		ValidThroughRound: 100,
	})
	require.NoError(t, err)
	dataHandler := &trieMock.DataTrieTrackerStub{RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
		if bytes.Equal(key, drwaprototype.ReceiverGateStorageKey(artifacts.Envelope.Context.RegulatedTokenID)) {
			return receiverBytes, 0, nil
		}
		return nil, 0, nil
	}}
	account := &vmcommonMocks.UserAccountStub{
		AddressBytesCalled:       func() []byte { return destinationHolder[:] },
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler { return dataHandler },
	}
	delegate := &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(acntSnd, acntDst vmcommon.UserAccountHandler, delegateInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		require.Nil(t, acntSnd)
		require.Equal(t, account, acntDst)
		require.Equal(t, uint64(10), delegateInput.GasProvided)
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 5}, nil
	}}
	coordinator := &testscommon.ShardsCoordinatorMock{NoShards: 2, CurrentShard: 1, ComputeIdCalled: func(address []byte) uint32 {
		if bytes.Equal(address, source[:]) {
			return 0
		}
		return 1
	}}
	destination, err := newPrototypeDestination(prototypeDestinationArgs{
		delegate:            delegate,
		classifier:          func(_ []byte) (bool, error) { return true, nil },
		enableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.DRWAEnforcementFlag),
		shardCoordinator:    coordinator,
		networkDomain:       networkDomain,
		cebEpoch:            9,
		retainedWorkBudgetsProvider: func(identity [32]byte) (drwaprototype.WorkBudgets, uint64, error) {
			require.Equal(t, gasIdentity, identity)
			return budgets, 100, nil
		},
	})
	require.NoError(t, err)
	require.NoError(t, destination.setBlockchainHook(&testscommon.BlockChainHookStub{CurrentRoundCalled: func() uint64 { return 7 }}))
	executionIdentity := bytes.Repeat([]byte{4}, 32)
	input := &vmcommon.ContractCallInput{
		RecipientAddr: destinationHolder[:],
		Function:      vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope,
		VMInput: vmcommon.VMInput{
			NativeCallOrigin: vmcommon.NativeCallOriginDRWAProtocolMessage,
			CallerAddr:       source[:],
			Arguments:        [][]byte{envelopeBytes},
			CallValue:        big.NewInt(0),
			CallType:         vmData.DirectCall,
			GasProvided:      100,
			CurrentTxHash:    executionIdentity,
			OriginalTxHash:   originIdentity[:],
			PrevTxHash:       originIdentity[:],
		},
	}

	return destination, input, account, artifacts
}
