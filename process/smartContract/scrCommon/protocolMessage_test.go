package scrCommon

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
)

func TestValidateProtocolMessageAdmission(t *testing.T) {
	t.Parallel()

	sourceAddress := []byte("source")
	destinationAddress := []byte("destination")
	coordinator := &processMock.ShardCoordinatorStub{
		SelfIdCalled: func() uint32 { return 1 },
		ComputeIdCalled: func(address []byte) uint32 {
			if bytes.Equal(address, destinationAddress) {
				return 1
			}
			return 0
		},
	}
	disabled := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	enabled := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.DRWAEnforcementFlag)
	validCallData := createPrototypeEnvelopeCallData(t)
	valid := func() *smartContractResult.SmartContractResult {
		return &smartContractResult.SmartContractResult{
			SndAddr:             sourceAddress,
			RcvAddr:             destinationAddress,
			Data:                validCallData,
			ProtocolMessageKind: vmData.ProtocolMessageKindDRWA,
		}
	}

	t.Run("ordinary kind preserves baseline admission", func(t *testing.T) {
		scr := valid()
		scr.ProtocolMessageKind = vmData.ProtocolMessageKindNone
		require.NoError(t, ValidateProtocolMessageAdmission(scr, disabled, coordinator))
	})

	t.Run("unknown kind rejects", func(t *testing.T) {
		scr := valid()
		scr.ProtocolMessageKind = vmData.ProtocolMessageKind(2)
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrUnknownProtocolMessageKind)
	})

	t.Run("known kind rejects before activation", func(t *testing.T) {
		require.ErrorIs(t, ValidateProtocolMessageAdmission(valid(), disabled, coordinator), process.ErrProtocolMessageBeforeActivation)
	})

	t.Run("wrong function rejects after activation", func(t *testing.T) {
		scr := valid()
		scr.Data = []byte("ESDTTransfer@00")
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrInvalidProtocolMessageFunction)
	})

	t.Run("function prefix is not sufficient", func(t *testing.T) {
		scr := valid()
		scr.Data = []byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope + "Suffix@00")
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrInvalidProtocolMessageFunction)
	})

	t.Run("exact function without envelope rejects", func(t *testing.T) {
		scr := valid()
		scr.Data = []byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope)
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrInvalidProtocolMessageEnvelope)
	})

	t.Run("empty envelope argument rejects", func(t *testing.T) {
		scr := valid()
		scr.Data = []byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope + "@")
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrInvalidProtocolMessageEnvelope)
	})

	t.Run("odd-length hex rejects", func(t *testing.T) {
		scr := valid()
		scr.Data = []byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope + "@0")
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrInvalidProtocolMessageEnvelope)
	})

	t.Run("non-hex argument rejects", func(t *testing.T) {
		scr := valid()
		scr.Data = []byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope + "@zz")
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrInvalidProtocolMessageEnvelope)
	})

	t.Run("uppercase hex rejects as alternate prototype spelling", func(t *testing.T) {
		scr := valid()
		separatorIndex := bytes.IndexByte(scr.Data, '@')
		scr.Data = append(append([]byte(nil), scr.Data[:separatorIndex+1]...), bytes.ToUpper(scr.Data[separatorIndex+1:])...)
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrInvalidProtocolMessageEnvelope)
	})

	t.Run("extra argument rejects", func(t *testing.T) {
		scr := valid()
		scr.Data = append(append([]byte(nil), scr.Data...), []byte("@00")...)
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrInvalidProtocolMessageEnvelope)
	})

	t.Run("oversized envelope rejects before decode", func(t *testing.T) {
		scr := valid()
		scr.Data = append(
			[]byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope+"@"),
			bytes.Repeat([]byte{'0'}, 2*drwaprototype.PrototypeValueEnvelopeMaximumLength()+2)...,
		)
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrInvalidProtocolMessageEnvelope)
	})

	t.Run("invalid decoded envelope rejects", func(t *testing.T) {
		scr := valid()
		scr.Data = []byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope + "@00")
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrInvalidProtocolMessageEnvelope)
	})

	t.Run("same-shard source rejects", func(t *testing.T) {
		scr := valid()
		scr.SndAddr = destinationAddress
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrInvalidProtocolMessageRoute)
	})

	t.Run("relayer metadata rejects", func(t *testing.T) {
		for _, mutate := range []func(*smartContractResult.SmartContractResult){
			func(scr *smartContractResult.SmartContractResult) {
				scr.RelayerAddr = bytes.Repeat([]byte{0x44}, 32)
			},
			func(scr *smartContractResult.SmartContractResult) {
				scr.RelayedValue = big.NewInt(0)
			},
		} {
			scr := valid()
			mutate(scr)
			require.ErrorIs(
				t, ValidateProtocolMessageAdmission(scr, enabled, coordinator),
				process.ErrInvalidProtocolMessageRoute,
			)
		}
	})

	t.Run("non-local destination rejects", func(t *testing.T) {
		scr := valid()
		scr.RcvAddr = sourceAddress
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrInvalidProtocolMessageRoute)
	})

	t.Run("exact active cross-shard carrier reaches later validation", func(t *testing.T) {
		require.NoError(t, ValidateProtocolMessageAdmission(valid(), enabled, coordinator))
	})

	t.Run("exact settlement and refund carriers reach source validation", func(t *testing.T) {
		for _, refund := range []bool{false, true} {
			scr := valid()
			scr.Data = createPrototypeResultCallData(t, refund)
			require.NoError(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator))
		}
	})

	t.Run("malformed settlement carrier rejects before account loading", func(t *testing.T) {
		scr := valid()
		scr.Data = []byte(PrototypeSettlementReceiptFunction + "@00")
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrInvalidProtocolMessageEnvelope)
	})
}

func createPrototypeResultCallData(t *testing.T, refund bool) []byte {
	t.Helper()
	effectID := [32]byte{1}
	contextHash := [32]byte{2}
	destinationIdentity := [32]byte{3}
	function := PrototypeSettlementReceiptFunction
	receipt, err := drwaprototype.BuildSettlementReceipt([32]byte{4}, effectID, contextHash, destinationIdentity)
	require.NoError(t, err)
	payload, err := drwaprototype.EncodeSettlementReceipt(receipt)
	require.NoError(t, err)
	if refund {
		function = PrototypeRefundEnvelopeFunction
		payload, err = drwaprototype.EncodeRefundEnvelope(drwaprototype.RefundEnvelope{
			EffectID:                     effectID,
			ContextHash:                  contextHash,
			DestinationExecutionIdentity: destinationIdentity,
			OriginalTransferPayload:      []byte("ESDTTransfer@544f4b454e2d616263646566@01"),
			RefundTo:                     [32]byte{5},
		})
		require.NoError(t, err)
	}
	return []byte(function + "@" + hex.EncodeToString(payload))
}

func createPrototypeEnvelopeCallData(t *testing.T) []byte {
	t.Helper()

	context := drwaprototype.ValueContext{
		EffectKind:               drwaprototype.ValueEffectKindDirectTransfer,
		RegulatedTokenID:         []byte("TOKEN-abcdef"),
		RegulatedTokenType:       drwaprototype.TokenTypeFungible,
		Quantity:                 []byte{1},
		CEBEpoch:                 7,
		TransferMode:             drwaprototype.TransferModeGatedDirect,
		SettlementExpiry:         1,
		DestinationGateGasLimit:  1,
		SuccessReceiptGasLimit:   1,
		RefundGenerationGasLimit: 1,
		SourceCompletionGasLimit: 1,
	}
	encoded, err := drwaprototype.EncodeValueEnvelope(drwaprototype.ValueEnvelope{
		OriginalTransferPayload: []byte("ESDTTransfer@544f4b454e2d616263646566@01"),
		Context:                 context,
	})
	require.NoError(t, err)

	callData := []byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope + "@")
	return append(callData, []byte(hex.EncodeToString(encoded))...)
}
