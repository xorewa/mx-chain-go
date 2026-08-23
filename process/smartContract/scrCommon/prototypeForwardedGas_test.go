package scrCommon

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestPrototypeExecutionGasUsedValidRuledVectors(t *testing.T) {
	t.Run("source local work is one", func(t *testing.T) {
		input, output := prototypeSourceGasFixture(t)
		gasUsed, matched, refund, err := PrototypeExecutionGasUsed(process.BuiltInFunctionCall, false, input, output)
		require.NoError(t, err)
		require.True(t, matched)
		require.False(t, refund)
		require.Equal(t, uint64(1), gasUsed)
	})

	t.Run("destination local work is thirty", func(t *testing.T) {
		input, output := prototypeDestinationGasFixture(t)
		gasUsed, matched, refund, err := PrototypeExecutionGasUsed(process.BuiltInFunctionCall, true, input, output)
		require.NoError(t, err)
		require.True(t, matched)
		require.False(t, refund)
		require.Equal(t, uint64(30), gasUsed)
	})

	t.Run("destination refund is explicit and consumes forty", func(t *testing.T) {
		input, output := prototypeDestinationRefundGasFixture(t)
		gasUsed, matched, refund, err := PrototypeExecutionGasUsed(process.BuiltInFunctionCall, true, input, output)
		require.NoError(t, err)
		require.True(t, matched)
		require.True(t, refund)
		require.Equal(t, uint64(40), gasUsed)
	})
}

func TestPrototypeExecutionGasUsedOrdinaryAndFailedRoutesRetainBaseline(t *testing.T) {
	t.Run("ordinary output", func(t *testing.T) {
		input := &vmcommon.ContractCallInput{Function: "ordinary"}
		output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}
		gasUsed, matched, refund, err := PrototypeExecutionGasUsed(process.BuiltInFunctionCall, false, input, output)
		require.NoError(t, err)
		require.False(t, matched)
		require.False(t, refund)
		require.Zero(t, gasUsed)
	})

	for _, isCrossShard := range []bool{false, true} {
		name := "local"
		if isCrossShard {
			name = "cross shard"
		}
		t.Run("ordinary gas-bearing output remains on baseline path/"+name, func(t *testing.T) {
			input := &vmcommon.ContractCallInput{
				Function: core.BuiltInFunctionESDTTransfer,
				VMInput: vmcommon.VMInput{
					GasProvided: 100,
				},
			}
			output := &vmcommon.VMOutput{
				ReturnCode:   vmcommon.Ok,
				GasRemaining: 20,
				OutputAccounts: map[string]*vmcommon.OutputAccount{
					"ordinary": {
						Address: []byte("ordinary"),
						OutputTransfers: []vmcommon.OutputTransfer{{
							Index:    1,
							Value:    big.NewInt(0),
							GasLimit: 30,
							Data:     []byte("ordinary@00"),
							CallType: vmData.DirectCall,
						}},
					},
				},
			}
			beforeRemaining := output.GasRemaining
			beforeForwarded := output.OutputAccounts["ordinary"].OutputTransfers[0].GasLimit

			gasUsed, matched, refund, err := PrototypeExecutionGasUsed(process.BuiltInFunctionCall, isCrossShard, input, output)
			require.NoError(t, err)
			require.False(t, matched)
			require.False(t, refund)
			require.Zero(t, gasUsed)
			require.Equal(t, beforeRemaining, output.GasRemaining)
			require.Equal(t, beforeForwarded, output.OutputAccounts["ordinary"].OutputTransfers[0].GasLimit)
			require.Nil(t, output.ProtocolExecution)
		})
	}

	t.Run("source denial before output", func(t *testing.T) {
		input, _ := prototypeSourceGasFixture(t)
		output := &vmcommon.VMOutput{ReturnCode: vmcommon.UserError}
		gasUsed, matched, refund, err := PrototypeExecutionGasUsed(process.BuiltInFunctionCall, false, input, output)
		require.NoError(t, err)
		require.False(t, matched)
		require.False(t, refund)
		require.Zero(t, gasUsed)
	})
}

func TestPrototypeExecutionGasUsedRejectsEverySpecialNearMiss(t *testing.T) {
	tests := []struct {
		name         string
		fixture      func(t *testing.T) (*vmcommon.ContractCallInput, *vmcommon.VMOutput)
		txType       process.TransactionType
		isCrossShard bool
		mutate       func(input *vmcommon.ContractCallInput, output *vmcommon.VMOutput)
	}{
		{
			name: "missing execution contract", fixture: prototypeSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				output.ProtocolExecution = nil
			},
		},
		{
			name: "declared local gas mismatch", fixture: prototypeSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				output.ProtocolExecution.LocalGasUsed++
			},
		},
		{
			name: "protocol output from unrelated function", fixture: prototypeSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(input *vmcommon.ContractCallInput, _ *vmcommon.VMOutput) { input.Function = "ordinary" },
		},
		{
			name: "source wrong origin", fixture: prototypeSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(input *vmcommon.ContractCallInput, _ *vmcommon.VMOutput) {
				input.NativeCallOrigin = vmcommon.NativeCallOriginUnknown
			},
		},
		{
			name: "source reported cross shard", fixture: prototypeSourceGasFixture,
			txType: process.BuiltInFunctionCall, isCrossShard: true,
		},
		{
			name: "unexpected transaction type", fixture: prototypeSourceGasFixture,
			txType: process.SCInvoking,
		},
		{
			name: "extra output account", fixture: prototypeSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				output.OutputAccounts["extra"] = &vmcommon.OutputAccount{Address: []byte("extra")}
			},
		},
		{
			name: "remote gas used", fixture: prototypeSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				onlyPrototypeOutput(output).GasUsed = 1
			},
		},
		{
			name: "nonzero value", fixture: prototypeSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				onlyPrototypeOutput(output).OutputTransfers[0].Value = big.NewInt(1)
			},
		},
		{
			name: "gas lock", fixture: prototypeSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				onlyPrototypeOutput(output).OutputTransfers[0].GasLocked = 1
			},
		},
		{
			name: "wrong protocol kind", fixture: prototypeSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				onlyPrototypeOutput(output).OutputTransfers[0].ProtocolMessageKind = vmData.ProtocolMessageKindNone
			},
		},
		{
			name: "source forwarded gas exceeds allowance", fixture: prototypeSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(input *vmcommon.ContractCallInput, _ *vmcommon.VMOutput) { input.GasProvided = 100 },
		},
		{
			name: "destination wrong origin", fixture: prototypeDestinationGasFixture,
			txType: process.BuiltInFunctionCall, isCrossShard: true,
			mutate: func(input *vmcommon.ContractCallInput, _ *vmcommon.VMOutput) {
				input.NativeCallOrigin = vmcommon.NativeCallOriginUnknown
			},
		},
		{
			name: "destination reported local", fixture: prototypeDestinationGasFixture,
			txType: process.BuiltInFunctionCall,
		},
		{
			name: "destination zero gate consumption", fixture: prototypeDestinationGasFixture,
			txType: process.BuiltInFunctionCall, isCrossShard: true,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				onlyPrototypeOutput(output).OutputTransfers[0].GasLimit = 80
			},
		},
		{
			name: "destination malformed receipt", fixture: prototypeDestinationGasFixture,
			txType: process.BuiltInFunctionCall, isCrossShard: true,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				onlyPrototypeOutput(output).OutputTransfers[0].Data = []byte(PrototypeSettlementReceiptFunction + "@00")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, output := test.fixture(t)
			if test.mutate != nil {
				test.mutate(input, output)
			}
			gasUsed, matched, refund, err := PrototypeExecutionGasUsed(test.txType, test.isCrossShard, input, output)
			require.ErrorIs(t, err, ErrInvalidPrototypeForwardedGas)
			require.True(t, matched)
			require.False(t, refund)
			require.Zero(t, gasUsed)
		})
	}
}

func prototypeDestinationRefundGasFixture(t *testing.T) (*vmcommon.ContractCallInput, *vmcommon.VMOutput) {
	t.Helper()
	input, _ := prototypeDestinationGasFixture(t)
	envelope, err := drwaprototype.DecodeValueEnvelope(input.Arguments[0])
	require.NoError(t, err)
	refundBytes, err := drwaprototype.EncodeRefundEnvelope(drwaprototype.RefundEnvelope{
		EffectID:                     envelope.Context.EffectID,
		ContextHash:                  [32]byte{7},
		DestinationExecutionIdentity: bytesToPrototypeHash(input.CurrentTxHash),
		OriginalTransferPayload:      envelope.OriginalTransferPayload,
		RefundTo:                     envelope.Context.SourceHolder,
	})
	require.NoError(t, err)
	output := prototypeGasOutput(
		envelope.Context.SourceHolder[:],
		envelope.Context.DestinationHolder[:],
		PrototypeRefundEnvelopeFunction,
		refundBytes,
		60,
	)
	output.ReturnCode = vmcommon.UserError
	output.ProtocolExecution = &vmcommon.ProtocolExecutionInfo{
		MessageKind:  vmData.ProtocolMessageKindDRWA,
		Outcome:      vmcommon.ProtocolExecutionOutcomeRefundEnvelope,
		LocalGasUsed: 40,
		ForwardedGas: 60,
	}
	return input, output
}

func bytesToPrototypeHash(value []byte) [32]byte {
	result := [32]byte{}
	copy(result[:], value)
	return result
}

func prototypeSourceGasFixture(t *testing.T) (*vmcommon.ContractCallInput, *vmcommon.VMOutput) {
	t.Helper()
	envelope := prototypeGasEnvelope()
	envelopeBytes, err := drwaprototype.EncodeValueEnvelope(envelope)
	require.NoError(t, err)
	source := envelope.Context.SourceHolder[:]
	destination := envelope.Context.DestinationHolder[:]
	input := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallerAddr:       append([]byte(nil), source...),
			Arguments:        [][]byte{append([]byte(nil), destination...), append([]byte(nil), envelope.Context.RegulatedTokenID...), append([]byte(nil), envelope.Context.Quantity...)},
			CallValue:        big.NewInt(0),
			CallType:         vmData.DirectCall,
			GasProvided:      101,
			NativeCallOrigin: vmcommon.NativeCallOriginOriginalUserTransaction,
		},
		RecipientAddr: append([]byte(nil), source...),
		Function:      PrototypeSourceDebitFunction,
	}
	output := prototypeGasOutput(destination, source, vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope, envelopeBytes, 100)
	output.ProtocolExecution = &vmcommon.ProtocolExecutionInfo{
		MessageKind:  vmData.ProtocolMessageKindDRWA,
		Outcome:      vmcommon.ProtocolExecutionOutcomeForward,
		LocalGasUsed: 1,
		ForwardedGas: 100,
	}
	return input, output
}

func prototypeDestinationGasFixture(t *testing.T) (*vmcommon.ContractCallInput, *vmcommon.VMOutput) {
	t.Helper()
	envelope := prototypeGasEnvelope()
	envelopeBytes, err := drwaprototype.EncodeValueEnvelope(envelope)
	require.NoError(t, err)
	currentHash := [32]byte{9}
	receipt, err := drwaprototype.BuildSettlementReceipt([32]byte{8}, envelope.Context.EffectID, [32]byte{7}, currentHash)
	require.NoError(t, err)
	receiptBytes, err := drwaprototype.EncodeSettlementReceipt(receipt)
	require.NoError(t, err)
	input := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallerAddr:       append([]byte(nil), envelope.Context.SourceHolder[:]...),
			Arguments:        [][]byte{envelopeBytes},
			CallValue:        big.NewInt(0),
			CallType:         vmData.DirectCall,
			GasProvided:      100,
			CurrentTxHash:    append([]byte(nil), currentHash[:]...),
			NativeCallOrigin: vmcommon.NativeCallOriginDRWAProtocolMessage,
		},
		RecipientAddr: append([]byte(nil), envelope.Context.DestinationHolder[:]...),
		Function:      vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope,
	}
	output := prototypeGasOutput(envelope.Context.SourceHolder[:], envelope.Context.DestinationHolder[:], PrototypeSettlementReceiptFunction, receiptBytes, 70)
	output.ProtocolExecution = &vmcommon.ProtocolExecutionInfo{
		MessageKind:  vmData.ProtocolMessageKindDRWA,
		Outcome:      vmcommon.ProtocolExecutionOutcomeSettlementReceipt,
		LocalGasUsed: 30,
		ForwardedGas: 70,
	}
	return input, output
}

func prototypeGasEnvelope() drwaprototype.ValueEnvelope {
	return drwaprototype.ValueEnvelope{
		OriginalTransferPayload: []byte("ESDTTransfer@544f4b454e2d616263646566@02"),
		Context: drwaprototype.ValueContext{
			EffectID:                 [32]byte{1},
			EffectKind:               drwaprototype.ValueEffectKindDirectTransfer,
			OriginExecutionIdentity:  [32]byte{2},
			RegulatedTokenID:         []byte("TOKEN-abcdef"),
			RegulatedTokenType:       drwaprototype.TokenTypeFungible,
			Quantity:                 []byte{2},
			SourceHolder:             [32]byte{3},
			DestinationHolder:        [32]byte{4},
			CEBEpoch:                 5,
			TransferMode:             drwaprototype.TransferModeGatedDirect,
			SettlementExpiry:         6,
			GasScheduleIdentity:      [32]byte{7},
			DestinationGateGasLimit:  10,
			SuccessReceiptGasLimit:   20,
			RefundGenerationGasLimit: 30,
			SourceCompletionGasLimit: 40,
		},
	}
}

func prototypeGasOutput(address, sender []byte, function string, payload []byte, gasLimit uint64) *vmcommon.VMOutput {
	data := []byte(function + "@" + hex.EncodeToString(payload))
	return &vmcommon.VMOutput{
		ReturnCode: vmcommon.Ok,
		OutputAccounts: map[string]*vmcommon.OutputAccount{
			string(address): {
				Address: append([]byte(nil), address...),
				OutputTransfers: []vmcommon.OutputTransfer{{
					Index:               1,
					Value:               big.NewInt(0),
					GasLimit:            gasLimit,
					Data:                data,
					CallType:            vmData.DirectCall,
					ProtocolMessageKind: vmData.ProtocolMessageKindDRWA,
					SenderAddress:       append([]byte(nil), sender...),
				}},
			},
		},
	}
}

func onlyPrototypeOutput(output *vmcommon.VMOutput) *vmcommon.OutputAccount {
	for _, outputAccount := range output.OutputAccounts {
		return outputAccount
	}
	return nil
}
