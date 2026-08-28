package scrCommon

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestDRWAExecutionGasUsedValidRuledVectors(t *testing.T) {
	t.Run("source local work is one", func(t *testing.T) {
		input, output := drwaSourceGasFixture(t)
		gasUsed, matched, refund, err := DRWAExecutionGasUsed(process.BuiltInFunctionCall, false, input, output)
		require.NoError(t, err)
		require.True(t, matched)
		require.False(t, refund)
		require.Equal(t, uint64(1), gasUsed)
	})

	t.Run("destination local work is thirty", func(t *testing.T) {
		input, output := drwaDestinationGasFixture(t)
		gasUsed, matched, refund, err := DRWAExecutionGasUsed(process.BuiltInFunctionCall, true, input, output)
		require.NoError(t, err)
		require.True(t, matched)
		require.False(t, refund)
		require.Equal(t, uint64(30), gasUsed)
	})

	t.Run("destination refund is explicit and consumes forty", func(t *testing.T) {
		input, output := drwaDestinationRefundGasFixture(t)
		gasUsed, matched, refund, err := DRWAExecutionGasUsed(process.BuiltInFunctionCall, true, input, output)
		require.NoError(t, err)
		require.True(t, matched)
		require.True(t, refund)
		require.Equal(t, uint64(40), gasUsed)
	})

	for _, refund := range []bool{false, true} {
		name := "settlement completion"
		if refund {
			name = "refund completion"
		}
		t.Run(name+" returns unused gas to source payer", func(t *testing.T) {
			input, output := drwaCompletionGasFixture(t, refund, 30)
			gasUsed, matched, isRefund, err := DRWAExecutionGasUsed(process.BuiltInFunctionCall, true, input, output)
			require.NoError(t, err)
			require.True(t, matched)
			require.False(t, isRefund)
			require.Equal(t, uint64(40), gasUsed)

			_, _, _, recipient, err := DRWAExecutionGasAccounting(process.BuiltInFunctionCall, true, input, output)
			require.NoError(t, err)
			require.Equal(t, input.RecipientAddr, recipient)
			recipient[0] ^= 0xff
			require.NotEqual(t, recipient, output.ProtocolExecution.GasRefundRecipient)
		})
	}
}

func TestDRWAGasRefundRecipientRejectsEveryNearMiss(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(input *vmcommon.ContractCallInput, output *vmcommon.VMOutput)
	}{
		{name: "missing with remainder", mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
			output.ProtocolExecution.GasRefundRecipient = nil
		}},
		{name: "wrong source payer", mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
			output.ProtocolExecution.GasRefundRecipient = bytes.Repeat([]byte{0x55}, 32)
		}},
		{name: "short source payer", mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
			output.ProtocolExecution.GasRefundRecipient = bytes.Repeat([]byte{0x44}, 31)
		}},
		{name: "smart contract source payer", mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
			output.ProtocolExecution.GasRefundRecipient = make([]byte, 32)
		}},
		{name: "recipient with zero remainder", mutate: func(input *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
			output.GasRemaining = 0
			input.GasProvided = output.ProtocolExecution.LocalGasUsed
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, output := drwaCompletionGasFixture(t, false, 30)
			test.mutate(input, output)
			gasUsed, matched, refund, err := DRWAExecutionGasUsed(process.BuiltInFunctionCall, true, input, output)
			require.ErrorIs(t, err, ErrInvalidDRWAForwardedGas)
			require.True(t, matched)
			require.False(t, refund)
			require.Zero(t, gasUsed)
		})
	}

	t.Run("recipient on non-completion outcome", func(t *testing.T) {
		input, output := drwaSourceGasFixture(t)
		output.ProtocolExecution.GasRefundRecipient = append([]byte(nil), input.RecipientAddr...)
		gasUsed, matched, refund, err := DRWAExecutionGasUsed(process.BuiltInFunctionCall, false, input, output)
		require.ErrorIs(t, err, ErrInvalidDRWAForwardedGas)
		require.True(t, matched)
		require.False(t, refund)
		require.Zero(t, gasUsed)
	})

	t.Run("zero remainder has no recipient", func(t *testing.T) {
		input, output := drwaCompletionGasFixture(t, false, 0)
		gasUsed, matched, refund, err := DRWAExecutionGasUsed(process.BuiltInFunctionCall, true, input, output)
		require.NoError(t, err)
		require.True(t, matched)
		require.False(t, refund)
		require.Equal(t, uint64(40), gasUsed)
		_, _, _, recipient, err := DRWAExecutionGasAccounting(process.BuiltInFunctionCall, true, input, output)
		require.NoError(t, err)
		require.Nil(t, recipient)
	})
}

func TestDRWAExecutionGasUsedOrdinaryAndFailedRoutesRetainBaseline(t *testing.T) {
	t.Run("ordinary output", func(t *testing.T) {
		input := &vmcommon.ContractCallInput{Function: "ordinary"}
		output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}
		gasUsed, matched, refund, err := DRWAExecutionGasUsed(process.BuiltInFunctionCall, false, input, output)
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

			gasUsed, matched, refund, err := DRWAExecutionGasUsed(process.BuiltInFunctionCall, isCrossShard, input, output)
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
		input, _ := drwaSourceGasFixture(t)
		output := &vmcommon.VMOutput{ReturnCode: vmcommon.UserError}
		gasUsed, matched, refund, err := DRWAExecutionGasUsed(process.BuiltInFunctionCall, false, input, output)
		require.NoError(t, err)
		require.False(t, matched)
		require.False(t, refund)
		require.Zero(t, gasUsed)
	})
}

func TestDRWAExecutionGasUsedRejectsEverySpecialNearMiss(t *testing.T) {
	tests := []struct {
		name         string
		fixture      func(t *testing.T) (*vmcommon.ContractCallInput, *vmcommon.VMOutput)
		txType       process.TransactionType
		isCrossShard bool
		mutate       func(input *vmcommon.ContractCallInput, output *vmcommon.VMOutput)
	}{
		{
			name: "missing execution contract", fixture: drwaSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				output.ProtocolExecution = nil
			},
		},
		{
			name: "declared local gas mismatch", fixture: drwaSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				output.ProtocolExecution.LocalGasUsed++
			},
		},
		{
			name: "protocol output from unrelated function", fixture: drwaSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(input *vmcommon.ContractCallInput, _ *vmcommon.VMOutput) { input.Function = "ordinary" },
		},
		{
			name: "source wrong origin", fixture: drwaSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(input *vmcommon.ContractCallInput, _ *vmcommon.VMOutput) {
				input.NativeCallOrigin = vmcommon.NativeCallOriginUnknown
			},
		},
		{
			name: "source reported cross shard", fixture: drwaSourceGasFixture,
			txType: process.BuiltInFunctionCall, isCrossShard: true,
		},
		{
			name: "unexpected transaction type", fixture: drwaSourceGasFixture,
			txType: process.SCInvoking,
		},
		{
			name: "extra output account", fixture: drwaSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				output.OutputAccounts["extra"] = &vmcommon.OutputAccount{Address: []byte("extra")}
			},
		},
		{
			name: "remote gas used", fixture: drwaSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				onlyDRWAOutput(output).GasUsed = 1
			},
		},
		{
			name: "nonzero value", fixture: drwaSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				onlyDRWAOutput(output).OutputTransfers[0].Value = big.NewInt(1)
			},
		},
		{
			name: "gas lock", fixture: drwaSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				onlyDRWAOutput(output).OutputTransfers[0].GasLocked = 1
			},
		},
		{
			name: "wrong protocol kind", fixture: drwaSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				onlyDRWAOutput(output).OutputTransfers[0].ProtocolMessageKind = vmData.ProtocolMessageKindNone
			},
		},
		{
			name: "source forwarded gas exceeds allowance", fixture: drwaSourceGasFixture,
			txType: process.BuiltInFunctionCall,
			mutate: func(input *vmcommon.ContractCallInput, _ *vmcommon.VMOutput) { input.GasProvided = 100 },
		},
		{
			name: "destination wrong origin", fixture: drwaDestinationGasFixture,
			txType: process.BuiltInFunctionCall, isCrossShard: true,
			mutate: func(input *vmcommon.ContractCallInput, _ *vmcommon.VMOutput) {
				input.NativeCallOrigin = vmcommon.NativeCallOriginUnknown
			},
		},
		{
			name: "destination reported local", fixture: drwaDestinationGasFixture,
			txType: process.BuiltInFunctionCall,
		},
		{
			name: "destination zero gate consumption", fixture: drwaDestinationGasFixture,
			txType: process.BuiltInFunctionCall, isCrossShard: true,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				onlyDRWAOutput(output).OutputTransfers[0].GasLimit = 80
			},
		},
		{
			name: "destination malformed receipt", fixture: drwaDestinationGasFixture,
			txType: process.BuiltInFunctionCall, isCrossShard: true,
			mutate: func(_ *vmcommon.ContractCallInput, output *vmcommon.VMOutput) {
				onlyDRWAOutput(output).OutputTransfers[0].Data = []byte(DRWASettlementReceiptFunction + "@00")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, output := test.fixture(t)
			if test.mutate != nil {
				test.mutate(input, output)
			}
			gasUsed, matched, refund, err := DRWAExecutionGasUsed(test.txType, test.isCrossShard, input, output)
			require.ErrorIs(t, err, ErrInvalidDRWAForwardedGas)
			require.True(t, matched)
			require.False(t, refund)
			require.Zero(t, gasUsed)
		})
	}
}

func drwaDestinationRefundGasFixture(t *testing.T) (*vmcommon.ContractCallInput, *vmcommon.VMOutput) {
	t.Helper()
	input, _ := drwaDestinationGasFixture(t)
	envelope, err := drwa.DecodeValueEnvelope(input.Arguments[0])
	require.NoError(t, err)
	refundBytes, err := drwa.EncodeRefundEnvelope(drwa.RefundEnvelope{
		EffectID:                     envelope.Context.EffectID,
		ContextHash:                  [32]byte{7},
		DestinationExecutionIdentity: bytesToDRWAHash(input.CurrentTxHash),
		OriginalTransferPayload:      envelope.OriginalTransferPayload,
		RefundTo:                     envelope.Context.SourceHolder,
	})
	require.NoError(t, err)
	output := drwaGasOutput(
		envelope.Context.SourceHolder[:],
		envelope.Context.DestinationHolder[:],
		DRWARefundEnvelopeFunction,
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

func drwaCompletionGasFixture(
	t *testing.T,
	refund bool,
	gasRemaining uint64,
) (*vmcommon.ContractCallInput, *vmcommon.VMOutput) {
	t.Helper()
	envelope := drwaGasEnvelope()
	destinationIdentity := [32]byte{9}
	function := DRWASettlementReceiptFunction
	outcome := vmcommon.ProtocolExecutionOutcomeSourceSettled
	receipt, err := drwa.BuildSettlementReceipt(
		[32]byte{8},
		envelope.Context.EffectID,
		[32]byte{7},
		destinationIdentity,
	)
	require.NoError(t, err)
	payload, err := drwa.EncodeSettlementReceipt(receipt)
	require.NoError(t, err)
	if refund {
		function = DRWARefundEnvelopeFunction
		outcome = vmcommon.ProtocolExecutionOutcomeSourceRefunded
		payload, err = drwa.EncodeRefundEnvelope(drwa.RefundEnvelope{
			EffectID:                     envelope.Context.EffectID,
			ContextHash:                  [32]byte{7},
			DestinationExecutionIdentity: destinationIdentity,
			OriginalTransferPayload:      envelope.OriginalTransferPayload,
			RefundTo:                     envelope.Context.SourceHolder,
		})
		require.NoError(t, err)
	}
	input := &vmcommon.ContractCallInput{
		RecipientAddr: append([]byte(nil), envelope.Context.SourceHolder[:]...),
		Function:      function,
		VMInput: vmcommon.VMInput{
			CallerAddr:       append([]byte(nil), envelope.Context.DestinationHolder[:]...),
			Arguments:        [][]byte{payload},
			CallValue:        big.NewInt(0),
			CallType:         vmData.DirectCall,
			GasProvided:      40 + gasRemaining,
			PrevTxHash:       append([]byte(nil), destinationIdentity[:]...),
			NativeCallOrigin: vmcommon.NativeCallOriginDRWAProtocolMessage,
		},
	}
	var recipient []byte
	if gasRemaining != 0 {
		recipient = append([]byte(nil), input.RecipientAddr...)
	}
	output := &vmcommon.VMOutput{
		ReturnCode:   vmcommon.Ok,
		GasRemaining: gasRemaining,
		ProtocolExecution: &vmcommon.ProtocolExecutionInfo{
			MessageKind:        vmData.ProtocolMessageKindDRWA,
			Outcome:            outcome,
			LocalGasUsed:       40,
			GasRefundRecipient: recipient,
		},
	}
	return input, output
}

func bytesToDRWAHash(value []byte) [32]byte {
	result := [32]byte{}
	copy(result[:], value)
	return result
}

func drwaSourceGasFixture(t *testing.T) (*vmcommon.ContractCallInput, *vmcommon.VMOutput) {
	t.Helper()
	envelope := drwaGasEnvelope()
	envelopeBytes, err := drwa.EncodeValueEnvelope(envelope)
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
		Function:      DRWASourceDebitFunction,
	}
	output := drwaGasOutput(destination, source, vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope, envelopeBytes, 100)
	output.ProtocolExecution = &vmcommon.ProtocolExecutionInfo{
		MessageKind:  vmData.ProtocolMessageKindDRWA,
		Outcome:      vmcommon.ProtocolExecutionOutcomeForward,
		LocalGasUsed: 1,
		ForwardedGas: 100,
	}
	return input, output
}

func drwaDestinationGasFixture(t *testing.T) (*vmcommon.ContractCallInput, *vmcommon.VMOutput) {
	t.Helper()
	envelope := drwaGasEnvelope()
	envelopeBytes, err := drwa.EncodeValueEnvelope(envelope)
	require.NoError(t, err)
	currentHash := [32]byte{9}
	receipt, err := drwa.BuildSettlementReceipt([32]byte{8}, envelope.Context.EffectID, [32]byte{7}, currentHash)
	require.NoError(t, err)
	receiptBytes, err := drwa.EncodeSettlementReceipt(receipt)
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
	output := drwaGasOutput(envelope.Context.SourceHolder[:], envelope.Context.DestinationHolder[:], DRWASettlementReceiptFunction, receiptBytes, 70)
	output.ProtocolExecution = &vmcommon.ProtocolExecutionInfo{
		MessageKind:  vmData.ProtocolMessageKindDRWA,
		Outcome:      vmcommon.ProtocolExecutionOutcomeSettlementReceipt,
		LocalGasUsed: 30,
		ForwardedGas: 70,
	}
	return input, output
}

func drwaGasEnvelope() drwa.ValueEnvelope {
	return drwa.ValueEnvelope{
		OriginalTransferPayload: []byte("ESDTTransfer@544f4b454e2d616263646566@02"),
		Context: drwa.ValueContext{
			EffectID:                 [32]byte{1},
			EffectKind:               drwa.ValueEffectKindDirectTransfer,
			OriginExecutionIdentity:  [32]byte{2},
			RegulatedTokenID:         []byte("TOKEN-abcdef"),
			RegulatedTokenType:       drwa.TokenTypeFungible,
			Quantity:                 []byte{2},
			SourceHolder:             [32]byte{3},
			DestinationHolder:        [32]byte{4},
			CEBEpoch:                 5,
			TransferMode:             drwa.TransferModeGatedDirect,
			SettlementExpiry:         6,
			GasScheduleIdentity:      [32]byte{7},
			DestinationGateGasLimit:  10,
			SuccessReceiptGasLimit:   20,
			RefundGenerationGasLimit: 30,
			SourceCompletionGasLimit: 40,
		},
	}
}

func drwaGasOutput(address, sender []byte, function string, payload []byte, gasLimit uint64) *vmcommon.VMOutput {
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

func onlyDRWAOutput(output *vmcommon.VMOutput) *vmcommon.OutputAccount {
	for _, outputAccount := range output.OutputAccounts {
		return outputAccount
	}
	return nil
}
