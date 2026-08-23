package scrCommon

import (
	"bytes"
	"encoding/hex"

	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/sharding"
)

// ValidateProtocolMessageAdmission rejects protocol-kind SCRs before account loading or mutation unless
// the kind, activation state, native function and cross-shard route are the declared prototype values.
//
// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B
func ValidateProtocolMessageAdmission(
	scr *smartContractResult.SmartContractResult,
	enableEpochsHandler common.EnableEpochsHandler,
	coordinator sharding.Coordinator,
) error {
	kind := scr.GetProtocolMessageKind()
	if kind == vmData.ProtocolMessageKindNone {
		return nil
	}
	if kind != vmData.ProtocolMessageKindDRWA {
		return process.ErrUnknownProtocolMessageKind
	}
	if !enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag) {
		return process.ErrProtocolMessageBeforeActivation
	}

	callData := scr.GetData()
	separatorIndex := bytes.IndexByte(callData, '@')
	function := callData
	if separatorIndex >= 0 {
		function = callData[:separatorIndex]
	}
	isValueEnvelope := bytes.Equal(function, []byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope))
	isSettlementReceipt := bytes.Equal(function, []byte(PrototypeSettlementReceiptFunction))
	isRefundEnvelope := bytes.Equal(function, []byte(PrototypeRefundEnvelopeFunction))
	if !isValueEnvelope && !isSettlementReceipt && !isRefundEnvelope {
		return process.ErrInvalidProtocolMessageFunction
	}
	if separatorIndex < 0 {
		return process.ErrInvalidProtocolMessageEnvelope
	}

	envelopeHex := callData[separatorIndex+1:]
	if len(envelopeHex) == 0 ||
		len(envelopeHex)%2 != 0 ||
		len(envelopeHex) > 2*drwaprototype.PrototypeValueEnvelopeMaximumLength() ||
		bytes.IndexByte(envelopeHex, '@') >= 0 {
		return process.ErrInvalidProtocolMessageEnvelope
	}
	envelopeBytes := make([]byte, hex.DecodedLen(len(envelopeHex)))
	decodedLength, err := hex.Decode(envelopeBytes, envelopeHex)
	if err != nil || decodedLength != len(envelopeBytes) {
		return process.ErrInvalidProtocolMessageEnvelope
	}
	if !bytes.Equal(envelopeHex, []byte(hex.EncodeToString(envelopeBytes))) {
		return process.ErrInvalidProtocolMessageEnvelope
	}
	switch {
	case isValueEnvelope:
		_, err = drwaprototype.DecodeValueEnvelope(envelopeBytes)
	case isSettlementReceipt:
		_, err = drwaprototype.DecodeSettlementReceipt(envelopeBytes)
	case isRefundEnvelope:
		_, err = drwaprototype.DecodeRefundEnvelope(envelopeBytes)
	}
	if err != nil {
		return process.ErrInvalidProtocolMessageEnvelope
	}

	selfShardID := coordinator.SelfId()
	if coordinator.ComputeId(scr.GetRcvAddr()) != selfShardID ||
		coordinator.ComputeId(scr.GetSndAddr()) == selfShardID {
		return process.ErrInvalidProtocolMessageRoute
	}

	return nil
}
