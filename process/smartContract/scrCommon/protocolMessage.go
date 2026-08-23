package scrCommon

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
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

	function := scr.GetData()
	if separatorIndex := bytes.IndexByte(function, '@'); separatorIndex >= 0 {
		function = function[:separatorIndex]
	}
	if !bytes.Equal(function, []byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope)) {
		return process.ErrInvalidProtocolMessageFunction
	}

	selfShardID := coordinator.SelfId()
	if coordinator.ComputeId(scr.GetRcvAddr()) != selfShardID ||
		coordinator.ComputeId(scr.GetSndAddr()) == selfShardID {
		return process.ErrInvalidProtocolMessageRoute
	}

	return nil
}
