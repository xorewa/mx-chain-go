package scrCommon

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
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
	valid := func() *smartContractResult.SmartContractResult {
		return &smartContractResult.SmartContractResult{
			SndAddr:             sourceAddress,
			RcvAddr:             destinationAddress,
			Data:                []byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope + "@00"),
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

	t.Run("same-shard source rejects", func(t *testing.T) {
		scr := valid()
		scr.SndAddr = destinationAddress
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrInvalidProtocolMessageRoute)
	})

	t.Run("non-local destination rejects", func(t *testing.T) {
		scr := valid()
		scr.RcvAddr = sourceAddress
		require.ErrorIs(t, ValidateProtocolMessageAdmission(scr, enabled, coordinator), process.ErrInvalidProtocolMessageRoute)
	})

	t.Run("exact active cross-shard carrier reaches later validation", func(t *testing.T) {
		require.NoError(t, ValidateProtocolMessageAdmission(valid(), enabled, coordinator))
	})
}
