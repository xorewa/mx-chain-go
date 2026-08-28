package builtInFunctions

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
	"github.com/multiversx/mx-chain-go/process/smartContract/processorV2"
	"github.com/multiversx/mx-chain-go/process/smartContract/scrCommon"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	testIntegration "github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmcommonBuiltInFunctions "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	vmcommonMock "github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

func TestDRWASourceCompletionProcessorAtomicMatrix(t *testing.T) {
	processors := []struct {
		name   string
		create func(args scrCommon.ArgsNewSmartContractProcessor) (drwaResultProcessor, error)
	}{
		{name: "legacy", create: func(args scrCommon.ArgsNewSmartContractProcessor) (drwaResultProcessor, error) {
			return smartContract.NewSmartContractProcessor(args)
		}},
		{name: "v2", create: func(args scrCommon.ArgsNewSmartContractProcessor) (drwaResultProcessor, error) {
			return processorV2.NewSmartContractProcessorV2(args)
		}},
	}
	tests := []struct {
		name                string
		refund              bool
		failAfterTerminalIO bool
		wantBalance         int64
		wantEffect          bool
		wantReturnCode      vmcommon.ReturnCode
		wantRemaining       uint64
		wantEGLDRefund      int64
	}{
		{name: "receipt success", wantBalance: 98, wantReturnCode: vmcommon.Ok, wantRemaining: 30, wantEGLDRefund: 30},
		{name: "refund success", refund: true, wantBalance: 100, wantReturnCode: vmcommon.Ok, wantRemaining: 20, wantEGLDRefund: 20},
		{name: "receipt removal failure rolls back", failAfterTerminalIO: true, wantBalance: 98, wantEffect: true, wantReturnCode: vmcommon.UserError},
		{name: "refund post-credit failure rolls back", refund: true, failAfterTerminalIO: true, wantBalance: 98, wantEffect: true, wantReturnCode: vmcommon.UserError},
	}

	for _, processorCase := range processors {
		for _, test := range tests {
			t.Run(processorCase.name+"/"+test.name, func(t *testing.T) {
				processor, accountsDB, sourceAddress, tokenID, effectID, scr, observations, forwarded := newDRWACompletionProcessorFixture(
					t, processorCase.create, test.refund, test.failAfterTerminalIO, nil, false,
				)
				returnCode, executionErr := processor.ProcessSmartContractResult(scr)
				require.Equal(t, test.wantReturnCode, returnCode)
				if test.wantReturnCode == vmcommon.Ok {
					require.NoError(t, executionErr)
				} else {
					require.NoError(t, executionErr)
					require.Greater(t, accountsDB.revertCount, 0)
				}

				account := loadDRWAJournalAccount(t, accountsDB, sourceAddress)
				require.Equal(t, test.wantBalance, loadDRWATokenBalance(t, account, tokenID))
				require.Equal(t, test.wantEGLDRefund, account.GetBalance().Int64())
				_, effectErr := drwa.LoadOpenEffect(account.AccountDataHandler(), effectID)
				if test.wantEffect {
					require.NoError(t, effectErr)
				} else {
					require.ErrorIs(t, effectErr, drwa.ErrOpenEffectNotFound)
				}
				if test.wantReturnCode == vmcommon.Ok {
					require.Equal(t, []uint64{test.wantRemaining}, observations.refunded)
					require.Len(t, observations.fees, 1)
					require.Zero(t, observations.fees[0].Sign())
					require.Len(t, *forwarded, 1)
					require.Equal(t, sourceAddress, (*forwarded)[0].RcvAddr)
					require.Equal(t, test.wantEGLDRefund, (*forwarded)[0].Value.Int64())
				}
			})
		}
	}
}

func TestDRWASourceCompletionDuplicateCannotMutateAfterEffectRemoval(t *testing.T) {
	processor, accountsDB, sourceAddress, tokenID, effectID, scr, _, forwarded := newDRWACompletionProcessorFixture(
		t,
		func(args scrCommon.ArgsNewSmartContractProcessor) (drwaResultProcessor, error) {
			return processorV2.NewSmartContractProcessorV2(args)
		},
		true,
		false,
		nil,
		false,
	)
	returnCode, err := processor.ProcessSmartContractResult(scr)
	require.Equal(t, vmcommon.Ok, returnCode)
	require.NoError(t, err)
	returnCode, err = processor.ProcessSmartContractResult(scr)
	require.Equal(t, vmcommon.UserError, returnCode)
	require.NoError(t, err)

	account := loadDRWAJournalAccount(t, accountsDB, sourceAddress)
	require.Equal(t, int64(100), loadDRWATokenBalance(t, account, tokenID))
	require.Equal(t, int64(20), account.GetBalance().Int64())
	creditedRefunds := 0
	for _, result := range *forwarded {
		if bytes.Equal(result.RcvAddr, sourceAddress) && result.Value.Cmp(big.NewInt(20)) == 0 {
			creditedRefunds++
		}
	}
	require.Equal(t, 1, creditedRefunds)
	_, effectErr := drwa.LoadOpenEffect(account.AccountDataHandler(), effectID)
	require.ErrorIs(t, effectErr, drwa.ErrOpenEffectNotFound)
}

func TestDRWASourceCompletionProcessorRejectsInvalidGasRefundRecipient(t *testing.T) {
	processors := []struct {
		name   string
		create func(args scrCommon.ArgsNewSmartContractProcessor) (drwaResultProcessor, error)
	}{
		{name: "legacy", create: func(args scrCommon.ArgsNewSmartContractProcessor) (drwaResultProcessor, error) {
			return smartContract.NewSmartContractProcessor(args)
		}},
		{name: "v2", create: func(args scrCommon.ArgsNewSmartContractProcessor) (drwaResultProcessor, error) {
			return processorV2.NewSmartContractProcessorV2(args)
		}},
	}
	mutations := []struct {
		name   string
		mutate func(output *vmcommon.VMOutput)
	}{
		{name: "missing", mutate: func(output *vmcommon.VMOutput) {
			output.ProtocolExecution.GasRefundRecipient = nil
		}},
		{name: "wrong account", mutate: func(output *vmcommon.VMOutput) {
			output.ProtocolExecution.GasRefundRecipient = bytes.Repeat([]byte{0x33}, drwaAddressLength)
		}},
		{name: "smart contract", mutate: func(output *vmcommon.VMOutput) {
			output.ProtocolExecution.GasRefundRecipient = make([]byte, drwaAddressLength)
		}},
	}

	for _, processorCase := range processors {
		for _, mutation := range mutations {
			t.Run(processorCase.name+"/"+mutation.name, func(t *testing.T) {
				processor, accountsDB, sourceAddress, tokenID, effectID, scr, observations, forwarded := newDRWACompletionProcessorFixture(
					t, processorCase.create, false, false, mutation.mutate, false,
				)
				returnCode, err := processor.ProcessSmartContractResult(scr)
				require.Equal(t, vmcommon.ExecutionFailed, returnCode)
				require.ErrorIs(t, err, scrCommon.ErrInvalidDRWAForwardedGas)
				require.Greater(t, accountsDB.revertCount, 0)

				account := loadDRWAJournalAccount(t, accountsDB, sourceAddress)
				require.Equal(t, int64(98), loadDRWATokenBalance(t, account, tokenID))
				require.Zero(t, account.GetBalance().Sign())
				_, effectErr := drwa.LoadOpenEffect(account.AccountDataHandler(), effectID)
				require.NoError(t, effectErr)
				require.Empty(t, *forwarded)
				require.Empty(t, observations.refunded)
			})
		}
	}
}

func TestDRWASourceCompletionProcessorRollsBackAfterLocalRefundCredit(t *testing.T) {
	processors := []struct {
		name   string
		create func(args scrCommon.ArgsNewSmartContractProcessor) (drwaResultProcessor, error)
	}{
		{name: "legacy", create: func(args scrCommon.ArgsNewSmartContractProcessor) (drwaResultProcessor, error) {
			return smartContract.NewSmartContractProcessor(args)
		}},
		{name: "v2", create: func(args scrCommon.ArgsNewSmartContractProcessor) (drwaResultProcessor, error) {
			return processorV2.NewSmartContractProcessorV2(args)
		}},
	}

	for _, processorCase := range processors {
		t.Run(processorCase.name, func(t *testing.T) {
			processor, accountsDB, sourceAddress, tokenID, effectID, scr, _, forwarded := newDRWACompletionProcessorFixture(
				t, processorCase.create, false, false, nil, true,
			)
			returnCode, err := processor.ProcessSmartContractResult(scr)
			require.Equal(t, vmcommon.ExecutionFailed, returnCode)
			require.ErrorContains(t, err, "injected result-forwarding failure")
			require.Greater(t, accountsDB.revertCount, 0)

			account := loadDRWAJournalAccount(t, accountsDB, sourceAddress)
			require.Equal(t, int64(98), loadDRWATokenBalance(t, account, tokenID))
			require.Zero(t, account.GetBalance().Sign())
			_, effectErr := drwa.LoadOpenEffect(account.AccountDataHandler(), effectID)
			require.NoError(t, effectErr)
			require.Empty(t, *forwarded)
		})
	}
}

func TestDRWASourceCompletionProcessorRejectsRelayerMetadataBeforeMutation(t *testing.T) {
	processors := []struct {
		name   string
		create func(args scrCommon.ArgsNewSmartContractProcessor) (drwaResultProcessor, error)
	}{
		{name: "legacy", create: func(args scrCommon.ArgsNewSmartContractProcessor) (drwaResultProcessor, error) {
			return smartContract.NewSmartContractProcessor(args)
		}},
		{name: "v2", create: func(args scrCommon.ArgsNewSmartContractProcessor) (drwaResultProcessor, error) {
			return processorV2.NewSmartContractProcessorV2(args)
		}},
	}

	for _, processorCase := range processors {
		t.Run(processorCase.name, func(t *testing.T) {
			processor, accountsDB, sourceAddress, tokenID, effectID, scr, observations, forwarded := newDRWACompletionProcessorFixture(
				t, processorCase.create, false, false, nil, false,
			)
			scr.RelayerAddr = bytes.Repeat([]byte{0x44}, drwaAddressLength)
			scr.RelayedValue = big.NewInt(0)

			returnCode, err := processor.ProcessSmartContractResult(scr)
			require.Equal(t, vmcommon.UserError, returnCode)
			require.ErrorIs(t, err, process.ErrInvalidProtocolMessageRoute)
			require.Zero(t, accountsDB.revertCount)

			account := loadDRWAJournalAccount(t, accountsDB, sourceAddress)
			require.Equal(t, int64(98), loadDRWATokenBalance(t, account, tokenID))
			require.Zero(t, account.GetBalance().Sign())
			_, effectErr := drwa.LoadOpenEffect(account.AccountDataHandler(), effectID)
			require.NoError(t, effectErr)
			require.Empty(t, *forwarded)
			require.Empty(t, observations.refunded)
		})
	}
}

func newDRWACompletionProcessorFixture(
	t *testing.T,
	create func(args scrCommon.ArgsNewSmartContractProcessor) (drwaResultProcessor, error),
	refund bool,
	failAfterTerminalIO bool,
	completionOutputMutation func(output *vmcommon.VMOutput),
	forwardingFault bool,
) (drwaResultProcessor, *drwaTrackingAccountsDB, []byte, []byte, [32]byte, *smartContractResult.SmartContractResult, *drwaProcessorGasObservations, *[]*smartContractResult.SmartContractResult) {
	t.Helper()
	sourceAddress := bytes.Repeat([]byte{0x11}, drwaAddressLength)
	destinationAddress := bytes.Repeat([]byte{0x22}, drwaAddressLength)
	tokenID := []byte("TOKEN-abcdef")
	originIdentity := [32]byte{3}
	destinationIdentity := [32]byte{4}
	budgets := drwa.WorkBudgets{DestinationGate: 10, SuccessReceipt: 20, RefundGeneration: 30, SourceCompletion: 40}
	artifacts, err := drwa.BuildDirectValueArtifacts([32]byte{1}, originIdentity, drwa.DirectValueIntent{
		RegulatedTokenID:         tokenID,
		Quantity:                 []byte{2},
		SourceHolder:             bytesToDRWAAddress(sourceAddress),
		DestinationHolder:        bytesToDRWAAddress(destinationAddress),
		CEBEpoch:                 9,
		SettlementExpiry:         100,
		GasScheduleIdentity:      [32]byte{2},
		DestinationGateGasLimit:  budgets.DestinationGate,
		SuccessReceiptGasLimit:   budgets.SuccessReceipt,
		RefundGenerationGasLimit: budgets.RefundGeneration,
		SourceCompletionGasLimit: budgets.SourceCompletion,
	})
	require.NoError(t, err)

	enableEpochs := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(
		common.SCDeployFlag,
		common.BuiltInFunctionsFlag,
		common.CleanUpInformativeSCRsFlag,
		common.DRWAEnforcementFlag,
		common.EGLDInESDTMultiTransferFlag,
	)
	accountsDB := &drwaTrackingAccountsDB{AccountsDB: testIntegration.CreateAccountsDB(testIntegration.CreateMemUnit(), enableEpochs)}
	account := loadDRWAJournalAccount(t, accountsDB, sourceAddress)
	esdtKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...)
	encodedToken, err := testIntegration.TestMarshalizer.Marshal(&esdt.ESDigitalToken{Value: big.NewInt(98)})
	require.NoError(t, err)
	require.NoError(t, account.AccountDataHandler().SaveKeyValue(esdtKey, encodedToken))
	effectBytes, err := drwa.EncodeOpenEffect(artifacts.OpenEffect)
	require.NoError(t, err)
	require.NoError(t, account.AccountDataHandler().SaveKeyValue(
		drwa.OpenEffectStorageKey(artifacts.OpenEffect.EffectID),
		effectBytes,
	))
	require.NoError(t, accountsDB.SaveAccount(account))
	_, err = accountsDB.Commit()
	require.NoError(t, err)
	account = loadDRWAJournalAccount(t, accountsDB, sourceAddress)

	coordinator := &testscommon.ShardsCoordinatorMock{NoShards: 2, CurrentShard: 0, ComputeIdCalled: func(address []byte) uint32 {
		if bytes.Equal(address, destinationAddress) {
			return 1
		}
		return 0
	}}
	baselineDelegate, err := vmcommonBuiltInFunctions.NewESDTTransferFunc(
		1,
		testIntegration.TestMarshalizer,
		&vmcommonMock.GlobalSettingsHandlerStub{},
		&vmcommonMock.ShardCoordinatorStub{ComputeIdCalled: coordinator.ComputeId},
		&vmcommonMock.ESDTRoleHandlerStub{},
		enableEpochs,
	)
	require.NoError(t, err)
	require.NoError(t, baselineDelegate.SetPayableChecker(&vmcommonMock.PayableHandlerStub{}))
	completion, err := newDRWASourceCompletion(drwaSourceCompletionArgs{
		delegate:            baselineDelegate,
		enableEpochsHandler: enableEpochs,
		shardCoordinator:    coordinator,
		networkDomain:       [32]byte{1},
		retainedWorkBudgetsProvider: func(identity [32]byte) (drwa.WorkBudgets, uint64, error) {
			require.Equal(t, [32]byte{2}, identity)
			return budgets, 100, nil
		},
	})
	require.NoError(t, err)
	if failAfterTerminalIO {
		completion.removeOpenEffect = func(handler vmcommon.AccountDataHandler, effectID [32]byte) error {
			require.NoError(t, drwa.RemoveOpenEffect(handler, effectID))
			return errors.New("injected after terminal mutation")
		}
	}

	function := DRWASettlementReceiptFunction
	gasLimit := uint64(70)
	receipt, err := drwa.BuildSettlementReceipt([32]byte{1}, artifacts.OpenEffect.EffectID, artifacts.ContextHash, destinationIdentity)
	require.NoError(t, err)
	payload, err := drwa.EncodeSettlementReceipt(receipt)
	require.NoError(t, err)
	if refund {
		function = DRWARefundEnvelopeFunction
		gasLimit = 60
		payload, err = drwa.EncodeRefundEnvelope(drwa.RefundEnvelope{
			EffectID:                     artifacts.OpenEffect.EffectID,
			ContextHash:                  artifacts.ContextHash,
			DestinationExecutionIdentity: destinationIdentity,
			OriginalTransferPayload:      artifacts.Envelope.OriginalTransferPayload,
			RefundTo:                     artifacts.Envelope.Context.SourceHolder,
		})
		require.NoError(t, err)
	}
	scr := &smartContractResult.SmartContractResult{
		Value:               big.NewInt(0),
		SndAddr:             destinationAddress,
		RcvAddr:             sourceAddress,
		GasPrice:            1,
		GasLimit:            gasLimit,
		Data:                []byte(fmt.Sprintf("%s@%s", function, hex.EncodeToString(payload))),
		OriginalTxHash:      originIdentity[:],
		PrevTxHash:          destinationIdentity[:],
		CallType:            vmData.DirectCall,
		ProtocolMessageKind: vmData.ProtocolMessageKindDRWA,
	}

	var hook *testscommon.BlockChainHookStub
	hook = &testscommon.BlockChainHookStub{ProcessBuiltInFunctionCalled: func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		output, processErr := completion.ProcessBuiltinFunction(nil, account, input)
		if processErr == nil {
			require.NoError(t, accountsDB.SaveAccount(account))
			if completionOutputMutation != nil {
				completionOutputMutation(output)
			}
		}
		return output, processErr
	}}
	observations := &drwaProcessorGasObservations{}
	forwarded := make([]*smartContractResult.SmartContractResult, 0)
	args := newDRWADestinationProcessorArgs(t, accountsDB, coordinator, enableEpochs, hook, completion, &forwarded, observations)
	if forwardingFault {
		args.ScrForwarder = &processMock.IntermediateTransactionHandlerMock{AddIntermediateTransactionsCalled: func(_ []data.TransactionHandler, _ []byte) error {
			return errors.New("injected result-forwarding failure")
		}}
	}
	builtIns := vmcommonBuiltInFunctions.NewBuiltInFunctionContainer()
	require.NoError(t, builtIns.Add(DRWASettlementReceiptFunction, completion))
	require.NoError(t, builtIns.Add(DRWARefundEnvelopeFunction, completion))
	args.BuiltInFunctions = builtIns
	processor, err := create(args)
	require.NoError(t, err)

	return processor, accountsDB, sourceAddress, tokenID, artifacts.OpenEffect.EffectID, scr, observations, &forwarded
}

func loadDRWATokenBalance(t *testing.T, account drwaJournalAccount, tokenID []byte) int64 {
	t.Helper()
	value, _, err := account.AccountDataHandler().RetrieveValue(
		append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...),
	)
	require.NoError(t, err)
	token := &esdt.ESDigitalToken{}
	require.NoError(t, testIntegration.TestMarshalizer.Unmarshal(token, value))
	return token.Value.Int64()
}
