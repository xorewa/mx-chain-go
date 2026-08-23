package builtInFunctions

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
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

func TestPrototypeSourceCompletionProcessorAtomicMatrix(t *testing.T) {
	processors := []struct {
		name   string
		create func(args scrCommon.ArgsNewSmartContractProcessor) (prototypeResultProcessor, error)
	}{
		{name: "legacy", create: func(args scrCommon.ArgsNewSmartContractProcessor) (prototypeResultProcessor, error) {
			return smartContract.NewSmartContractProcessor(args)
		}},
		{name: "v2", create: func(args scrCommon.ArgsNewSmartContractProcessor) (prototypeResultProcessor, error) {
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
	}{
		{name: "receipt success", wantBalance: 98, wantReturnCode: vmcommon.Ok, wantRemaining: 30},
		{name: "refund success", refund: true, wantBalance: 100, wantReturnCode: vmcommon.Ok, wantRemaining: 20},
		{name: "receipt removal failure rolls back", failAfterTerminalIO: true, wantBalance: 98, wantEffect: true, wantReturnCode: vmcommon.UserError},
		{name: "refund post-credit failure rolls back", refund: true, failAfterTerminalIO: true, wantBalance: 98, wantEffect: true, wantReturnCode: vmcommon.UserError},
	}

	for _, processorCase := range processors {
		for _, test := range tests {
			t.Run(processorCase.name+"/"+test.name, func(t *testing.T) {
				processor, accountsDB, sourceAddress, tokenID, effectID, scr, observations := newPrototypeCompletionProcessorFixture(
					t, processorCase.create, test.refund, test.failAfterTerminalIO,
				)
				returnCode, executionErr := processor.ProcessSmartContractResult(scr)
				require.Equal(t, test.wantReturnCode, returnCode)
				if test.wantReturnCode == vmcommon.Ok {
					require.NoError(t, executionErr)
				} else {
					require.NoError(t, executionErr)
					require.Greater(t, accountsDB.revertCount, 0)
				}

				account := loadPrototypeJournalAccount(t, accountsDB, sourceAddress)
				require.Equal(t, test.wantBalance, loadPrototypeTokenBalance(t, account, tokenID))
				_, effectErr := drwaprototype.LoadOpenEffect(account.AccountDataHandler(), effectID)
				if test.wantEffect {
					require.NoError(t, effectErr)
				} else {
					require.ErrorIs(t, effectErr, drwaprototype.ErrOpenEffectNotFound)
				}
				if test.wantReturnCode == vmcommon.Ok {
					require.Equal(t, []uint64{test.wantRemaining}, observations.refunded)
					require.Len(t, observations.fees, 1)
					require.Zero(t, observations.fees[0].Sign())
				}
			})
		}
	}
}

func TestPrototypeSourceCompletionDuplicateCannotMutateAfterEffectRemoval(t *testing.T) {
	processor, accountsDB, sourceAddress, tokenID, effectID, scr, _ := newPrototypeCompletionProcessorFixture(
		t,
		func(args scrCommon.ArgsNewSmartContractProcessor) (prototypeResultProcessor, error) {
			return processorV2.NewSmartContractProcessorV2(args)
		},
		true,
		false,
	)
	returnCode, err := processor.ProcessSmartContractResult(scr)
	require.Equal(t, vmcommon.Ok, returnCode)
	require.NoError(t, err)
	returnCode, err = processor.ProcessSmartContractResult(scr)
	require.Equal(t, vmcommon.UserError, returnCode)
	require.NoError(t, err)

	account := loadPrototypeJournalAccount(t, accountsDB, sourceAddress)
	require.Equal(t, int64(100), loadPrototypeTokenBalance(t, account, tokenID))
	_, effectErr := drwaprototype.LoadOpenEffect(account.AccountDataHandler(), effectID)
	require.ErrorIs(t, effectErr, drwaprototype.ErrOpenEffectNotFound)
}

func newPrototypeCompletionProcessorFixture(
	t *testing.T,
	create func(args scrCommon.ArgsNewSmartContractProcessor) (prototypeResultProcessor, error),
	refund bool,
	failAfterTerminalIO bool,
) (prototypeResultProcessor, *prototypeTrackingAccountsDB, []byte, []byte, [32]byte, *smartContractResult.SmartContractResult, *prototypeProcessorGasObservations) {
	t.Helper()
	sourceAddress := bytes.Repeat([]byte{0x11}, prototypeAddressLength)
	destinationAddress := bytes.Repeat([]byte{0x22}, prototypeAddressLength)
	tokenID := []byte("TOKEN-abcdef")
	originIdentity := [32]byte{3}
	destinationIdentity := [32]byte{4}
	budgets := drwaprototype.WorkBudgets{DestinationGate: 10, SuccessReceipt: 20, RefundGeneration: 30, SourceCompletion: 40}
	artifacts, err := drwaprototype.BuildDirectValueArtifacts([32]byte{1}, originIdentity, drwaprototype.DirectValueIntent{
		RegulatedTokenID:         tokenID,
		Quantity:                 []byte{2},
		SourceHolder:             bytesToPrototypeAddress(sourceAddress),
		DestinationHolder:        bytesToPrototypeAddress(destinationAddress),
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
	)
	accountsDB := &prototypeTrackingAccountsDB{AccountsDB: testIntegration.CreateAccountsDB(testIntegration.CreateMemUnit(), enableEpochs)}
	account := loadPrototypeJournalAccount(t, accountsDB, sourceAddress)
	esdtKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...)
	encodedToken, err := testIntegration.TestMarshalizer.Marshal(&esdt.ESDigitalToken{Value: big.NewInt(98)})
	require.NoError(t, err)
	require.NoError(t, account.AccountDataHandler().SaveKeyValue(esdtKey, encodedToken))
	effectBytes, err := drwaprototype.EncodeOpenEffect(artifacts.OpenEffect)
	require.NoError(t, err)
	require.NoError(t, account.AccountDataHandler().SaveKeyValue(
		drwaprototype.OpenEffectStorageKey(artifacts.OpenEffect.EffectID),
		effectBytes,
	))
	require.NoError(t, accountsDB.SaveAccount(account))
	_, err = accountsDB.Commit()
	require.NoError(t, err)
	account = loadPrototypeJournalAccount(t, accountsDB, sourceAddress)

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
		&vmcommonMock.EnableEpochsHandlerStub{},
	)
	require.NoError(t, err)
	require.NoError(t, baselineDelegate.SetPayableChecker(&vmcommonMock.PayableHandlerStub{}))
	completion, err := newPrototypeSourceCompletion(prototypeSourceCompletionArgs{
		delegate:            baselineDelegate,
		enableEpochsHandler: enableEpochs,
		shardCoordinator:    coordinator,
		networkDomain:       [32]byte{1},
		retainedWorkBudgetsProvider: func(identity [32]byte) (drwaprototype.WorkBudgets, uint64, error) {
			require.Equal(t, [32]byte{2}, identity)
			return budgets, 100, nil
		},
	})
	require.NoError(t, err)
	if failAfterTerminalIO {
		completion.removeOpenEffect = func(handler vmcommon.AccountDataHandler, effectID [32]byte) error {
			require.NoError(t, drwaprototype.RemoveOpenEffect(handler, effectID))
			return errors.New("injected after terminal mutation")
		}
	}

	function := PrototypeSettlementReceiptFunction
	gasLimit := uint64(70)
	receipt, err := drwaprototype.BuildSettlementReceipt([32]byte{1}, artifacts.OpenEffect.EffectID, artifacts.ContextHash, destinationIdentity)
	require.NoError(t, err)
	payload, err := drwaprototype.EncodeSettlementReceipt(receipt)
	require.NoError(t, err)
	if refund {
		function = PrototypeRefundEnvelopeFunction
		gasLimit = 60
		payload, err = drwaprototype.EncodeRefundEnvelope(drwaprototype.RefundEnvelope{
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
		}
		return output, processErr
	}}
	observations := &prototypeProcessorGasObservations{}
	forwarded := make([]*smartContractResult.SmartContractResult, 0)
	args := newPrototypeDestinationProcessorArgs(t, accountsDB, coordinator, enableEpochs, hook, completion, &forwarded, observations)
	builtIns := vmcommonBuiltInFunctions.NewBuiltInFunctionContainer()
	require.NoError(t, builtIns.Add(PrototypeSettlementReceiptFunction, completion))
	require.NoError(t, builtIns.Add(PrototypeRefundEnvelopeFunction, completion))
	args.BuiltInFunctions = builtIns
	processor, err := create(args)
	require.NoError(t, err)

	return processor, accountsDB, sourceAddress, tokenID, artifacts.OpenEffect.EffectID, scr, observations
}

func loadPrototypeTokenBalance(t *testing.T, account prototypeJournalAccount, tokenID []byte) int64 {
	t.Helper()
	value, _, err := account.AccountDataHandler().RetrieveValue(
		append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...),
	)
	require.NoError(t, err)
	token := &esdt.ESDigitalToken{}
	require.NoError(t, testIntegration.TestMarshalizer.Unmarshal(token, value))
	return token.Value.Int64()
}
