package builtInFunctions

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
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
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/process/smartContract/processorV2"
	"github.com/multiversx/mx-chain-go/process/smartContract/scrCommon"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/hashingMocks"
	testIntegration "github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	"github.com/multiversx/mx-chain-go/txcache"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmcommonBuiltInFunctions "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	vmcommonMock "github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type prototypeResultProcessor interface {
	ProcessSmartContractResult(scr *smartContractResult.SmartContractResult) (vmcommon.ReturnCode, error)
}

type prototypeProcessorGasObservations struct {
	fees      []*big.Int
	devFees   []*big.Int
	refunded  []uint64
	penalized []uint64
}

const prototypeOrdinaryControlFunction = "prototypeOrdinaryControl"

func TestPrototypeAccountingSeamPreservesOrdinaryBuiltInAcrossBothProcessors(t *testing.T) {
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

	for _, processorCase := range processors {
		t.Run(processorCase.name, func(t *testing.T) {
			processor, accountsDB, tokenID, destinationAddress, forwarded, observations := newPrototypeDestinationProcessorFixture(
				t, processorCase.create, true, false, false,
			)
			scr := &smartContractResult.SmartContractResult{
				Value:          big.NewInt(0),
				SndAddr:        bytes.Repeat([]byte{0x11}, prototypeAddressLength),
				RcvAddr:        append([]byte(nil), destinationAddress...),
				GasPrice:       1,
				GasLimit:       100,
				Data:           []byte(prototypeOrdinaryControlFunction),
				OriginalTxHash: bytes.Repeat([]byte{0x61}, prototypeHashLength),
				PrevTxHash:     bytes.Repeat([]byte{0x61}, prototypeHashLength),
				CallType:       vmData.DirectCall,
			}

			returnCode, err := processor.ProcessSmartContractResult(scr)
			require.NoError(t, err)
			require.Equal(t, vmcommon.Ok, returnCode)
			require.Len(t, *forwarded, 1)
			require.Equal(t, vmData.ProtocolMessageKindNone, (*forwarded)[0].GetProtocolMessageKind())
			require.False(t, bytes.Contains((*forwarded)[0].GetData(), []byte("DRWA")))
			require.Len(t, observations.fees, 1)
			require.Zero(t, observations.fees[0].Sign())
			require.Zero(t, observations.devFees[0].Sign())
			require.Equal(t, []uint64{70}, observations.refunded)
			require.Empty(t, observations.penalized)

			canonical := loadPrototypeJournalAccount(t, accountsDB, destinationAddress)
			esdtBytes, _, err := canonical.AccountDataHandler().RetrieveValue(
				append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...),
			)
			require.NoError(t, err)
			require.Empty(t, esdtBytes)
		})
	}
}

func TestPrototypeDestinationProcessorSuccessAndRollbackControls(t *testing.T) {
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
		name            string
		admitted        bool
		postCreditFault bool
		accountingFault bool
		wantBalance     int64
		wantFunction    string
		wantReturnCode  vmcommon.ReturnCode
		wantRevert      bool
		wantIntegrity   bool
		wantForwardGas  uint64
		wantObservedFee int64
		wantFeeCalls    int
		wantRefunded    []uint64
	}{
		{name: "no injection success", admitted: true, wantBalance: 2, wantFunction: PrototypeSettlementReceiptFunction, wantReturnCode: vmcommon.Ok, wantForwardGas: 70, wantFeeCalls: 1, wantRefunded: []uint64{0}},
		{name: "receiver denial", admitted: false, wantBalance: 0, wantFunction: PrototypeRefundEnvelopeFunction, wantReturnCode: vmcommon.Ok, wantRevert: true, wantForwardGas: 60, wantFeeCalls: 1, wantRefunded: []uint64{0}},
		{name: "after credit output failure", admitted: true, postCreditFault: true, wantBalance: 0, wantFunction: PrototypeRefundEnvelopeFunction, wantReturnCode: vmcommon.Ok, wantRevert: true, wantForwardGas: 60, wantFeeCalls: 1, wantRefunded: []uint64{0}},
		{name: "after credit accounting output corruption", admitted: true, accountingFault: true, wantBalance: 0, wantReturnCode: vmcommon.ExecutionFailed, wantRevert: true, wantIntegrity: true},
	}

	for _, processorCase := range processors {
		processorCase := processorCase
		for _, test := range tests {
			test := test
			t.Run(processorCase.name+"/"+test.name, func(t *testing.T) {
				processor, accountsDB, tokenID, destinationAddress, forwarded, observations := newPrototypeDestinationProcessorFixture(
					t, processorCase.create, test.admitted, test.postCreditFault, test.accountingFault,
				)
				scr := newPrototypeDestinationSCR(t, tokenID, destinationAddress)
				returnCode, executionErr := processor.ProcessSmartContractResult(scr)
				require.Equal(t, test.wantReturnCode, returnCode)
				if test.wantIntegrity {
					require.ErrorIs(t, executionErr, scrCommon.ErrInvalidPrototypeForwardedGas)
				} else {
					assert.NoError(t, executionErr)
				}
				if test.wantRevert {
					require.Greater(t, accountsDB.revertCount, 0)
				}

				canonical := loadPrototypeJournalAccount(t, accountsDB, destinationAddress)
				esdtBytes, _, err := canonical.AccountDataHandler().RetrieveValue(
					append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...),
				)
				require.NoError(t, err)
				token := &esdt.ESDigitalToken{}
				if len(esdtBytes) == 0 {
					token.Value = big.NewInt(0)
				} else {
					require.NoError(t, testIntegration.TestMarshalizer.Unmarshal(token, esdtBytes))
				}
				require.Zero(t, token.Value.Cmp(big.NewInt(test.wantBalance)))

				if test.wantIntegrity {
					require.Empty(t, *forwarded)
					require.Empty(t, observations.fees)
					require.Empty(t, observations.refunded)
					require.Empty(t, observations.penalized)
					return
				}
				require.Len(t, *forwarded, 1)
				result := (*forwarded)[0]
				require.Equal(t, vmData.ProtocolMessageKindDRWA, result.GetProtocolMessageKind())
				require.True(t, bytes.HasPrefix(result.GetData(), []byte(test.wantFunction+"@")))
				require.False(t, bytes.HasPrefix(result.GetData(), []byte(core.BuiltInFunctionESDTTransfer+"@")))
				require.Equal(t, test.wantForwardGas, result.GetGasLimit())
				require.Len(t, observations.fees, test.wantFeeCalls)
				if test.wantFeeCalls > 0 {
					require.Equal(t, test.wantObservedFee, observations.fees[0].Int64())
					require.Zero(t, observations.devFees[0].Sign())
				}
				require.Equal(t, test.wantRefunded, observations.refunded)
				require.Empty(t, observations.penalized)
			})
		}
	}
}

func newPrototypeDestinationProcessorFixture(
	t *testing.T,
	create func(args scrCommon.ArgsNewSmartContractProcessor) (prototypeResultProcessor, error),
	admitted bool,
	postCreditFault bool,
	accountingFault bool,
) (prototypeResultProcessor, *prototypeTrackingAccountsDB, []byte, []byte, *[]*smartContractResult.SmartContractResult, *prototypeProcessorGasObservations) {
	t.Helper()
	sourceAddress := bytes.Repeat([]byte{0x11}, prototypeAddressLength)
	destinationAddress := bytes.Repeat([]byte{0x22}, prototypeAddressLength)
	tokenID := []byte("TOKEN-abcdef")
	enableEpochs := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(
		common.SCDeployFlag,
		common.BuiltInFunctionsFlag,
		common.CleanUpInformativeSCRsFlag,
		common.DRWAEnforcementFlag,
	)
	accountsDB := &prototypeTrackingAccountsDB{AccountsDB: testIntegration.CreateAccountsDB(testIntegration.CreateMemUnit(), enableEpochs)}
	destinationAccount := loadPrototypeJournalAccount(t, accountsDB, destinationAddress)
	receiverBytes, err := drwaprototype.EncodeReceiverGateRecord(drwaprototype.ReceiverGateRecord{
		Holder:            bytesToPrototypeAddress(destinationAddress),
		CEBEpoch:          9,
		Admitted:          admitted,
		ValidThroughRound: 100,
	})
	require.NoError(t, err)
	require.NoError(t, destinationAccount.AccountDataHandler().SaveKeyValue(
		drwaprototype.ReceiverGateStorageKey(tokenID), receiverBytes,
	))
	require.NoError(t, accountsDB.SaveAccount(destinationAccount))
	_, err = accountsDB.Commit()
	require.NoError(t, err)
	destinationAccount = loadPrototypeJournalAccount(t, accountsDB, destinationAddress)

	coordinator := &testscommon.ShardsCoordinatorMock{NoShards: 2, CurrentShard: 1, ComputeIdCalled: func(address []byte) uint32 {
		if bytes.Equal(address, sourceAddress) {
			return 0
		}
		return 1
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
	destination, err := newPrototypeDestination(prototypeDestinationArgs{
		delegate:            baselineDelegate,
		classifier:          func(_ []byte) (bool, error) { return true, nil },
		enableEpochsHandler: enableEpochs,
		shardCoordinator:    coordinator,
		networkDomain:       [32]byte{1},
		cebEpoch:            9,
		retainedWorkBudgetsProvider: func(identity [32]byte) (drwaprototype.WorkBudgets, uint64, error) {
			require.Equal(t, [32]byte{2}, identity)
			return drwaprototype.WorkBudgets{DestinationGate: 10, SuccessReceipt: 20, RefundGeneration: 30, SourceCompletion: 40}, 100, nil
		},
	})
	require.NoError(t, err)
	if postCreditFault {
		destination.delegate = &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(acntSnd, acntDst vmcommon.UserAccountHandler, input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
			output, delegateErr := baselineDelegate.ProcessBuiltinFunction(acntSnd, acntDst, input)
			require.NoError(t, delegateErr)
			output.OutputAccounts = map[string]*vmcommon.OutputAccount{"injected": {}}
			return output, nil
		}}
	}

	var hook *testscommon.BlockChainHookStub
	hook = &testscommon.BlockChainHookStub{
		CurrentRoundCalled: func() uint64 { return 7 },
		ProcessBuiltInFunctionCalled: func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
			if input.Function == prototypeOrdinaryControlFunction {
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 70}, nil
			}
			output, processErr := destination.ProcessBuiltinFunction(nil, destinationAccount, input)
			if processErr == nil {
				if accountingFault {
					for _, outputAccount := range output.OutputAccounts {
						outputAccount.OutputTransfers[0].ProtocolMessageKind = vmData.ProtocolMessageKindNone
					}
				}
				require.NoError(t, accountsDB.SaveAccount(destinationAccount))
			}
			return output, processErr
		},
	}
	require.NoError(t, destination.setBlockchainHook(hook))
	forwarded := make([]*smartContractResult.SmartContractResult, 0, 1)
	observations := &prototypeProcessorGasObservations{}
	args := newPrototypeDestinationProcessorArgs(t, accountsDB, coordinator, enableEpochs, hook, destination, &forwarded, observations)
	processor, err := create(args)
	require.NoError(t, err)

	return processor, accountsDB, tokenID, destinationAddress, &forwarded, observations
}

func newPrototypeDestinationSCR(t *testing.T, tokenID, destinationAddress []byte) *smartContractResult.SmartContractResult {
	t.Helper()
	sourceAddress := bytes.Repeat([]byte{0x11}, prototypeAddressLength)
	artifacts, err := drwaprototype.BuildDirectValueArtifacts([32]byte{1}, [32]byte{3}, drwaprototype.DirectValueIntent{
		RegulatedTokenID:         tokenID,
		Quantity:                 []byte{2},
		SourceHolder:             bytesToPrototypeAddress(sourceAddress),
		DestinationHolder:        bytesToPrototypeAddress(destinationAddress),
		CEBEpoch:                 9,
		SettlementExpiry:         100,
		GasScheduleIdentity:      [32]byte{2},
		DestinationGateGasLimit:  10,
		SuccessReceiptGasLimit:   20,
		RefundGenerationGasLimit: 30,
		SourceCompletionGasLimit: 40,
	})
	require.NoError(t, err)
	envelopeBytes, err := drwaprototype.EncodeValueEnvelope(artifacts.Envelope)
	require.NoError(t, err)
	originIdentity := [32]byte{3}
	return &smartContractResult.SmartContractResult{
		Value:               big.NewInt(0),
		SndAddr:             sourceAddress,
		RcvAddr:             append([]byte(nil), destinationAddress...),
		GasPrice:            1,
		GasLimit:            100,
		Data:                []byte(fmt.Sprintf("%s@%s", vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope, hex.EncodeToString(envelopeBytes))),
		OriginalTxHash:      append([]byte(nil), originIdentity[:]...),
		PrevTxHash:          append([]byte(nil), originIdentity[:]...),
		CallType:            vmData.DirectCall,
		ProtocolMessageKind: vmData.ProtocolMessageKindDRWA,
	}
}

func newPrototypeDestinationProcessorArgs(
	t *testing.T,
	accountsDB state.AccountsAdapter,
	coordinator *testscommon.ShardsCoordinatorMock,
	enableEpochs common.EnableEpochsHandler,
	hook *testscommon.BlockChainHookStub,
	destination vmcommon.BuiltinFunction,
	forwarded *[]*smartContractResult.SmartContractResult,
	observations *prototypeProcessorGasObservations,
) scrCommon.ArgsNewSmartContractProcessor {
	t.Helper()
	gasSchedule := map[string]map[string]uint64{
		common.BaseOpsAPICost: {common.AsyncCallStepField: 1000, common.AsyncCallbackGasLockField: 3000},
		common.BuiltInCost:    {vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope: 1},
	}
	builtIns := vmcommonBuiltInFunctions.NewBuiltInFunctionContainer()
	require.NoError(t, builtIns.Add(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope, destination))
	require.NoError(t, builtIns.Add(PrototypeSettlementReceiptFunction, &processMock.BuiltInFunctionStub{}))
	require.NoError(t, builtIns.Add(PrototypeRefundEnvelopeFunction, &processMock.BuiltInFunctionStub{}))
	require.NoError(t, builtIns.Add(prototypeOrdinaryControlFunction, &processMock.BuiltInFunctionStub{}))

	return scrCommon.ArgsNewSmartContractProcessor{
		VmContainer:      &processMock.VMContainerMock{},
		ArgsParser:       smartContract.NewArgumentParser(),
		Hasher:           &hashingMocks.HasherMock{},
		Marshalizer:      &processMock.MarshalizerMock{},
		AccountsDB:       accountsDB,
		BlockChainHook:   hook,
		BuiltInFunctions: builtIns,
		PubkeyConv:       testscommon.NewPubkeyConverterMock(32),
		ShardCoordinator: coordinator,
		ScrForwarder: &processMock.IntermediateTransactionHandlerMock{AddIntermediateTransactionsCalled: func(txs []data.TransactionHandler, _ []byte) error {
			for _, result := range txs {
				if scr, ok := result.(*smartContractResult.SmartContractResult); ok {
					*forwarded = append(*forwarded, scr)
				}
			}
			return nil
		}},
		BadTxForwarder: &processMock.IntermediateTransactionHandlerMock{},
		TxFeeHandler: &processMock.FeeAccumulatorStub{ProcessTransactionFeeCalled: func(cost, devFee *big.Int, _ []byte) {
			observations.fees = append(observations.fees, new(big.Int).Set(cost))
			observations.devFees = append(observations.devFees, new(big.Int).Set(devFee))
		}},
		TxLogsProcessor: &processMock.TxLogsProcessorStub{},
		EconomicsFee: &economicsmocks.EconomicsHandlerMock{
			DeveloperPercentageCalled: func() float64 { return 0 },
			ComputeTxFeeCalled: func(tx data.TransactionWithFeeHandler) *big.Int {
				return core.SafeMul(tx.GetGasLimit(), tx.GetGasPrice())
			},
			ComputeFeeForProcessingCalled: func(tx data.TransactionWithFeeHandler, gasToUse uint64) *big.Int {
				return core.SafeMul(tx.GetGasPrice(), gasToUse)
			},
		},
		TxTypeHandler: &testscommon.TxTypeHandlerMock{ComputeTransactionTypeCalled: func(_ data.TransactionHandler) (process.TransactionType, process.TransactionType, bool) {
			return process.BuiltInFunctionCall, process.BuiltInFunctionCall, false
		}},
		GasHandler: &testscommon.GasHandlerStub{
			SetGasRefundedCalled: func(gas uint64, _ []byte) {
				observations.refunded = append(observations.refunded, gas)
			},
			SetGasPenalizedCalled: func(gas uint64, _ []byte) {
				observations.penalized = append(observations.penalized, gas)
			},
		},
		GasSchedule:         testscommon.NewGasScheduleNotifierMock(gasSchedule),
		EnableRoundsHandler: &testscommon.EnableRoundsHandlerStub{},
		EnableEpochsHandler: enableEpochs,
		WasmVMChangeLocker:  &sync.RWMutex{},
		VMOutputCacher:      txcache.NewDisabledCache(),
	}
}

func bytesToPrototypeAddress(address []byte) [32]byte {
	result := [32]byte{}
	copy(result[:], address)
	return result
}
