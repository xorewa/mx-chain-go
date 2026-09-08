package builtInFunctions

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
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

type drwaBuiltInProcessor interface {
	ExecuteBuiltInFunction(
		tx data.TransactionHandler,
		acntSnd state.UserAccountHandler,
		acntDst state.UserAccountHandler,
	) (vmcommon.ReturnCode, error)
}

type drwaJournalAccount interface {
	state.UserAccountHandler
	vmcommon.UserAccountHandler
}

type drwaTrackingAccountsDB struct {
	*state.AccountsDB
	revertCount int
}

func (accountsDB *drwaTrackingAccountsDB) RevertToSnapshot(snapshot int) error {
	accountsDB.revertCount++
	return accountsDB.AccountsDB.RevertToSnapshot(snapshot)
}

func TestDRWASourceDebitRealWrapperJournalRollbackMatrix(t *testing.T) {
	processors := []struct {
		name   string
		create func(args scrCommon.ArgsNewSmartContractProcessor) (drwaBuiltInProcessor, error)
	}{
		{name: "legacy", create: func(args scrCommon.ArgsNewSmartContractProcessor) (drwaBuiltInProcessor, error) {
			return smartContract.NewSmartContractProcessor(args)
		}},
		{name: "v2", create: func(args scrCommon.ArgsNewSmartContractProcessor) (drwaBuiltInProcessor, error) {
			return processorV2.NewSmartContractProcessorV2(args)
		}},
	}
	tests := []struct {
		name                string
		initialTokenBalance int64
		configure           func(t *testing.T, sourceDebit *drwaSourceDebit, baselineDelegate vmcommon.BuiltinFunction, capturedEffect *[32]byte, debitObserved *bool)
		wantCreatorCalled   bool
		wantDebitObserved   bool
		wantSuccess         bool
		accountingFault     bool
		wantIntegrity       bool
	}{
		{
			name:                "no injection success",
			initialTokenBalance: 100,
			configure:           captureDRWAOpenEffect,
			wantCreatorCalled:   true,
			wantSuccess:         true,
		},
		{
			name:                "after debit accounting output corruption",
			initialTokenBalance: 100,
			configure:           captureDRWAOpenEffect,
			wantCreatorCalled:   true,
			accountingFault:     true,
			wantIntegrity:       true,
		},
		{
			name:                "before OpenEffect storage",
			initialTokenBalance: 100,
			configure: func(_ *testing.T, sourceDebit *drwaSourceDebit, _ vmcommon.BuiltinFunction, _ *[32]byte, _ *bool) {
				sourceDebit.networkDomain = [32]byte{}
			},
		},
		{
			name:                "during OpenEffect storage",
			initialTokenBalance: 100,
			configure: func(t *testing.T, sourceDebit *drwaSourceDebit, _ vmcommon.BuiltinFunction, capturedEffect *[32]byte, _ *bool) {
				injected := errors.New("injected after OpenEffect write")
				sourceDebit.createOpenEffect = func(handler vmcommon.AccountDataHandler, effect drwa.OpenEffect) error {
					*capturedEffect = effect.EffectID
					require.NoError(t, drwa.CreateOpenEffect(handler, effect))
					return injected
				}
			},
			wantCreatorCalled: true,
		},
		{
			name:                "at baseline debit",
			initialTokenBalance: 1,
			configure:           captureDRWAOpenEffect,
			wantCreatorCalled:   true,
		},
		{
			name:                "after baseline debit",
			initialTokenBalance: 100,
			configure: func(t *testing.T, sourceDebit *drwaSourceDebit, baselineDelegate vmcommon.BuiltinFunction, capturedEffect *[32]byte, debitObserved *bool) {
				captureDRWAOpenEffect(t, sourceDebit, baselineDelegate, capturedEffect, debitObserved)
				sourceDebit.delegate = &processMock.BuiltInFunctionStub{
					ProcessBuiltinFunctionCalled: func(acntSnd, acntDst vmcommon.UserAccountHandler, input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
						output, err := baselineDelegate.ProcessBuiltinFunction(acntSnd, acntDst, input)
						require.NoError(t, err)
						*debitObserved = true
						output.OutputAccounts = map[string]*vmcommon.OutputAccount{"injected-invalid-output": {}}
						return output, nil
					},
				}
			},
			wantCreatorCalled: true,
			wantDebitObserved: true,
		},
	}

	for _, processorCase := range processors {
		processorCase := processorCase
		for _, test := range tests {
			test := test
			t.Run(processorCase.name+"/"+test.name, func(t *testing.T) {
				sourceAddress := bytes.Repeat([]byte{0x11}, drwaAddressLength)
				destination := bytes.Repeat([]byte{0x22}, drwaAddressLength)
				tokenID := []byte("TOKEN-abcdef")
				enableEpochs := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(
					common.SCDeployFlag,
					common.BuiltInFunctionsFlag,
					common.DRWAEnforcementFlag,
				)
				accountsDB := &drwaTrackingAccountsDB{
					AccountsDB: testIntegration.CreateAccountsDB(testIntegration.CreateMemUnit(), enableEpochs),
				}
				marshaller := testIntegration.TestMarshalizer
				esdtKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...)

				sourceAccount := loadDRWAJournalAccount(t, accountsDB, sourceAddress)
				encodedToken, err := marshaller.Marshal(&esdt.ESDigitalToken{Value: big.NewInt(test.initialTokenBalance)})
				require.NoError(t, err)
				require.NoError(t, sourceAccount.AccountDataHandler().SaveKeyValue(esdtKey, encodedToken))
				require.NoError(t, accountsDB.SaveAccount(sourceAccount))
				_, err = accountsDB.Commit()
				require.NoError(t, err)
				sourceAccount = loadDRWAJournalAccount(t, accountsDB, sourceAddress)

				baselineDelegate, err := vmcommonBuiltInFunctions.NewESDTTransferFunc(
					1,
					marshaller,
					&vmcommonMock.GlobalSettingsHandlerStub{},
					&vmcommonMock.ShardCoordinatorStub{ComputeIdCalled: func(address []byte) uint32 {
						if bytes.Equal(address, destination) {
							return 1
						}
						return 0
					}},
					&vmcommonMock.ESDTRoleHandlerStub{},
					&vmcommonMock.EnableEpochsHandlerStub{},
				)
				require.NoError(t, err)
				coordinator := &testscommon.ShardsCoordinatorMock{
					NoShards:     2,
					CurrentShard: 0,
					ComputeIdCalled: func(address []byte) uint32 {
						if bytes.Equal(address, destination) {
							return 1
						}
						return 0
					},
				}
				sourceDebit, err := newDRWASourceDebit(drwaSourceDebitArgs{
					delegate:                 baselineDelegate,
					classifier:               func(_ []byte) (bool, error) { return true, nil },
					enableEpochsHandler:      enableEpochs,
					shardCoordinator:         coordinator,
					networkDomain:            [32]byte{1},
					cebEpoch:                 9,
					settlementLifetimeRounds: 100,
					currentWorkBudgetsProvider: func() ([32]byte, drwa.WorkBudgets, uint64, error) {
						return [32]byte{2}, drwa.WorkBudgets{
							DestinationGate:  10,
							SuccessReceipt:   20,
							RefundGeneration: 30,
							SourceCompletion: 40,
						}, 100, nil
					},
				})
				require.NoError(t, err)

				var capturedEffect [32]byte
				debitObserved := false
				test.configure(t, sourceDebit, baselineDelegate, &capturedEffect, &debitObserved)
				var wrapperErr error
				drwaOutputCount := 0
				hook := &testscommon.BlockChainHookStub{
					CurrentRoundCalled: func() uint64 { return 7 },
					ProcessBuiltInFunctionCalled: func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
						output, processErr := sourceDebit.ProcessBuiltinFunction(sourceAccount, sourceAccount, input)
						wrapperErr = processErr
						if processErr == nil {
							if test.accountingFault {
								for _, outputAccount := range output.OutputAccounts {
									outputAccount.OutputTransfers[0].ProtocolMessageKind = vmData.ProtocolMessageKindNone
								}
							}
							require.NoError(t, accountsDB.SaveAccount(sourceAccount))
						}
						return output, processErr
					},
				}
				require.NoError(t, sourceDebit.setBlockchainHook(hook))
				args := newDRWAProcessorArgs(t, accountsDB, coordinator, enableEpochs, hook, sourceDebit, &drwaOutputCount)
				processor, err := processorCase.create(args)
				require.NoError(t, err)

				tx := &transaction.Transaction{
					Nonce:    0,
					SndAddr:  sourceAddress,
					RcvAddr:  sourceAddress,
					Value:    big.NewInt(0),
					GasLimit: 100000,
					Data: []byte(fmt.Sprintf("%s@%s@%s@02",
						DRWASourceDebitFunction,
						hex.EncodeToString(destination),
						hex.EncodeToString(tokenID),
					)),
				}
				returnCode, executionErr := processor.ExecuteBuiltInFunction(tx, sourceAccount, sourceAccount)
				if test.wantIntegrity {
					require.Equal(t, vmcommon.ExecutionFailed, returnCode)
					require.ErrorIs(t, executionErr, scrCommon.ErrInvalidDRWAForwardedGas)
					require.Greater(t, accountsDB.revertCount, 0)
					require.Zero(t, drwaOutputCount)
					canonicalAccount := loadDRWAJournalAccount(t, accountsDB, sourceAddress)
					canonicalTokenBytes, _, loadErr := canonicalAccount.AccountDataHandler().RetrieveValue(esdtKey)
					require.NoError(t, loadErr)
					canonicalToken := &esdt.ESDigitalToken{}
					require.NoError(t, marshaller.Unmarshal(canonicalToken, canonicalTokenBytes))
					require.Equal(t, "100", canonicalToken.Value.String())
					_, loadErr = drwa.LoadOpenEffect(canonicalAccount.AccountDataHandler(), capturedEffect)
					require.ErrorIs(t, loadErr, drwa.ErrOpenEffectNotFound)
					return
				}
				if test.wantSuccess {
					assert.Equal(t, vmcommon.Ok, returnCode)
					assert.NoError(t, executionErr)

					canonicalAccount := loadDRWAJournalAccount(t, accountsDB, sourceAddress)
					canonicalTokenBytes, _, loadErr := canonicalAccount.AccountDataHandler().RetrieveValue(esdtKey)
					require.NoError(t, loadErr)
					canonicalToken := &esdt.ESDigitalToken{}
					require.NoError(t, marshaller.Unmarshal(canonicalToken, canonicalTokenBytes))
					assert.Equal(t, "98", canonicalToken.Value.String())
					_, loadErr = drwa.LoadOpenEffect(canonicalAccount.AccountDataHandler(), capturedEffect)
					assert.NoError(t, loadErr)
					assert.Equal(t, 1, drwaOutputCount)
					return
				}

				require.Equal(t, vmcommon.UserError, returnCode)
				require.ErrorIs(t, executionErr, process.ErrFailedTransaction)
				if test.name == "before OpenEffect storage" {
					require.ErrorIs(t, wrapperErr, ErrDRWASourceDebitDenied)
				} else {
					require.ErrorIs(t, wrapperErr, ErrDRWASourceDebitMutation)
				}
				require.Equal(t, test.wantDebitObserved, debitObserved)
				require.Greater(t, accountsDB.revertCount, 0)
				require.Zero(t, drwaOutputCount)

				canonicalAccount := loadDRWAJournalAccount(t, accountsDB, sourceAddress)
				canonicalTokenBytes, _, err := canonicalAccount.AccountDataHandler().RetrieveValue(esdtKey)
				require.NoError(t, err)
				canonicalToken := &esdt.ESDigitalToken{}
				require.NoError(t, marshaller.Unmarshal(canonicalToken, canonicalTokenBytes))
				require.Zero(t, canonicalToken.Value.Cmp(big.NewInt(test.initialTokenBalance)))
				if test.wantCreatorCalled {
					require.NotEqual(t, [32]byte{}, capturedEffect)
					_, err = drwa.LoadOpenEffect(canonicalAccount.AccountDataHandler(), capturedEffect)
					require.ErrorIs(t, err, drwa.ErrOpenEffectNotFound)
				} else {
					require.Equal(t, [32]byte{}, capturedEffect)
				}
			})
		}
	}
}

func TestDRWASameShardRegulatedTransferProcessorSuccessAndRollbackMatrix(t *testing.T) {
	processors := []struct {
		name   string
		create func(args scrCommon.ArgsNewSmartContractProcessor) (drwaBuiltInProcessor, error)
	}{
		{name: "legacy", create: func(args scrCommon.ArgsNewSmartContractProcessor) (drwaBuiltInProcessor, error) {
			return smartContract.NewSmartContractProcessor(args)
		}},
		{name: "v2", create: func(args scrCommon.ArgsNewSmartContractProcessor) (drwaBuiltInProcessor, error) {
			return processorV2.NewSmartContractProcessorV2(args)
		}},
	}
	tests := []struct {
		name                string
		admitted            bool
		injectAfterMutation bool
		wantSuccess         bool
	}{
		{name: "no injection success", admitted: true, wantSuccess: true},
		{name: "receiver denial", admitted: false},
		{name: "delegate failure after both balance mutations", admitted: true, injectAfterMutation: true},
	}

	for _, processorCase := range processors {
		processorCase := processorCase
		for _, test := range tests {
			test := test
			t.Run(processorCase.name+"/"+test.name, func(t *testing.T) {
				sourceAddress := bytes.Repeat([]byte{0x31}, drwaAddressLength)
				destinationAddress := bytes.Repeat([]byte{0x32}, drwaAddressLength)
				tokenID := []byte("TOKEN-abcdef")
				esdtKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...)
				enableEpochs := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(
					common.SCDeployFlag,
					common.BuiltInFunctionsFlag,
					common.DRWAEnforcementFlag,
				)
				accountsDB := &drwaTrackingAccountsDB{
					AccountsDB: testIntegration.CreateAccountsDB(testIntegration.CreateMemUnit(), enableEpochs),
				}
				sourceAccount := loadDRWAJournalAccount(t, accountsDB, sourceAddress)
				destinationAccount := loadDRWAJournalAccount(t, accountsDB, destinationAddress)
				encodedSource, err := testIntegration.TestMarshalizer.Marshal(&esdt.ESDigitalToken{
					Value: big.NewInt(100),
					Type:  uint32(core.Fungible),
				})
				require.NoError(t, err)
				require.NoError(t, sourceAccount.AccountDataHandler().SaveKeyValue(esdtKey, encodedSource))
				receiverBytes, err := drwa.EncodeReceiverGateRecord(drwa.ReceiverGateRecord{
					Holder:            bytesToDRWAAddress(destinationAddress),
					CEBEpoch:          9,
					Admitted:          test.admitted,
					ValidThroughRound: 100,
				})
				require.NoError(t, err)
				require.NoError(t, destinationAccount.AccountDataHandler().SaveKeyValue(
					drwa.ReceiverGateStorageKey(tokenID),
					receiverBytes,
				))
				require.NoError(t, accountsDB.SaveAccount(sourceAccount))
				require.NoError(t, accountsDB.SaveAccount(destinationAccount))
				_, err = accountsDB.Commit()
				require.NoError(t, err)
				sourceAccount = loadDRWAJournalAccount(t, accountsDB, sourceAddress)
				destinationAccount = loadDRWAJournalAccount(t, accountsDB, destinationAddress)

				coordinator := &testscommon.ShardsCoordinatorMock{
					NoShards:        2,
					CurrentShard:    0,
					ComputeIdCalled: func(_ []byte) uint32 { return 0 },
				}
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
				var delegate vmcommon.BuiltinFunction = baselineDelegate
				mutationObserved := false
				if test.injectAfterMutation {
					delegateStub := &drwaTransferDelegateStub{}
					delegateStub.ProcessBuiltinFunctionCalled = func(acntSnd, acntDst vmcommon.UserAccountHandler, input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
						_, delegateErr := baselineDelegate.ProcessBuiltinFunction(acntSnd, acntDst, input)
						require.NoError(t, delegateErr)
						mutationObserved = true
						return nil, errors.New("injected after same-shard balance mutations")
					}
					delegate = delegateStub
				}
				guard, err := newDRWATransferGuard(
					core.BuiltInFunctionESDTTransfer,
					delegate,
					func(_ []byte) (bool, error) { return true, nil },
					enableEpochs,
					coordinator,
					9,
					func() (uint64, error) { return 7, nil },
				)
				require.NoError(t, err)

				var wrapperErr error
				drwaOutputCount := 0
				hook := &testscommon.BlockChainHookStub{ProcessBuiltInFunctionCalled: func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
					output, processErr := guard.ProcessBuiltinFunction(sourceAccount, destinationAccount, input)
					wrapperErr = processErr
					if processErr == nil {
						require.NoError(t, accountsDB.SaveAccount(sourceAccount))
						require.NoError(t, accountsDB.SaveAccount(destinationAccount))
					}
					return output, processErr
				}}
				args := newDRWAProcessorArgs(t, accountsDB, coordinator, enableEpochs, hook, guard, &drwaOutputCount)
				builtIns := vmcommonBuiltInFunctions.NewBuiltInFunctionContainer()
				require.NoError(t, builtIns.Add(core.BuiltInFunctionESDTTransfer, guard))
				args.BuiltInFunctions = builtIns
				processor, err := processorCase.create(args)
				require.NoError(t, err)

				tx := &transaction.Transaction{
					Nonce:    0,
					SndAddr:  sourceAddress,
					RcvAddr:  destinationAddress,
					Value:    big.NewInt(0),
					GasLimit: 100000,
					Data: []byte(fmt.Sprintf("%s@%s@02",
						core.BuiltInFunctionESDTTransfer,
						hex.EncodeToString(tokenID),
					)),
				}
				returnCode, executionErr := processor.ExecuteBuiltInFunction(tx, sourceAccount, destinationAccount)
				if test.wantSuccess {
					require.Equal(t, vmcommon.Ok, returnCode)
					require.NoError(t, executionErr)
				} else {
					require.Equal(t, vmcommon.UserError, returnCode)
					require.ErrorIs(t, executionErr, process.ErrFailedTransaction)
					require.Greater(t, accountsDB.revertCount, 0)
					if test.injectAfterMutation {
						require.True(t, mutationObserved)
					} else {
						require.ErrorIs(t, wrapperErr, ErrDRWASameShardTransferDenied)
					}
				}
				require.Zero(t, drwaOutputCount)

				canonicalSource := loadDRWAJournalAccount(t, accountsDB, sourceAddress)
				canonicalDestination := loadDRWAJournalAccount(t, accountsDB, destinationAddress)
				wantSource := int64(100)
				wantDestination := int64(0)
				if test.wantSuccess {
					wantSource = 98
					wantDestination = 2
				}
				requireDRWATokenBalance(t, canonicalSource, esdtKey, wantSource)
				requireDRWATokenBalance(t, canonicalDestination, esdtKey, wantDestination)
			})
		}
	}
}

func requireDRWATokenBalance(t *testing.T, account drwaJournalAccount, key []byte, expected int64) {
	t.Helper()
	encoded, _, err := account.AccountDataHandler().RetrieveValue(key)
	require.NoError(t, err)
	if len(encoded) == 0 {
		require.Zero(t, expected)
		return
	}
	token := &esdt.ESDigitalToken{}
	require.NoError(t, testIntegration.TestMarshalizer.Unmarshal(token, encoded))
	require.Zero(t, token.Value.Cmp(big.NewInt(expected)))
}

func captureDRWAOpenEffect(
	t *testing.T,
	sourceDebit *drwaSourceDebit,
	_ vmcommon.BuiltinFunction,
	capturedEffect *[32]byte,
	_ *bool,
) {
	t.Helper()
	sourceDebit.createOpenEffect = func(handler vmcommon.AccountDataHandler, effect drwa.OpenEffect) error {
		*capturedEffect = effect.EffectID
		return drwa.CreateOpenEffect(handler, effect)
	}
}

func loadDRWAJournalAccount(
	t *testing.T,
	accountsDB state.AccountsAdapter,
	address []byte,
) drwaJournalAccount {
	t.Helper()
	account, err := accountsDB.LoadAccount(address)
	require.NoError(t, err)
	userAccount, ok := account.(drwaJournalAccount)
	require.True(t, ok)
	return userAccount
}

func newDRWAProcessorArgs(
	t *testing.T,
	accountsDB state.AccountsAdapter,
	coordinator *testscommon.ShardsCoordinatorMock,
	enableEpochs common.EnableEpochsHandler,
	hook *testscommon.BlockChainHookStub,
	sourceDebit vmcommon.BuiltinFunction,
	drwaOutputCount *int,
) scrCommon.ArgsNewSmartContractProcessor {
	t.Helper()
	gasSchedule := map[string]map[string]uint64{
		common.BaseOpsAPICost: {
			common.AsyncCallStepField:        1000,
			common.AsyncCallbackGasLockField: 3000,
		},
		common.BuiltInCost: {
			core.BuiltInFunctionESDTTransfer: 1,
			DRWASourceDebitFunction:          1,
		},
	}
	builtIns := vmcommonBuiltInFunctions.NewBuiltInFunctionContainer()
	require.NoError(t, builtIns.Add(DRWASourceDebitFunction, sourceDebit))
	require.NoError(t, builtIns.Add(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope, &processMock.BuiltInFunctionStub{}))

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
				scr, ok := result.(*smartContractResult.SmartContractResult)
				if ok && scr.GetProtocolMessageKind() == vmData.ProtocolMessageKindDRWA {
					(*drwaOutputCount)++
				}
			}
			return nil
		}},
		BadTxForwarder:  &processMock.IntermediateTransactionHandlerMock{},
		TxFeeHandler:    &processMock.FeeAccumulatorStub{},
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
		GasHandler:          &testscommon.GasHandlerStub{},
		GasSchedule:         testscommon.NewGasScheduleNotifierMock(gasSchedule),
		EnableRoundsHandler: &testscommon.EnableRoundsHandlerStub{},
		EnableEpochsHandler: enableEpochs,
		WasmVMChangeLocker:  &sync.RWMutex{},
		VMOutputCacher:      txcache.NewDisabledCache(),
	}
}
