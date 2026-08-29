package builtInFunctions

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
	"github.com/multiversx/mx-chain-go/process/smartContract/processorV2"
	"github.com/multiversx/mx-chain-go/process/smartContract/scrCommon"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	testIntegration "github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type drwaOrdinaryTransferVector struct {
	name             string
	functionName     string
	transactionData  func(source, destination, tokenID []byte) []byte
	receiverIsSource bool
	classifierCalls  int
	classifiedTokens []string
}

type drwaOrdinaryInputObservation struct {
	function         string
	caller           []byte
	recipient        []byte
	arguments        [][]byte
	callValue        string
	gasProvided      uint64
	gasLocked        uint64
	currentTxHash    []byte
	originalTxHash   []byte
	previousTxHash   []byte
	nativeCallOrigin vmcommon.NativeCallOrigin
	callType         vmData.CallType
}

type drwaOrdinaryRunObservation struct {
	returnCode         vmcommon.ReturnCode
	input              drwaOrdinaryInputObservation
	classifierCalls    int
	classifiedTokens   []string
	ordinaryStateValue []byte
	rootHash           []byte
	journalLength      int
	revertCount        int
	drwaOutputCount    int
	outputJSON         []byte
	protocolExecution  bool
}

// TestDRWATransferGuardFlagOnOrdinaryProcessorDifferential proves the ordinary-token
// path stays byte-for-byte equivalent when DRWA enforcement is enabled with a real,
// populated classification system account. It covers every guarded transfer entry
// point through both smart-contract processor generations. The control differs only
// in the DRWA flag; all transaction, account, delegate and processor inputs are equal.
func TestDRWATransferGuardFlagOnOrdinaryProcessorDifferential(t *testing.T) {
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
	vectors := []drwaOrdinaryTransferVector{
		{
			name:             "ESDTTransfer",
			functionName:     core.BuiltInFunctionESDTTransfer,
			classifierCalls:  1,
			classifiedTokens: []string{"ORDINARY-abcdef"},
			transactionData: func(_, _ []byte, tokenID []byte) []byte {
				return []byte(fmt.Sprintf("%s@%s@01", core.BuiltInFunctionESDTTransfer, hex.EncodeToString(tokenID)))
			},
		},
		{
			name:             "ESDTNFTTransfer",
			functionName:     core.BuiltInFunctionESDTNFTTransfer,
			receiverIsSource: true,
			classifierCalls:  1,
			classifiedTokens: []string{"ORDINARY-abcdef"},
			transactionData: func(_, destination, tokenID []byte) []byte {
				return []byte(fmt.Sprintf("%s@%s@01@01@%s",
					core.BuiltInFunctionESDTNFTTransfer,
					hex.EncodeToString(tokenID),
					hex.EncodeToString(destination),
				))
			},
		},
		{
			name:             "MultiESDTNFTTransfer",
			functionName:     core.BuiltInFunctionMultiESDTNFTTransfer,
			receiverIsSource: true,
			classifierCalls:  2,
			classifiedTokens: []string{"ORDINARY-abcdef", "ORDINARY2-abcdef"},
			transactionData: func(_, destination, tokenID []byte) []byte {
				return []byte(fmt.Sprintf("%s@%s@02@%s@00@01@%s@00@02",
					core.BuiltInFunctionMultiESDTNFTTransfer,
					hex.EncodeToString(destination),
					hex.EncodeToString(tokenID),
					hex.EncodeToString([]byte("ORDINARY2-abcdef")),
				))
			},
		},
	}

	for _, processorCase := range processors {
		processorCase := processorCase
		for _, vector := range vectors {
			vector := vector
			t.Run(processorCase.name+"/"+vector.name, func(t *testing.T) {
				control := runDRWAOrdinaryProcessorVector(t, processorCase.create, vector, false)
				candidate := runDRWAOrdinaryProcessorVector(t, processorCase.create, vector, true)

				require.Zero(t, control.classifierCalls)
				require.Empty(t, control.classifiedTokens)
				require.Equal(t, vector.classifierCalls, candidate.classifierCalls)
				require.Equal(t, vector.classifiedTokens, candidate.classifiedTokens)
				control.classifierCalls = 0
				candidate.classifierCalls = 0
				control.classifiedTokens = nil
				candidate.classifiedTokens = nil
				require.Equal(t, control, candidate)
			})
		}
	}
}

func runDRWAOrdinaryProcessorVector(
	t *testing.T,
	create func(args scrCommon.ArgsNewSmartContractProcessor) (drwaBuiltInProcessor, error),
	vector drwaOrdinaryTransferVector,
	drwaEnabled bool,
) drwaOrdinaryRunObservation {
	t.Helper()

	sourceAddress := bytes.Repeat([]byte{0x41}, drwaAddressLength)
	destinationAddress := bytes.Repeat([]byte{0x42}, drwaAddressLength)
	ordinaryTokenID := []byte("ORDINARY-abcdef")
	markedControlTokenID := []byte("MARKED-abcdef")
	ordinaryStateKey := []byte("ordinary-guard-differential-state")
	enabledFlags := []core.EnableEpochFlag{common.SCDeployFlag, common.BuiltInFunctionsFlag}
	if drwaEnabled {
		enabledFlags = append(enabledFlags, common.DRWAEnforcementFlag)
	}
	enableEpochs := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(enabledFlags...)
	accountsDB := &drwaTrackingAccountsDB{
		AccountsDB: testIntegration.CreateAccountsDB(testIntegration.CreateMemUnit(), enableEpochs),
	}
	require.NoError(t, drwa.MarkDRWARegulatedToken(accountsDB, markedControlTokenID))
	sourceAccount := loadDRWAJournalAccount(t, accountsDB, sourceAddress)
	destinationAccount := loadDRWAJournalAccount(t, accountsDB, destinationAddress)
	require.NoError(t, accountsDB.SaveAccount(sourceAccount))
	require.NoError(t, accountsDB.SaveAccount(destinationAccount))
	_, err := accountsDB.Commit()
	require.NoError(t, err)
	sourceAccount = loadDRWAJournalAccount(t, accountsDB, sourceAddress)
	destinationAccount = loadDRWAJournalAccount(t, accountsDB, destinationAddress)

	coordinator := &testscommon.ShardsCoordinatorMock{
		NoShards:     3,
		CurrentShard: 0,
		ComputeIdCalled: func(_ []byte) uint32 {
			return 0
		},
	}
	observation := drwaOrdinaryRunObservation{}
	delegate := &drwaTransferDelegateStub{}
	delegate.ProcessBuiltinFunctionCalled = func(
		acntSnd, acntDst vmcommon.UserAccountHandler,
		input *vmcommon.ContractCallInput,
	) (*vmcommon.VMOutput, error) {
		require.Same(t, sourceAccount, acntSnd)
		require.Same(t, destinationAccount, acntDst)
		observation.input = observeDRWAOrdinaryInput(input)
		value := []byte{byte(len(input.Arguments)), byte(len(input.Function))}
		require.NoError(t, acntSnd.AccountDataHandler().SaveKeyValue(ordinaryStateKey, value))
		return &vmcommon.VMOutput{
			ReturnCode:    vmcommon.Ok,
			ReturnMessage: "ordinary-control-message",
			GasRemaining:  input.GasProvided - 123,
			GasRefund:     big.NewInt(7),
			ReturnData:    [][]byte{[]byte("ordinary-control"), {0x01, 0x02}},
			Logs: []*vmcommon.LogEntry{{
				Identifier: []byte("ordinary-control-log"),
				Address:    append([]byte(nil), acntSnd.AddressBytes()...),
				Topics:     [][]byte{[]byte("topic")},
				Data:       [][]byte{[]byte("data")},
			}},
		}, nil
	}
	guard, err := newDRWATransferGuard(
		vector.functionName,
		delegate,
		func(tokenID []byte) (bool, error) {
			observation.classifierCalls++
			observation.classifiedTokens = append(observation.classifiedTokens, string(tokenID))
			return drwa.IsDRWARegulatedToken(accountsDB, tokenID)
		},
		enableEpochs,
		coordinator,
		9,
		func() (uint64, error) { return 7, nil },
	)
	require.NoError(t, err)

	var wrapperErr error
	hook := &testscommon.BlockChainHookStub{ProcessBuiltInFunctionCalled: func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		output, processErr := guard.ProcessBuiltinFunction(sourceAccount, destinationAccount, input)
		wrapperErr = processErr
		if processErr == nil {
			encodedOutput, marshalErr := json.Marshal(output)
			require.NoError(t, marshalErr)
			observation.outputJSON = encodedOutput
			observation.protocolExecution = output.ProtocolExecution != nil
			require.NoError(t, accountsDB.SaveAccount(sourceAccount))
			require.NoError(t, accountsDB.SaveAccount(destinationAccount))
		}
		return output, processErr
	}}
	args := newDRWAProcessorArgs(t, accountsDB, coordinator, enableEpochs, hook, guard, &observation.drwaOutputCount)
	require.NoError(t, args.BuiltInFunctions.Add(vector.functionName, guard))
	processor, err := create(args)
	require.NoError(t, err)

	receiverAddress := destinationAddress
	destinationForProcessor := destinationAccount
	if vector.receiverIsSource {
		receiverAddress = sourceAddress
		destinationForProcessor = sourceAccount
	}
	tx := &transaction.Transaction{
		Nonce:    0,
		SndAddr:  sourceAddress,
		RcvAddr:  receiverAddress,
		Value:    big.NewInt(0),
		GasLimit: 100_000,
		Data:     vector.transactionData(sourceAddress, destinationAddress, ordinaryTokenID),
	}
	observation.returnCode, err = processor.ExecuteBuiltInFunction(tx, sourceAccount, destinationForProcessor)
	require.NoError(t, err)
	require.NoError(t, wrapperErr)
	require.Equal(t, vmcommon.Ok, observation.returnCode)
	require.Zero(t, observation.drwaOutputCount)

	observation.journalLength = accountsDB.JournalLen()
	observation.revertCount = accountsDB.revertCount
	rootHash, err := accountsDB.Commit()
	require.NoError(t, err)
	observation.rootHash = append([]byte(nil), rootHash...)
	canonicalSource := loadDRWAJournalAccount(t, accountsDB, sourceAddress)
	observation.ordinaryStateValue, _, err = canonicalSource.AccountDataHandler().RetrieveValue(ordinaryStateKey)
	require.NoError(t, err)
	require.NotEmpty(t, observation.ordinaryStateValue)

	return observation
}

func observeDRWAOrdinaryInput(input *vmcommon.ContractCallInput) drwaOrdinaryInputObservation {
	result := drwaOrdinaryInputObservation{
		function:         input.Function,
		caller:           append([]byte(nil), input.CallerAddr...),
		recipient:        append([]byte(nil), input.RecipientAddr...),
		arguments:        make([][]byte, len(input.Arguments)),
		gasProvided:      input.GasProvided,
		gasLocked:        input.GasLocked,
		currentTxHash:    append([]byte(nil), input.CurrentTxHash...),
		originalTxHash:   append([]byte(nil), input.OriginalTxHash...),
		previousTxHash:   append([]byte(nil), input.PrevTxHash...),
		nativeCallOrigin: input.NativeCallOrigin,
		callType:         input.CallType,
	}
	if input.CallValue != nil {
		result.callValue = input.CallValue.String()
	}
	for index, argument := range input.Arguments {
		result.arguments[index] = append([]byte(nil), argument...)
	}

	return result
}

var _ vmcommon.BuiltinFunction = (*drwaTransferGuard)(nil)
