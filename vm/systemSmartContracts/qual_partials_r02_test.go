package systemSmartContracts

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/process/smartContract/processorV2"
	"github.com/multiversx/mx-chain-go/process/smartContract/scrCommon"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/txcache"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmProcess "github.com/multiversx/mx-chain-go/vm/process"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

type qualPartialsSystemMachine struct {
	contract *esdt
	host     *vmContext
	flags    *enableEpochsHandlerMock.EnableEpochsHandlerStub
	db       *qualDRWARegistrationStore
	call     func(*vmcommon.ContractCallInput) (*vmcommon.VMOutput, error)
	consume  func(*vmcommon.VMOutput, *transaction.Transaction) ([]data.TransactionHandler, error)
	undo     func(*transaction.Transaction, int, error) error
}

// Real SystemVM and node output consumer, using the existing memory store.
// No bootstrap/factory or canonical context admission is being qualified.
func qualPartialsNewSystemMachine(t *testing.T) *qualPartialsSystemMachine {
	t.Helper()
	e, host, flags := qualTransitionContract(t, true)
	_, _, db, _, _, _ := qualNativeRegistration(t)
	f := &qualPartialsSystemMachine{contract: e, host: host, flags: flags, db: db}
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	host.userAccountsDB = db
	hook := host.blockChainHook.(*mock.BlockChainHookStub)
	hook.GetUserAccountCalled = func(address []byte) (vmcommon.UserAccountHandler, error) {
		a, err := db.LoadAccount(address)
		if err != nil {
			return nil, err
		}
		return a.(vmcommon.UserAccountHandler), nil
	}
	hook.GetStorageDataCalled = func(address, key []byte) ([]byte, uint32, error) {
		a, err := db.LoadAccount(address)
		if err != nil {
			return nil, 0, err
		}
		return a.(state.UserAccountHandler).RetrieveValue(key)
	}
	container := &mock.SystemSCContainerStub{GetCalled: func(address []byte) (vm.SystemSmartContract, error) {
		require.Equal(t, core.ESDTSCAddress, address)
		return e, nil
	}}
	require.NoError(t, host.SetSystemSCContainer(container))
	machine, err := vmProcess.NewSystemVM(vmProcess.ArgsNewSystemVM{SystemEI: host, SystemContracts: container, VmType: []byte{0}, GasSchedule: testscommon.NewGasScheduleNotifierMock(map[string]map[string]uint64{common.BaseOpsAPICost: {common.AsyncCallStepField: 1, common.AsyncCallbackGasLockField: 1}})})
	require.NoError(t, err)
	f.call = machine.RunSmartContractCall
	coordinator, err := sharding.NewMultiShardCoordinator(3, core.MetachainShardId)
	require.NoError(t, err)
	args := scrCommon.ArgsNewSmartContractProcessor{
		VmContainer: &processMock.VMContainerMock{}, ArgsParser: smartContract.NewArgumentParser(), Hasher: blake2b.NewBlake2b(), Marshalizer: &marshal.GogoProtoMarshalizer{}, AccountsDB: db,
		BlockChainHook: &testscommon.BlockChainHookStub{}, PubkeyConv: testscommon.NewPubkeyConverterMock(32), ShardCoordinator: coordinator,
		ScrForwarder: &processMock.IntermediateTransactionHandlerMock{}, BadTxForwarder: &processMock.IntermediateTransactionHandlerMock{}, TxFeeHandler: &processMock.FeeAccumulatorStub{}, TxLogsProcessor: &processMock.TxLogsProcessorStub{}, EconomicsFee: &economicsmocks.EconomicsHandlerMock{}, TxTypeHandler: &testscommon.TxTypeHandlerMock{}, GasHandler: &testscommon.GasHandlerStub{}, EnableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.FixCorrectSmallIntAndGasLimitsFlag), GasSchedule: testscommon.NewGasScheduleNotifierMock(map[string]map[string]uint64{}), WasmVMChangeLocker: &sync.RWMutex{}, VMOutputCacher: txcache.NewDisabledCache(), BuiltInFunctions: builtInFunctions.NewBuiltInFunctionContainer(),
	}
	sc, err := processorV2.NewSmartContractProcessorV2(args)
	require.NoError(t, err)
	f.consume = func(out *vmcommon.VMOutput, tx *transaction.Transaction) ([]data.TransactionHandler, error) {
		callback, results, err := processorV2.NewVMOutputAccountsProcessor(sc, &vmcommon.VMInput{CallType: vmData.DirectCall}, out, tx, []byte("resume2-hash")).Run()
		require.False(t, callback)
		return results, err
	}
	f.undo = func(tx *transaction.Transaction, snapshot int, cause error) error {
		return sc.ProcessIfError(nil, []byte("resume2-hash"), tx, cause.Error(), nil, snapshot, 0)
	}
	return f
}

func qualPartialsSeedToken(t *testing.T, f *qualPartialsSystemMachine, id []byte, token *ESDTDataV2) []byte {
	t.Helper()
	encoded, err := (&marshal.GogoProtoMarshalizer{}).Marshal(token)
	require.NoError(t, err)
	a, err := f.db.LoadAccount(core.ESDTSCAddress)
	require.NoError(t, err)
	require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(id, encoded))
	require.NoError(t, f.db.SaveAccount(a))
	_, err = f.db.Commit()
	require.NoError(t, err)
	return encoded
}

// Inject an inconsistent overall balance into the actual native output, prove
// the owning rollback, then consume the original output and recreate its trie.
func qualPartialsConsumeSystemOutput(t *testing.T, f *qualPartialsSystemMachine, in *vmcommon.ContractCallInput, out *vmcommon.VMOutput, id, expected []byte, wantRecipients, wantPayloads [][]byte) {
	t.Helper()
	root, err := f.db.RootHash()
	require.NoError(t, err)
	snapshot := f.db.JournalLen()
	acc := out.OutputAccounts[string(core.ESDTSCAddress)]
	require.NotNil(t, acc)
	originalDelta := new(big.Int).Set(acc.BalanceDelta)
	acc.BalanceDelta = new(big.Int).Add(originalDelta, big.NewInt(1))
	tx := &transaction.Transaction{SndAddr: in.CallerAddr, RcvAddr: in.RecipientAddr, Value: new(big.Int).Set(in.CallValue), GasPrice: in.GasPrice}
	_, err = f.consume(out, tx)
	require.ErrorIs(t, err, process.ErrOverallBalanceChangeFromSC)
	require.NoError(t, f.undo(tx, snapshot, err))
	after, err := f.db.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	acc.BalanceDelta = originalDelta
	results, err := f.consume(out, tx)
	require.NoError(t, err)
	require.Len(t, results, len(wantRecipients))
	require.Len(t, wantPayloads, len(wantRecipients))
	for i, result := range results {
		scr := result.(*smartContractResult.SmartContractResult)
		require.Equal(t, []byte("resume2-hash"), scr.PrevTxHash)
		require.Equal(t, []byte("resume2-hash"), scr.OriginalTxHash)
		require.Equal(t, in.CallerAddr, scr.OriginalSender)
		require.Equal(t, vmData.DirectCall, scr.CallType)
		require.Equal(t, wantRecipients[i], result.GetRcvAddr())
		require.Equal(t, core.ESDTSCAddress, result.GetSndAddr())
		require.Equal(t, wantPayloads[i], result.GetData())
		require.Zero(t, result.GetValue().Sign())
		require.Equal(t, uint64(0), result.GetGasLimit())
		require.Equal(t, uint64(9), result.GetGasPrice())
	}
	committed, err := f.db.Commit()
	require.NoError(t, err)
	require.NoError(t, f.db.RecreateTrie(holders.NewDefaultRootHashesHolder(committed)))
	require.Equal(t, expected, qualNativeRegistrationValue(t, f.db, core.ESDTSCAddress, id))
	a, err := f.db.GetExistingAccount(core.ESDTSCAddress)
	require.NoError(t, err)
	require.Equal(t, in.CallValue, a.(state.UserAccountHandler).GetBalance())
	require.Equal(t, []byte{1}, qualNativeRegistrationValue(t, f.db, core.ESDTSCAddress, []byte("fixture/sentinel")))
}

func TestQualPartialsR02SystemVMFanoutConsumer(t *testing.T) {
	f := qualPartialsNewSystemMachine(t)
	owner := bytes.Repeat([]byte{1}, 32)
	id := []byte("TOKEN-abcdef")
	token := &ESDTDataV2{OwnerAddress: owner, TokenName: []byte("TokenName"), TickerName: []byte("TOKEN"), TokenType: []byte(core.FungibleESDT), MintedValue: big.NewInt(0), BurntValue: big.NewInt(0), CanPause: true}
	before := qualPartialsSeedToken(t, f, id, token)
	in := qualTransitionInput("pause", [][]byte{id}, false)
	in.GasProvided = 1000
	in.GasPrice = 9
	// An owner denial must suppress staged SystemVM output, then allow a fresh call.
	in.CallerAddr = bytes.Repeat([]byte{2}, 32)
	denied, err := f.call(in)
	require.NoError(t, err)
	require.Equal(t, vmcommon.UserError, denied.ReturnCode)
	require.Empty(t, denied.OutputAccounts)
	require.Empty(t, denied.Logs)
	require.Zero(t, denied.GasRemaining)
	require.Equal(t, before, qualNativeRegistrationValue(t, f.db, core.ESDTSCAddress, id))
	in.CallerAddr = owner
	out, err := f.call(in)
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, out.ReturnCode)
	require.Equal(t, uint64(993), out.GasRemaining)
	require.Equal(t, []*vmcommon.LogEntry{{Identifier: []byte(core.BuiltInFunctionESDTPause), Address: owner, Topics: [][]byte{id}}}, out.Logs)
	token.IsPaused = true
	expected, err := (&marshal.GogoProtoMarshalizer{}).Marshal(token)
	require.NoError(t, err)
	var recipients, payloads [][]byte
	for shard := byte(0); shard < 3; shard++ {
		a := bytes.Clone(core.SystemAccountAddress)
		a[31] = shard
		recipients = append(recipients, a)
		payloads = append(payloads, []byte(core.BuiltInFunctionESDTPause+"@"+hex.EncodeToString(id)))
	}
	qualPartialsConsumeSystemOutput(t, f, in, out, id, expected, recipients, payloads)
}
