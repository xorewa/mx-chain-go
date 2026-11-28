package processorV2

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"sort"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/process"
	coordinator2 "github.com/multiversx/mx-chain-go/process/coordinator"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
)

const qualSP222AckGas = uint64(60000)

type qualSP222Effects struct{}

func (e *qualSP222Effects) IsInterfaceNil() bool      { return e == nil }
func (e *qualSP222Effects) AcknowledgmentGas() uint64 { return qualSP222AckGas }
func (e *qualSP222Effects) Withhold(state.AccountsAdapter, []byte, uint64, []drwa.WithheldEffect) error {
	return nil
}

// qualSP222RegistrationOutputs registers the tokens on a metachain store and
// returns the native output of each registration.
func qualSP222RegistrationOutputs(t *testing.T, tokens ...string) []*vmcommon.VMOutput {
	t.Helper()
	store := integrationtests.CreateInMemoryShardAccountsDB()
	account, err := store.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue([]byte(core.ProtectedKeyPrefix+"DRWA@registry@count"), make([]byte, 8)))
	require.NoError(t, store.SaveAccount(account))
	_, err = store.Commit()
	require.NoError(t, err)
	registration, boundary, err := drwa.NewRegistryRegistration(store,
		&testscommon.ShardsCoordinatorMock{NoShards: 3, CurrentShard: core.MetachainShardId}, 4)
	require.NoError(t, err)
	require.NoError(t, registration.SetRegistrationEffects(&qualSP222Effects{}))
	for _, token := range tokens {
		require.NoError(t, registration.RegisterToken(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
			return []byte(token), &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
		}))
	}
	_, outputs, err := boundary.Commit()
	require.NoError(t, err)
	require.Len(t, outputs, len(tokens))
	return outputs
}

// SP2-22, owner decision of 27 November (option 1), through the native result
// processor on both sides and with no change to it:
//
//  1. the metachain processor turns the output of a registration into one
//     asynchronous-call result for each execution shard and nothing else;
//  2. the processor of a shard executes that result and itself creates the
//     callback for the metachain ESDT system contract, from the shard's
//     system account address, with the gas of the delta: the acknowledgment;
//  3. the metachain processor hands that callback to the system contract in
//     the form ParseRegistryAcknowledgment reads;
//  4. a refused delta returns the native error callback, which is not an
//     acknowledgment, and a delta without gas returns nothing to the
//     metachain.
func TestQualSP222DeltaAndAcknowledgmentThroughTheNativeResultProcessor(t *testing.T) {
	const shard = uint32(1)
	system := bytes.Clone(core.SystemAccountAddress)
	system[len(system)-1] = uint8(shard)
	parser := smartContract.NewArgumentParser()
	// The native transaction type handler of a node of the given shard.
	txTypes := func(coordinator sharding.Coordinator, builtIns vmcommon.BuiltInFunctionContainer) process.TxTypeHandler {
		handler, typeErr := coordinator2.NewTxTypeHandler(coordinator2.ArgNewTxTypeHandler{
			PubkeyConverter: createMockPubkeyConverter(), ShardCoordinator: coordinator, BuiltInFunctions: builtIns,
			ArgumentParser: parsers.NewCallArgsParser(), ESDTTransferParser: &testscommon.ESDTTransferParserStub{},
			EnableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(),
		})
		require.NoError(t, typeErr)
		return handler
	}

	// 1. The metachain side.
	metaCoordinator, err := sharding.NewMultiShardCoordinator(3, core.MetachainShardId)
	require.NoError(t, err)
	require.Equal(t, shard, metaCoordinator.ComputeId(system), "the shard's system account address is in the shard")
	require.Equal(t, core.MetachainShardId, metaCoordinator.ComputeId(core.ESDTSCAddress))
	metaArguments := createMockSmartContractProcessorArguments()
	metaArguments.ShardCoordinator = metaCoordinator
	metaArguments.ArgsParser = parser
	metaTypes := txTypes(metaCoordinator, builtInFunctions.NewBuiltInFunctionContainer())
	metaArguments.TxTypeHandler = metaTypes
	meta, err := NewSmartContractProcessorV2(metaArguments)
	require.NoError(t, err)
	registering := &transaction.Transaction{SndAddr: bytes.Repeat([]byte{9}, 32), RcvAddr: bytes.Clone(core.ESDTSCAddress),
		Value: big.NewInt(0), GasLimit: 10 * qualSP222AckGas, GasPrice: 1, Data: []byte("registration")}
	outputs := qualSP222RegistrationOutputs(t, "TOKEN-abcdef", "OTHER-abcdef")
	deltas := make([]*smartContractResult.SmartContractResult, len(outputs))
	for i, output := range outputs {
		_, results, resultsErr := meta.processSCOutputAccounts(&vmcommon.VMInput{CallType: vmData.DirectCall}, output, registering, []byte("registration"))
		require.NoError(t, resultsErr)
		require.Len(t, results, 3, "a registration releases one result for each execution shard")
		sort.Slice(results, func(a, b int) bool { return bytes.Compare(results[a].GetRcvAddr(), results[b].GetRcvAddr()) < 0 })
		for to, result := range results {
			scr := result.(*smartContractResult.SmartContractResult)
			require.Equal(t, core.ESDTSCAddress, scr.SndAddr)
			require.Equal(t, uint32(to), metaCoordinator.ComputeId(scr.RcvAddr))
			require.Equal(t, vmData.AsynchronousCall, scr.CallType)
			require.Equal(t, qualSP222AckGas, scr.GasLimit)
			require.Zero(t, scr.Value.Sign())
			require.True(t, bytes.HasPrefix(scr.Data, []byte(drwa.RegistryDeltaFunctionName+"@")))
		}
		deltas[i] = results[shard].(*smartContractResult.SmartContractResult)
		require.Equal(t, system, deltas[i].RcvAddr)
	}

	// 2. The shard side.
	shardCoordinator, err := sharding.NewMultiShardCoordinator(3, shard)
	require.NoError(t, err)
	store := integrationtests.CreateInMemoryShardAccountsDB()
	registry, err := drwa.NewShardRegistry(store, shard)
	require.NoError(t, err)
	require.NoError(t, registry.BeginExecution())
	apply := registry.DeltaFunction()
	var created []data.TransactionHandler
	arguments := createMockSmartContractProcessorArguments()
	arguments.AccountsDB = store
	arguments.ShardCoordinator = shardCoordinator
	arguments.ArgsParser = parser
	shardBuiltIns := builtInFunctions.NewBuiltInFunctionContainer()
	require.NoError(t, shardBuiltIns.Add(drwa.RegistryDeltaFunctionName, apply))
	arguments.BuiltInFunctions = shardBuiltIns
	shardTypes := txTypes(shardCoordinator, shardBuiltIns)
	arguments.TxTypeHandler = shardTypes
	for _, delta := range deltas {
		kind, atDestination, _ := shardTypes.ComputeTransactionType(delta)
		require.Equal(t, process.BuiltInFunctionCall, kind, "the shard executes the delta as a built-in call")
		require.Equal(t, process.BuiltInFunctionCall, atDestination)
	}
	arguments.BlockChainHook = &testscommon.BlockChainHookStub{
		ProcessBuiltInFunctionCalled: func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
			require.Equal(t, drwa.RegistryDeltaFunctionName, input.Function)
			return apply.ProcessBuiltinFunction(nil, nil, input)
		},
	}
	arguments.ScrForwarder = &mock.IntermediateTransactionHandlerMock{
		AddIntermediateTransactionsCalled: func(txs []data.TransactionHandler, _ []byte) error {
			created = append(created, txs...)
			return nil
		},
	}
	sc, err := NewSmartContractProcessorV2(arguments)
	require.NoError(t, err)
	deliver := func(delta *smartContractResult.SmartContractResult) []*smartContractResult.SmartContractResult {
		created = nil
		_, processErr := sc.ProcessSmartContractResult(delta)
		require.NoError(t, processErr)
		var toMetachain []*smartContractResult.SmartContractResult
		for _, tx := range created {
			if shardCoordinator.ComputeId(tx.GetRcvAddr()) == core.MetachainShardId {
				toMetachain = append(toMetachain, tx.(*smartContractResult.SmartContractResult))
			}
		}
		return toMetachain
	}
	classified := func(token string) bool {
		regulated, classifyErr := registry.ClassifyToken([]byte(token))
		require.NoError(t, classifyErr)
		return regulated
	}
	// 3. The metachain's reading of a result that came back.
	read := func(result *smartContractResult.SmartContractResult) (*drwa.RegistryAcknowledgment, error) {
		require.Equal(t, core.ESDTSCAddress, result.RcvAddr)
		kind, _, _ := metaTypes.ComputeTransactionType(result)
		require.Equal(t, process.SCInvoking, kind, "the metachain executes the callback as a call of the system contract")
		input, inputErr := meta.createVMCallInput(result, []byte("callback"), false)
		require.NoError(t, inputErr)
		return drwa.ParseRegistryAcknowledgment(input, metaCoordinator.NumberOfShards())
	}

	// 4. A delta without gas is applied, but nothing reaches the metachain:
	// this shard is not counted there.
	unfunded := *deltas[0]
	unfunded.GasLimit = 0
	require.Empty(t, deliver(&unfunded), "a callback without gas does not leave the shard")
	require.True(t, classified("TOKEN-abcdef"), "the member is applied")
	root := func() []byte {
		hash, rootErr := store.RootHash()
		require.NoError(t, rootErr)
		return hash
	}
	applied := root()

	// The same member delivered again, with gas: no second mutation, and the
	// acknowledgment leaves with that gas.
	results := deliver(deltas[0])
	require.Equal(t, applied, root(), "the state of the shard is the same")
	require.Len(t, results, 1, "one result leaves for the metachain")
	require.Equal(t, system, results[0].SndAddr)
	require.Equal(t, vmData.AsynchronousCallBack, results[0].CallType)
	require.Equal(t, qualSP222AckGas, results[0].GasLimit)
	require.Zero(t, results[0].Value.Sign())
	acknowledgment, err := read(results[0])
	require.NoError(t, err)
	require.Equal(t, &drwa.RegistryAcknowledgment{Shard: shard, TokenID: []byte("TOKEN-abcdef"), Ordinal: 0}, acknowledgment)

	// The next member, first delivery.
	results = deliver(deltas[1])
	require.True(t, classified("OTHER-abcdef"))
	require.Len(t, results, 1)
	acknowledgment, err = read(results[0])
	require.NoError(t, err)
	require.Equal(t, &drwa.RegistryAcknowledgment{Shard: shard, TokenID: []byte("OTHER-abcdef"), Ordinal: 1}, acknowledgment)

	// A delta the shard refuses (a member that is not the next one): nothing is
	// applied.
	refused := *deltas[1]
	refused.Data = []byte(drwa.RegistryDeltaFunctionName + "@" + hex.EncodeToString([]byte("THIRD-abcdef")) + "@" +
		hex.EncodeToString(binary.BigEndian.AppendUint64(nil, 5)) + "@01@02@")
	before := root()
	results = deliver(&refused)
	require.Equal(t, before, root())
	require.False(t, classified("THIRD-abcdef"))
	// The native processor reports the refusal to the caller: a callback with
	// the error code of the delta. It is not an acknowledgment.
	require.Len(t, results, 1)
	require.Equal(t, vmData.AsynchronousCallBack, results[0].CallType)
	require.True(t, bytes.HasPrefix(results[0].Data, []byte("@04@"+hex.EncodeToString([]byte(drwa.ErrInvalidRegistryDelta.Error())))))
	_, err = read(results[0])
	require.ErrorIs(t, err, drwa.ErrInvalidRegistryAcknowledgment)
}
