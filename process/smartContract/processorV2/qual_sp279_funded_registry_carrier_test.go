package processorV2

import (
	"bytes"
	"encoding/binary"
	"sort"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"

	"math/big"

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

type qualSP279Block struct{ epoch uint32 }

func (b *qualSP279Block) IsInterfaceNil() bool { return b == nil }
func (b *qualSP279Block) ExecutingBlock() ([]byte, []byte, uint32, error) {
	return []byte("block"), []byte("header"), b.epoch, nil
}

// The entries of the test. They are test inputs, not proposed values.
const (
	qualSP279Source     = uint64(4000)
	qualSP279Success    = uint64(9000)
	qualSP279Completion = uint64(51000)
	qualSP279Leg        = qualSP279Success + qualSP279Completion
)

func qualSP279Schedule(scale uint64) map[string]map[string]uint64 {
	class := drwa.RegistryDeltaCarrierClass
	return map[string]map[string]uint64{drwa.CarrierCostSection: {class + "Source": scale * qualSP279Source, class + "Destination": 0,
		class + "Success": scale * qualSP279Success, class + "Refund": 0, class + "Completion": scale * qualSP279Completion}}
}

// SP2-79 through the native result processors of the metachain and of a
// shard, with no change to either (Part A F.2: "actual processor/error/refund
// paths included"):
//
//  1. a funded registration returns what it has left and gives each delta the
//     retained leg gas; the native gas check of the metachain processor accepts
//     that output, and refuses one that carries a unit more than it was given;
//  2. the shard's processor executes the delta, which uses none of that gas,
//     and returns all of it with the callback;
//  3. the metachain applies the acknowledgment once, at the retained
//     completion entry, also after the schedule changed;
//  4. a delta that was delivered without gas is applied by the shard and never
//     acknowledged; the same leg is then funded again from the gas of another
//     operation, delivered, applied a second time by nothing, and acknowledged
//     once.
func TestQualSP279FundedDeltaAcknowledgmentAndRedriveThroughTheNativeResultProcessor(t *testing.T) {
	const shards = uint32(3)
	parser := smartContract.NewArgumentParser()
	txTypes := func(coordinator sharding.Coordinator, builtIns vmcommon.BuiltInFunctionContainer) process.TxTypeHandler {
		handler, typeErr := coordinator2.NewTxTypeHandler(coordinator2.ArgNewTxTypeHandler{
			PubkeyConverter: createMockPubkeyConverter(), ShardCoordinator: coordinator, BuiltInFunctions: builtIns,
			ArgumentParser: parsers.NewCallArgsParser(), ESDTTransferParser: &testscommon.ESDTTransferParserStub{},
			EnableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(),
		})
		require.NoError(t, typeErr)
		return handler
	}

	// The metachain: store with the registry count and the retained budget,
	// the funding owner priced by the gas schedule, the registration.
	metaStore := integrationtests.CreateInMemoryShardAccountsDB()
	account, err := metaStore.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	system := account.(state.UserAccountHandler)
	require.NoError(t, system.SaveKeyValue([]byte(core.ProtectedKeyPrefix+"DRWA@registry@count"), make([]byte, 8)))
	budgetKey := []byte(core.ProtectedKeyPrefix + "DRWA@scopedAdmission@budget")
	budget := binary.BigEndian.AppendUint64(nil, 1)
	budget = binary.BigEndian.AppendUint64(budget, uint64(len(budgetKey)+32))
	budget = append(budget, make([]byte, 16)...)
	require.NoError(t, system.SaveKeyValue(budgetKey, budget))
	require.NoError(t, metaStore.SaveAccount(system))
	_, err = metaStore.Commit()
	require.NoError(t, err)
	schedule := testscommon.NewGasScheduleNotifierMock(qualSP279Schedule(1))
	var subscriber core.GasScheduleSubscribeHandler
	schedule.RegisterNotifyHandlerCalled = func(handler core.GasScheduleSubscribeHandler) { subscriber = handler }
	prices, err := drwa.NewGasScheduleCarrierPricing(schedule)
	require.NoError(t, err)
	block := &qualSP279Block{epoch: 1}
	funding, err := drwa.NewCarrierFunding(drwa.ArgsCarrierFunding{Accounts: metaStore, Marshaller: &marshal.GogoProtoMarshalizer{},
		Hasher: blake2b.NewBlake2b(), Block: block, Prices: prices,
		Limits: drwa.RegistrationResourceLimits{Records: 100, RetainedBytes: 1 << 20, NewRecordsPerEpoch: 100}, RecordBytes: 4096})
	require.NoError(t, err)
	metaCoordinator, err := sharding.NewMultiShardCoordinator(shards, core.MetachainShardId)
	require.NoError(t, err)
	registration, boundary, err := drwa.NewRegistryRegistration(metaStore, metaCoordinator, 4)
	require.NoError(t, err)
	require.NoError(t, registration.SetCarrierFunding(funding))

	metaArguments := createMockSmartContractProcessorArguments()
	metaArguments.ShardCoordinator = metaCoordinator
	metaArguments.ArgsParser = parser
	metaTypes := txTypes(metaCoordinator, builtInFunctions.NewBuiltInFunctionContainer())
	metaArguments.TxTypeHandler = metaTypes
	meta, err := NewSmartContractProcessorV2(metaArguments)
	require.NoError(t, err)

	// 1. The registering transaction and its gas after native creation.
	total := qualSP279Source + uint64(shards)*qualSP279Leg
	const creation = uint64(100000)
	registering := &transaction.Transaction{SndAddr: bytes.Repeat([]byte{9}, 32), RcvAddr: bytes.Clone(core.ESDTSCAddress),
		Value: big.NewInt(0), GasLimit: creation + total + 77, GasPrice: 1, Data: []byte("registration")}
	create := func(token string, left uint64) func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		return func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
			return []byte(token), &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: left}, nil
		}
	}
	require.ErrorIs(t, registration.RegisterToken(create("SHORT-abcdef", total-1)), drwa.ErrCarrierUnderfunded,
		"an underfunded registration is refused in its own journal operation")
	require.NoError(t, registration.RegisterToken(create("TOKEN-abcdef", total+77)))
	_, outputs, err := boundary.Commit()
	require.NoError(t, err)
	require.Len(t, outputs, 1)
	output := outputs[0]
	require.Equal(t, uint64(77), output.GasRemaining)
	require.NoError(t, meta.gasConsumedChecks(registering, registering.GasLimit, 0, output), "the native gas check accepts the funded output")
	inflated := *output
	inflated.GasRemaining = creation + qualSP279Source + 77 + 1
	require.ErrorIs(t, meta.gasConsumedChecks(registering, registering.GasLimit, 0, &inflated), process.ErrMoreGasConsumedThanProvided,
		"and a partition that was not taken from the gas would be refused by it")
	_, results, err := meta.processSCOutputAccounts(&vmcommon.VMInput{CallType: vmData.DirectCall}, output, registering, []byte("registration"))
	require.NoError(t, err)
	require.Len(t, results, int(shards))
	sort.Slice(results, func(a, b int) bool { return bytes.Compare(results[a].GetRcvAddr(), results[b].GetRcvAddr()) < 0 })
	deltas := make([]*smartContractResult.SmartContractResult, shards)
	for to, result := range results {
		deltas[to] = result.(*smartContractResult.SmartContractResult)
		require.Equal(t, uint32(to), metaCoordinator.ComputeId(deltas[to].RcvAddr))
		require.Equal(t, qualSP279Leg, deltas[to].GasLimit, "each leg carries its outcome and completion gas")
		require.Equal(t, vmData.AsynchronousCall, deltas[to].CallType)
	}

	// 2. One native processor for each execution shard.
	type shardNode struct {
		store    *state.AccountsDB
		registry *drwa.ShardRegistry
		deliver  func(*smartContractResult.SmartContractResult) []*smartContractResult.SmartContractResult
	}
	nodes := make([]*shardNode, shards)
	for shard := uint32(0); shard < shards; shard++ {
		shardCoordinator, coordinatorErr := sharding.NewMultiShardCoordinator(shards, shard)
		require.NoError(t, coordinatorErr)
		store := integrationtests.CreateInMemoryShardAccountsDB()
		registry, registryErr := drwa.NewShardRegistry(store, shard)
		require.NoError(t, registryErr)
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
		arguments.TxTypeHandler = txTypes(shardCoordinator, shardBuiltIns)
		arguments.BlockChainHook = &testscommon.BlockChainHookStub{
			ProcessBuiltInFunctionCalled: func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				return apply.ProcessBuiltinFunction(nil, nil, input)
			},
		}
		arguments.ScrForwarder = &mock.IntermediateTransactionHandlerMock{
			AddIntermediateTransactionsCalled: func(txs []data.TransactionHandler, _ []byte) error {
				created = append(created, txs...)
				return nil
			},
		}
		sc, processorErr := NewSmartContractProcessorV2(arguments)
		require.NoError(t, processorErr)
		nodes[shard] = &shardNode{store: store, registry: registry,
			deliver: func(delta *smartContractResult.SmartContractResult) []*smartContractResult.SmartContractResult {
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
			}}
	}
	root := func(shard uint32) []byte {
		hash, rootErr := nodes[shard].store.RootHash()
		require.NoError(t, rootErr)
		return bytes.Clone(hash)
	}
	// 3. The metachain's funded application of a callback that came back.
	acknowledge := func(callback *smartContractResult.SmartContractResult) (drwa.CarrierOutcomeResult, error) {
		require.Equal(t, core.ESDTSCAddress, callback.RcvAddr)
		kind, _, _ := metaTypes.ComputeTransactionType(callback)
		require.Equal(t, process.SCInvoking, kind)
		input, inputErr := meta.createVMCallInput(callback, []byte("callback"), false)
		require.NoError(t, inputErr)
		require.Equal(t, callback.GasLimit, input.GasProvided, "the callback's gas reaches the system contract")
		_, result, ackErr := funding.AcknowledgeRegistryDelta(input, shards)
		return result, ackErr
	}
	member := binary.BigEndian.AppendUint64([]byte("TOKEN-abcdef"), 0)
	read := func() *drwa.CarrierFundingState {
		s, readErr := funding.Read(drwa.RegistryDeltaCarrierClass, member)
		require.NoError(t, readErr)
		return s
	}

	// Shard 1: delivered, acknowledged with the whole leg gas.
	callbacks := nodes[1].deliver(deltas[1])
	require.Len(t, callbacks, 1)
	require.Equal(t, vmData.AsynchronousCallBack, callbacks[0].CallType)
	require.Equal(t, qualSP279Leg, callbacks[0].GasLimit, "the delta used none of the outcome and completion gas")
	// The schedule changes before the acknowledgment is processed.
	subscriber.GasScheduleChange(qualSP279Schedule(10))
	block.epoch++
	result, err := acknowledge(callbacks[0])
	require.NoError(t, err)
	require.Equal(t, drwa.CarrierOutcomeResult{Applied: true, Completion: qualSP279Completion, Remaining: qualSP279Success}, result,
		"completed at the retained entry, not at the active one")
	// The same callback delivered to the metachain again.
	result, err = acknowledge(callbacks[0])
	require.NoError(t, err)
	require.False(t, result.Applied)
	require.Equal(t, drwa.CarrierOutcome, read().Phase)

	// 4. Shard 0: the delta arrives without gas. Applied, never acknowledged.
	unfunded := *deltas[0]
	unfunded.GasLimit = 0
	require.Empty(t, nodes[0].deliver(&unfunded))
	applied := root(0)
	regulated, err := nodes[0].registry.ClassifyToken([]byte("TOKEN-abcdef"))
	require.NoError(t, err)
	require.True(t, regulated)
	require.False(t, read().HasOutcome(0), "the metachain does not count the shard")

	// Another operation on the metachain redrives the leg from its own gas,
	// at the retained entries although the active schedule is ten times higher.
	redriving := &transaction.Transaction{SndAddr: bytes.Repeat([]byte{8}, 32), RcvAddr: bytes.Clone(core.ESDTSCAddress),
		Value: big.NewInt(0), GasLimit: qualSP279Source + qualSP279Leg + 5, GasPrice: 1, Data: []byte("redrive")}
	redriveOutput := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}
	_, err = funding.RedriveRegistryDelta(redriveOutput, []byte("TOKEN-abcdef"), 0, 0, shards, qualSP279Source+qualSP279Leg-1)
	require.ErrorIs(t, err, drwa.ErrCarrierUnderfunded)
	require.Empty(t, redriveOutput.OutputAccounts, "a refused redrive emits nothing")
	redriveOutput.GasRemaining, err = funding.RedriveRegistryDelta(redriveOutput, []byte("TOKEN-abcdef"), 0, 0, shards, redriving.GasLimit)
	require.NoError(t, err)
	require.Equal(t, uint64(5), redriveOutput.GasRemaining)
	require.NoError(t, meta.gasConsumedChecks(redriving, redriving.GasLimit, 0, redriveOutput))
	_, results, err = meta.processSCOutputAccounts(&vmcommon.VMInput{CallType: vmData.DirectCall}, redriveOutput, redriving, []byte("redrive"))
	require.NoError(t, err)
	require.Len(t, results, 1)
	again := results[0].(*smartContractResult.SmartContractResult)
	require.Equal(t, deltas[0].RcvAddr, again.RcvAddr)
	require.Equal(t, deltas[0].Data, again.Data, "the same delta with the same identifiers")
	require.Equal(t, qualSP279Leg, again.GasLimit)

	callbacks = nodes[0].deliver(again)
	require.Equal(t, applied, root(0), "the shard applies nothing a second time")
	require.Len(t, callbacks, 1)
	require.Equal(t, qualSP279Leg, callbacks[0].GasLimit)
	result, err = acknowledge(callbacks[0])
	require.NoError(t, err)
	require.True(t, result.Applied)
	require.False(t, result.Terminal)
	// The first delivery's late duplicate, now with gas: one outcome only.
	late := nodes[0].deliver(deltas[0])
	require.Equal(t, applied, root(0))
	require.Len(t, late, 1)
	result, err = acknowledge(late[0])
	require.NoError(t, err)
	require.False(t, result.Applied)

	// A callback that returns with less gas than the retained completion work
	// is refused and the leg stays open.
	callbacks = nodes[2].deliver(deltas[2])
	require.Len(t, callbacks, 1)
	short := *callbacks[0]
	short.GasLimit = qualSP279Completion - 1
	_, err = acknowledge(&short)
	require.ErrorIs(t, err, drwa.ErrCarrierUnderfunded)
	require.False(t, read().HasOutcome(2))
	result, err = acknowledge(callbacks[0])
	require.NoError(t, err)
	require.True(t, result.Terminal)
	final := read()
	require.Equal(t, drwa.CarrierTerminal, final.Phase)
	require.Equal(t, uint64(1), final.Redrives)
	require.Equal(t, drwa.CarrierPrice{Source: qualSP279Source, Success: qualSP279Success, Completion: qualSP279Completion}, final.Price)

	// A registration of the next block pays the active schedule.
	_, err = metaStore.Commit()
	require.NoError(t, err)
	next, _, err := drwa.NewRegistryRegistration(metaStore, metaCoordinator, 4)
	require.NoError(t, err)
	require.NoError(t, next.SetCarrierFunding(funding))
	require.ErrorIs(t, next.RegisterToken(create("OTHER-abcdef", total)), drwa.ErrCarrierUnderfunded)
	require.NoError(t, next.RegisterToken(create("OTHER-abcdef", 10*total)))
}
