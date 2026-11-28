package processorV2

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/batch"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
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

const qualSP232Token = "REGUL-0a1b2c"

var qualSP232Domain = []byte("sp232 processor domain")

type qualSP232Prices struct{}

func (p *qualSP232Prices) IsInterfaceNil() bool { return p == nil }
func (p *qualSP232Prices) CarrierPrice(string) (drwa.CarrierPrice, error) {
	return drwa.CarrierPrice{Source: 1000, Destination: 20000, Success: 500, Refund: 900, Completion: 30000}, nil
}

type qualSP232Block struct{}

func (b *qualSP232Block) IsInterfaceNil() bool { return b == nil }
func (b *qualSP232Block) ExecutingBlock() ([]byte, []byte, uint32, error) {
	return []byte("block"), []byte("header"), 4, nil
}

type qualSP232Evidence struct{}

func (e *qualSP232Evidence) IsInterfaceNil() bool { return e == nil }
func (e *qualSP232Evidence) ReadFinalItem(uint32, []byte, []byte) ([]byte, []byte, error) {
	return nil, nil, errors.New("no evidence in this test")
}

type qualSP232Binding struct{}

func (b *qualSP232Binding) IsInterfaceNil() bool                     { return b == nil }
func (b *qualSP232Binding) VerifyAdminEffect(drwa.AdminEffect) error { return nil }

func qualSP232Frame(t *testing.T, fields ...[]byte) []byte {
	t.Helper()
	raw, err := (&marshal.GogoProtoMarshalizer{}).Marshal(batch.New(fields...))
	require.NoError(t, err)
	return raw
}

// qualSP232RolesState is the independently computed state hash of a holder's
// role and latest-nonce items of the token.
func qualSP232RolesState(t *testing.T, holder, roles []byte) []byte {
	t.Helper()
	return blake2b.NewBlake2b().Compute(string(qualSP232Frame(t, []byte("DRWA/ADMIN/STATE/candidate1"), qualSP232Domain, holder,
		[]byte(core.ProtectedKeyPrefix+core.ESDTRoleIdentifier+core.ESDTKeyIdentifier+qualSP232Token), roles,
		[]byte(core.ProtectedKeyPrefix+core.ESDTNFTLatestNonceIdentifier+qualSP232Token), nil)))
}

// SP2-32 through the native result processor on both sides, with no change to
// it (Part A, hostile producer requirement: "through the actual supported
// VM/processor encoding"):
//
//  1. the metachain processor turns the output of the origin owner into one
//     asynchronous-call result for the target shard, carrying the envelope;
//  2. the shard's processor executes that result as a built-in call, the role
//     is granted once by the native role built-in, and the processor itself
//     creates the callback with the gas the retained destination work left;
//  3. the same result again changes no state;
//  4. the same data in a result whose sender is a contract, or in a user
//     transaction, grants nothing; a result that lost its data (R01.08) calls
//     nothing.
func TestQualSP232AdminLegThroughTheNativeResultProcessor(t *testing.T) {
	const shard = uint32(1)
	system := bytes.Clone(core.SystemAccountAddress)
	system[len(system)-1] = uint8(shard)
	holder := bytes.Repeat([]byte{7}, 32)
	holder[31] = uint8(shard)
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

	// The metachain store: the system account with the retained budget record.
	metaStore := integrationtests.CreateInMemoryShardAccountsDB()
	account, err := metaStore.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	budgetKey := []byte(core.ProtectedKeyPrefix + "DRWA@scopedAdmission@budget")
	budget := binary.BigEndian.AppendUint64(nil, 1)
	budget = binary.BigEndian.AppendUint64(budget, uint64(len(budgetKey)+32))
	budget = binary.BigEndian.AppendUint64(budget, 4)
	budget = binary.BigEndian.AppendUint64(budget, 0)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(budgetKey, budget))
	require.NoError(t, metaStore.SaveAccount(account))
	_, err = metaStore.Commit()
	require.NoError(t, err)
	limits := drwa.RegistrationResourceLimits{Records: 1000, RetainedBytes: 1 << 30, NewRecordsPerEpoch: 1000}
	marshaller, hasher := &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b()
	domain := func() []byte { return qualSP232Domain }
	funding, err := drwa.NewCarrierFunding(drwa.ArgsCarrierFunding{Accounts: metaStore, Marshaller: marshaller, Hasher: hasher,
		Block: &qualSP232Block{}, Prices: &qualSP232Prices{}, Limits: limits, RecordBytes: 4096})
	require.NoError(t, err)
	effects, err := drwa.NewAdminEffects(drwa.ArgsAdminEffects{Accounts: metaStore, Marshaller: marshaller, Hasher: hasher,
		Domain: domain, Funding: funding, Block: &qualSP232Block{}, Evidence: &qualSP232Evidence{}, Limits: limits,
		RecordBytes: 4096, Shards: 3})
	require.NoError(t, err)
	role := []byte(core.ESDTRoleLocalMint)
	granted := append([]byte{0x0a, byte(len(role))}, role...)
	output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}
	const legGas = uint64(20000 + 900 + 30000)
	effectID, remaining, err := effects.Open(output, drwa.AdminEffectRequest{Operation: "DRWAApplyTokenAdmin",
		Origin: hasher.Compute("protected origin execution"), TokenID: []byte(qualSP232Token), TokenType: []byte(core.FungibleESDT),
		Binding: "CURRENT_CEB", Epoch: 2,
		Payload: []byte(core.BuiltInFunctionSetESDTRole + "@" + hex.EncodeToString([]byte(qualSP232Token)) + "@" + hex.EncodeToString(role)),
		Legs: []drwa.AdminEffectLeg{{Shard: shard, Target: holder, Predecessor: qualSP232RolesState(t, holder, nil),
			Result: qualSP232RolesState(t, holder, granted)}}}, 1000+legGas+7)
	require.NoError(t, err)
	require.Equal(t, uint64(7), remaining)

	// 1. The metachain side.
	metaCoordinator, err := sharding.NewMultiShardCoordinator(3, core.MetachainShardId)
	require.NoError(t, err)
	metaArguments := createMockSmartContractProcessorArguments()
	metaArguments.ShardCoordinator = metaCoordinator
	metaArguments.ArgsParser = parser
	metaArguments.TxTypeHandler = txTypes(metaCoordinator, builtInFunctions.NewBuiltInFunctionContainer())
	meta, err := NewSmartContractProcessorV2(metaArguments)
	require.NoError(t, err)
	opening := &transaction.Transaction{SndAddr: bytes.Repeat([]byte{9}, 32), RcvAddr: bytes.Clone(core.ESDTSCAddress),
		Value: big.NewInt(0), GasLimit: 10 * legGas, GasPrice: 1, Data: []byte("protected operation")}
	_, results, err := meta.processSCOutputAccounts(&vmcommon.VMInput{CallType: vmData.DirectCall}, output, opening, []byte("protected operation"))
	require.NoError(t, err)
	require.Len(t, results, 1, "one result for the one target")
	leg := results[0].(*smartContractResult.SmartContractResult)
	require.Equal(t, core.ESDTSCAddress, leg.SndAddr)
	require.Equal(t, system, leg.RcvAddr)
	require.Equal(t, vmData.AsynchronousCall, leg.CallType)
	require.Equal(t, legGas, leg.GasLimit)
	require.Zero(t, leg.Value.Sign())
	require.True(t, bytes.HasPrefix(leg.Data, []byte(drwa.AdminEffectFunctionName+"@")))
	retained, err := effects.Leg(effectID, 0)
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(leg.Data, []byte(drwa.AdminEffectFunctionName+"@"+hex.EncodeToString(retained)+"@")),
		"the result carries the retained envelope, then the native call identifiers")

	// 2. The shard side.
	shardCoordinator, err := sharding.NewMultiShardCoordinator(3, shard)
	require.NoError(t, err)
	require.Equal(t, shard, shardCoordinator.ComputeId(holder))
	store := integrationtests.CreateInMemoryShardAccountsDB()
	registry, err := drwa.NewShardRegistry(store, shard)
	require.NoError(t, err)
	require.NoError(t, registry.BeginExecution())
	_, err = registry.DeltaFunction().ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{CallerAddr: core.ESDTSCAddress, CallValue: big.NewInt(0), CallType: vmData.AsynchronousCall,
			Arguments: [][]byte{[]byte(qualSP232Token), make([]byte, 8)}},
		RecipientAddr: system, Function: drwa.RegistryDeltaFunctionName})
	require.NoError(t, err)
	_, err = store.Commit()
	require.NoError(t, err)
	require.NoError(t, registry.Committed())
	shardBuiltIns := builtInFunctions.NewBuiltInFunctionContainer()
	setRole, err := builtInFunctions.NewESDTRolesFunc(marshaller, true)
	require.NoError(t, err)
	require.NoError(t, shardBuiltIns.Add(core.BuiltInFunctionSetESDTRole, setRole))
	function, err := drwa.NewAdminEffectFunction(drwa.ArgsAdminEffectFunction{Accounts: store, Marshaller: marshaller, Hasher: hasher,
		Classifier: registry, BuiltIns: shardBuiltIns, Shard: shard, ShardOf: shardCoordinator.ComputeId, Domain: domain, RecordBytes: 4096})
	require.NoError(t, err)
	require.NoError(t, function.SetBindingSource(&qualSP232Binding{}))
	require.NoError(t, shardBuiltIns.Add(drwa.AdminEffectFunctionName, function))
	shardTypes := txTypes(shardCoordinator, shardBuiltIns)
	kind, atDestination, _ := shardTypes.ComputeTransactionType(leg)
	require.Equal(t, process.BuiltInFunctionCall, kind, "the shard executes the leg as a built-in call")
	require.Equal(t, process.BuiltInFunctionCall, atDestination)

	var created []data.TransactionHandler
	calls := 0
	arguments := createMockSmartContractProcessorArguments()
	arguments.AccountsDB = store
	arguments.ShardCoordinator = shardCoordinator
	arguments.ArgsParser = parser
	arguments.BuiltInFunctions = shardBuiltIns
	arguments.TxTypeHandler = shardTypes
	arguments.BlockChainHook = &testscommon.BlockChainHookStub{
		ProcessBuiltInFunctionCalled: func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
			calls++
			require.Equal(t, drwa.AdminEffectFunctionName, input.Function)
			return function.ProcessBuiltinFunction(nil, nil, input)
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
	deliver := func(result *smartContractResult.SmartContractResult) []*smartContractResult.SmartContractResult {
		created = nil
		_, processErr := sc.ProcessSmartContractResult(result)
		require.NoError(t, processErr)
		var toMetachain []*smartContractResult.SmartContractResult
		for _, tx := range created {
			if shardCoordinator.ComputeId(tx.GetRcvAddr()) == core.MetachainShardId {
				toMetachain = append(toMetachain, tx.(*smartContractResult.SmartContractResult))
			}
		}
		return toMetachain
	}
	roles := func() []byte {
		loaded, loadErr := store.LoadAccount(holder)
		require.NoError(t, loadErr)
		value, _, _ := loaded.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(
			[]byte(core.ProtectedKeyPrefix + core.ESDTRoleIdentifier + core.ESDTKeyIdentifier + qualSP232Token))
		return value
	}
	// root is the state the leg can change: the data of the shard's system
	// account (the applied-leg item, the settings) and the holder's roles. The
	// native processor's own bookkeeping of a failed result is not part of it.
	root := func() []byte {
		_, commitErr := store.Commit()
		require.NoError(t, commitErr)
		loaded, loadErr := store.LoadAccount(core.SystemAccountAddress)
		require.NoError(t, loadErr)
		return append(bytes.Clone(loaded.(vmcommon.UserAccountHandler).GetRootHash()), roles()...)
	}

	// 4, first: copies of the canonical data grant nothing.
	before := root()
	contract := append(make([]byte, 8), bytes.Repeat([]byte{5}, 24)...)
	contract[31] = 2
	copied := *leg
	copied.SndAddr = contract
	callbacks := deliver(&copied)
	require.Equal(t, 1, calls, "the processor hands the copy to the function, which refuses it")
	require.Equal(t, before, root())
	require.Empty(t, roles())
	for _, callback := range callbacks {
		require.False(t, bytes.HasPrefix(callback.Data, []byte("@00@")), "no successful outcome leaves the shard")
	}
	userTransaction := &transaction.Transaction{SndAddr: bytes.Repeat([]byte{3}, 32), RcvAddr: system, Value: big.NewInt(0),
		GasLimit: legGas, GasPrice: 1, Data: bytes.Clone(leg.Data)}
	kind, _, _ = shardTypes.ComputeTransactionType(userTransaction)
	require.Equal(t, process.BuiltInFunctionCall, kind)
	input, err := sc.createVMCallInput(userTransaction, []byte("user transaction hash"), true)
	require.NoError(t, err)
	_, err = function.ProcessBuiltinFunction(nil, nil, input)
	require.ErrorIs(t, err, drwa.ErrInvalidAdminEffect, "the call the processor builds from a user transaction is not the protected result")
	require.Equal(t, before, root())
	lost := *leg
	lost.Data = nil
	calls = 0
	deliver(&lost)
	require.Zero(t, calls, "a result without data calls no built-in")
	require.Equal(t, before, root())
	require.Empty(t, roles())

	// 2. The canonical leg: one grant, and the native callback with the gas
	// the retained destination work left.
	callbacks = deliver(leg)
	require.Equal(t, granted, roles())
	applied := root()
	require.Len(t, callbacks, 1, "one result leaves for the metachain")
	require.Equal(t, system, callbacks[0].SndAddr)
	require.Equal(t, core.ESDTSCAddress, callbacks[0].RcvAddr)
	require.Equal(t, vmData.AsynchronousCallBack, callbacks[0].CallType)
	require.Equal(t, legGas-20000, callbacks[0].GasLimit)
	require.True(t, bytes.HasPrefix(callbacks[0].Data, []byte("@00@"+hex.EncodeToString(effectID)+"@")),
		"the outcome names the effect and the leg")

	// 3. The same leg again: no second mutation, the same outcome.
	again := deliver(leg)
	require.Equal(t, applied, root())
	require.Equal(t, granted, roles())
	require.Len(t, again, 1)
	require.Equal(t, callbacks[0].Data, again[0].Data)
	require.Equal(t, callbacks[0].GasLimit, again[0].GasLimit)

	// A leg whose carrier brought less than the retained destination work is
	// refused: nothing is applied and no successful outcome leaves.
	short := *leg
	short.GasLimit = 19999
	storeBefore := root()
	for _, callback := range deliver(&short) {
		require.False(t, bytes.HasPrefix(callback.Data, []byte("@00@")))
	}
	require.Equal(t, storeBefore, root())
}
