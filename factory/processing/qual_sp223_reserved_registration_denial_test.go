package processing

import (
	"bytes"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/block/preprocess"
	"github.com/multiversx/mx-chain-go/process/coordinator"
	processFactory "github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/process/factory/containers"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/process/smartContract/processorV2"
	"github.com/multiversx/mx-chain-go/process/smartContract/scrCommon"
	nativeValidation "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/testscommon"
	commonMocks "github.com/multiversx/mx-chain-go/testscommon/common"
	dataMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	"github.com/multiversx/mx-chain-go/testscommon/guardianMocks"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	storageMock "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/multiversx/mx-chain-go/txcache"
)

// SP2-23, audit finding TA-SP2-23-1-1. A public transaction that names a
// reserved registration function reaches the metachain in a miniblock of its
// sender's shard. Production here: the installed metachain system VM and its
// DRWA owner, the smart-contract processor, the metachain transaction
// processor, the transaction pool with the receipt source and the transaction
// preprocessor. Synthetic and labelled so: fee, gas, log and block-size
// collaborators, and the recorder of the results the processor emits.

type qualSP223DenialWorld struct {
	node *qualSP225Node
	pre  process.PreProcessor
	pool interface {
		AddData([]byte, interface{}, int, string)
	}
	results []data.TransactionHandler
	logs    []string
	hasher  interface{ Compute(string) []byte }
	codec   marshal.Marshalizer
}

func qualSP223Denial(t *testing.T, deployment bool) *qualSP223DenialWorld {
	t.Helper()
	w := &qualSP223DenialWorld{hasher: blake2b.NewBlake2b(), codec: &marshal.GogoProtoMarshalizer{}}
	if deployment {
		w.node = qualSP225MetaNode(t, true, qualSP225GenesisStore(t))
		require.NoError(t, w.node.owner.BeginExecution())
	} else {
		w.node = qualSP225MetaNode(t, false, integrationtests.CreateInMemoryShardAccountsDB())
	}
	vms := containers.NewVirtualMachinesContainer()
	require.NoError(t, vms.Add(processFactory.SystemVirtualMachine, w.node.system))
	shards, err := sharding.NewMultiShardCoordinator(3, core.MetachainShardId)
	require.NoError(t, err)
	converter := testscommon.NewPubkeyConverterMock(32)
	esdtParser, err := parsers.NewESDTTransferParser(w.codec)
	require.NoError(t, err)
	kinds, err := coordinator.NewTxTypeHandler(coordinator.ArgNewTxTypeHandler{
		PubkeyConverter: converter, ShardCoordinator: shards, BuiltInFunctions: vmBuiltins.NewBuiltInFunctionContainer(),
		ArgumentParser: parsers.NewCallArgsParser(), ESDTTransferParser: esdtParser, EnableEpochsHandler: qualSP225Flags(),
	})
	require.NoError(t, err)
	fees := &economicsmocks.EconomicsHandlerMock{
		ComputeTxFeeCalled: func(tx data.TransactionWithFeeHandler) *big.Int {
			return core.SafeMul(tx.GetGasLimit(), tx.GetGasPrice())
		},
		ComputeFeeForProcessingCalled: func(tx data.TransactionWithFeeHandler, gas uint64) *big.Int {
			return core.SafeMul(tx.GetGasPrice(), gas)
		},
		ComputeGasLimitCalled:     func(data.TransactionWithFeeHandler) uint64 { return 1 },
		MaxGasLimitPerBlockCalled: func(uint32) uint64 { return 1 << 40 },
		MaxGasLimitPerTxCalled:    func() uint64 { return 1 << 40 },
	}
	forwarder := &processMock.IntermediateTransactionHandlerMock{AddIntermediateTransactionsCalled: func(txs []data.TransactionHandler, _ []byte) error {
		w.results = append(w.results, txs...)
		return nil
	}}
	logs := &processMock.TxLogsProcessorStub{SaveLogCalled: func(_ []byte, _ data.TransactionHandler, entries []*vmcommon.LogEntry) error {
		for _, entry := range entries {
			w.logs = append(w.logs, string(entry.Identifier)+"|"+string(bytes.Join(entry.Topics, []byte{'|'})))
		}
		return nil
	}}
	contracts, err := processorV2.NewSmartContractProcessorV2(scrCommon.ArgsNewSmartContractProcessor{
		VmContainer: vms, ArgsParser: smartContract.NewArgumentParser(), Hasher: blake2b.NewBlake2b(), Marshalizer: w.codec,
		AccountsDB: w.node.user, BlockChainHook: w.node.hook, BuiltInFunctions: vmBuiltins.NewBuiltInFunctionContainer(),
		PubkeyConv: converter, ShardCoordinator: shards, ScrForwarder: forwarder, BadTxForwarder: forwarder,
		TxFeeHandler: &processMock.FeeAccumulatorStub{}, TxLogsProcessor: logs, EconomicsFee: fees,
		TxTypeHandler: kinds, GasHandler: &testscommon.GasHandlerStub{}, EnableEpochsHandler: qualSP225Flags(),
		EnableRoundsHandler: &testscommon.EnableRoundsHandlerStub{},
		GasSchedule:         w.node.pcf.gasSchedule, WasmVMChangeLocker: &sync.RWMutex{}, VMOutputCacher: txcache.NewDisabledCache(),
	})
	require.NoError(t, err)
	transactions, err := nativeValidation.NewMetaTxProcessor(nativeValidation.ArgsNewMetaTxProcessor{
		Hasher: blake2b.NewBlake2b(), Marshalizer: w.codec, Accounts: w.node.user, PubkeyConv: converter, ShardCoordinator: shards,
		ScProcessor: contracts, TxTypeHandler: kinds, EconomicsFee: fees, EnableEpochsHandler: qualSP225Flags(),
		GuardianChecker: &guardianMocks.GuardedAccountHandlerStub{}, TxVersionChecker: &testscommon.TxVersionCheckerStub{},
	})
	require.NoError(t, err)

	pool := dataMock.NewPoolsHolderMock().Transactions()
	if deployment {
		// As processComponents does on a DRWA node: the pool carries the
		// receipt source, so the reserved names take the native route.
		require.NoError(t, pool.(interface {
			ConfigureNativeValidationSource(*nativeValidation.NativeValidationSource) error
		}).ConfigureNativeValidationSource(w.node.pcf.drwaNativeValidationSource))
	}
	w.pool = pool
	w.pre, err = preprocess.NewTransactionPreprocessor(preprocess.ArgsTransactionPreProcessor{
		BasePreProcessorArgs: preprocess.BasePreProcessorArgs{
			DataPool: pool, Store: &storageMock.ChainStorerStub{}, Hasher: blake2b.NewBlake2b(), Marshalizer: w.codec,
			ShardCoordinator: shards, Accounts: w.node.user, AccountsProposal: w.node.user,
			OnRequestTransaction: func(uint32, [][]byte) {}, GasHandler: &processMock.GasHandlerMock{}, PubkeyConverter: converter,
			BlockSizeComputation: &testscommon.BlockSizeComputationStub{}, BalanceComputation: &testscommon.BalanceComputationStub{},
			ProcessedMiniBlocksTracker: &testscommon.ProcessedMiniBlocksTrackerStub{},
			TxExecutionOrderHandler:    &commonMocks.TxExecutionOrderHandlerStub{}, EconomicsFee: fees,
			EnableEpochsHandler: qualSP225Flags(), EnableRoundsHandler: &testscommon.EnableRoundsHandlerStub{},
			EpochNotifier: &epochNotifier.EpochNotifierStub{}, RoundNotifier: &epochNotifier.RoundNotifierStub{},
		},
		TxProcessor: transactions, BlockTracker: &processMock.BlockTrackerMock{}, BlockType: block.TxBlock, TxTypeHandler: kinds,
		ScheduledTxsExecutionHandler: &testscommon.ScheduledTxsExecutionStub{},
		TxCacheSelectionConfig: config.TxCacheSelectionConfig{SelectionGasBandwidthIncreasePercent: 400,
			SelectionGasBandwidthIncreaseScheduledPercent: 260, SelectionGasRequested: 10_000_000_000, SelectionMaxNumTxs: 30000,
			SelectionLoopDurationCheckInterval: 10},
		TxVersionCheckerHandler: &testscommon.TxVersionCheckerStub{},
	})
	require.NoError(t, err)
	return w
}

// qualSP223Sender is an account of execution shard 1.
func qualSP223Sender() []byte {
	sender := bytes.Repeat([]byte{7}, 32)
	sender[31] = 1
	return sender
}

// miniBlock puts the calls into the pool on the route from shard 1 to the
// metachain and returns the miniblock that carries them.
func (w *qualSP223DenialWorld) miniBlock(t *testing.T, value int64, calls ...string) *block.MiniBlock {
	t.Helper()
	mb := &block.MiniBlock{SenderShardID: 1, ReceiverShardID: core.MetachainShardId, Type: block.TxBlock}
	for nonce, call := range calls {
		tx := &transaction.Transaction{Nonce: uint64(nonce), SndAddr: qualSP223Sender(), RcvAddr: bytes.Clone(core.ESDTSCAddress),
			Value: big.NewInt(value), GasPrice: 1, GasLimit: 60_000_000, Data: []byte(call), ChainID: []byte("inert-chain"), Version: 1}
		encoded, err := w.codec.Marshal(tx)
		require.NoError(t, err)
		hash := w.hasher.Compute(string(encoded))
		w.pool.AddData(hash, tx, len(encoded), process.ShardCacherIdentifier(1, core.MetachainShardId))
		mb.TxHashes = append(mb.TxHashes, hash)
	}
	return mb
}

func (w *qualSP223DenialWorld) process(mb *block.MiniBlock) (int, error) {
	_, last, _, err := w.pre.ProcessMiniBlock(mb, func() bool { return true }, func() bool { return false }, false, false, -1,
		&testscommon.PreProcessorExecutionInfoHandlerMock{}, process.GasProcessingPolicy{})
	return last, err
}

// outcome is what the sender sees of the calls: the results sent back to its
// shard and the logs of the failed calls.
func (w *qualSP223DenialWorld) outcome(t *testing.T) []string {
	t.Helper()
	seen := append([]string{}, w.logs...)
	for _, result := range w.results {
		scr, ok := result.(*smartContractResult.SmartContractResult)
		require.True(t, ok)
		seen = append(seen, "result|"+string(scr.RcvAddr)+"|"+scr.Value.String()+"|"+string(scr.ReturnMessage))
	}
	return seen
}

// The miniblock that carries a reserved registration request is processed to
// its end. The request is answered as a failed call: the sender gets the error
// and its value back, nothing is registered, and the calls after it in the
// same miniblock are executed. Before this row's correction the metachain
// transaction processor returned an error for the request, and the miniblock
// stopped at that transaction on every attempt (run ta11_before in the lane's
// evidence).
func TestQualSP223ReservedRegistrationRequestIsAPlainDenial(t *testing.T) {
	for _, function := range []string{"DRWARegisterToken", "DRWARegisterBootstrapIntent"} {
		for _, shape := range []struct {
			name, arguments string
			value           int64
		}{{"bare", "", 0}, {"arguments", "@01@02", 0}, {"value", "@01@02", 5}} {
			t.Run(function+"/"+shape.name, func(t *testing.T) {
				calls := []string{function + shape.arguments, "unknownEndpoint@01", function + shape.arguments}
				// What a metachain node without DRWA does with the same miniblock.
				upstream := qualSP223Denial(t, false)
				last, err := upstream.process(upstream.miniBlock(t, shape.value, calls...))
				require.NoError(t, err)
				require.Equal(t, 2, last)
				expected := upstream.outcome(t)
				require.NotEmpty(t, expected)
				// The state a DRWA node keeps after three calls of a function the
				// contract does not have.
				control := qualSP223Denial(t, true)
				last, err = control.process(control.miniBlock(t, shape.value, "unknownEndpoint@01", "unknownEndpoint@01", "unknownEndpoint@01"))
				require.NoError(t, err)
				require.Equal(t, 2, last)
				controlRoot, err := control.node.user.RootHash()
				require.NoError(t, err)

				w := qualSP223Denial(t, true)
				for _, call := range calls {
					require.Equal(t, call != "unknownEndpoint@01", nativeValidation.RequiresDRWANativeValidationReceipt(
						&transaction.Transaction{RcvAddr: core.ESDTSCAddress, Data: []byte(call)}), "the reserved names take the native route")
				}
				last, err = w.process(w.miniBlock(t, shape.value, calls...))
				require.NoError(t, err, "the miniblock is not held back")
				require.Equal(t, 2, last, "every transaction of the miniblock is processed")
				seen := w.outcome(t)
				require.Len(t, seen, len(expected))
				// The reserved requests carry the denial; the call between them is
				// answered by the contract as on a node without DRWA.
				denial, denied := process.ErrTransactionNotExecutable.Error(), 0
				for i := range seen {
					if strings.HasSuffix(seen[i], "|"+denial) {
						seen[i] = strings.TrimSuffix(seen[i], denial) + "invalid method to call"
						denied++
					}
				}
				require.Equal(t, 2*len(expected)/3, denied)
				require.Equal(t, expected, seen, "apart from the message, the answer a node without DRWA gives to a call the contract does not serve")
				returned := 0
				for _, line := range seen {
					if strings.HasPrefix(line, "result|"+string(qualSP223Sender())+"|"+big.NewInt(shape.value).String()+"|") {
						returned++
					}
				}
				if shape.value != 0 {
					require.Equal(t, 3, returned, "each failed call returns its value to the sender")
				}
				after, err := w.node.user.RootHash()
				require.NoError(t, err)
				require.Equal(t, controlRoot, after, "nothing is registered and no value stays on the metachain")
				require.NoError(t, w.node.system.(interface{ DRWAExecutionError() error }).DRWAExecutionError())
				_, err = w.node.user.Commit()
				require.NoError(t, err)
				_, err = w.node.peer.Commit()
				require.NoError(t, err)
				require.NoError(t, w.node.owner.Committed())
				require.NoError(t, w.node.owner.BeginExecution(), "the next block starts")
			})
		}
	}
}
