package drwa

import (
	"math/big"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	blproc "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// SP2-24: a time consumer inside a real block-processing pass. The real shard
// or metachain processor runs ProcessBlockProposal with the consumer's real
// hook as its block-chain hook. The processor installs the header, the
// transaction-processing step of the pass runs the consumer, and the processor
// ends the evaluation when the pass returns. Everything else in the processor
// is the block package's own mock set.
type qualSP224Pass struct {
	ran      int
	captured *HeaderTimeContext
	inside   error // what the consumer returned inside the pass
	result   error // what ProcessBlockProposal returned
}

func qualSP224PassHeader(c *qualSP224Consumer, time uint64) data.HeaderHandler {
	header := c.headerAt(time)
	// The processors accept the block after their genesis only.
	_ = header.SetNonce(1)
	switch h := header.(type) {
	case *block.MetaBlockV3:
		h.LastExecutionResult = &block.MetaExecutionResultInfo{ExecutionResult: &block.BaseMetaExecutionResult{AccumulatedFeesInEpoch: big.NewInt(0), DevFeesInEpoch: big.NewInt(0)}}
	}
	return header
}

func qualSP224RunPass(t *testing.T, c *qualSP224Consumer, header data.HeaderHandler, wantContext bool) *qualSP224Pass {
	t.Helper()
	pass := &qualSP224Pass{}
	coordinator := &testscommon.TransactionCoordinatorMock{
		ProcessBlockTransactionCalled: func(executed data.HeaderHandler, _ *block.Body, _ func() time.Duration) error {
			pass.ran++
			require.Same(t, header, executed)
			context, err := c.hook.EvaluatedHeaderTimeContext()
			if wantContext {
				require.NoError(t, err, "the processor installed the block's context before execution")
				identity, locus := context.HeaderIdentity()
				expected, hashErr := c.identityOf(header)
				require.NoError(t, hashErr)
				require.Equal(t, expected, identity, "the context is the one of the block in execution")
				require.Equal(t, c.shard, locus)
				at, readErr := context.Milliseconds()
				require.NoError(t, readErr)
				require.EqualValues(t, header.GetTimeStamp(), at)
			} else {
				require.Error(t, err)
				require.Nil(t, context)
			}
			pass.captured = context
			pass.inside = c.run(context)
			return pass.inside
		},
	}
	shards := testscommon.NewMultiShardsCoordinatorMock(3)
	shards.CurrentShard = c.shard
	if c.shard == core.MetachainShardId {
		last := &block.MetaBlockV3{LastExecutionResult: &block.MetaExecutionResultInfo{ExecutionResult: &block.BaseMetaExecutionResult{AccumulatedFeesInEpoch: big.NewInt(0), DevFeesInEpoch: big.NewInt(0)}}}
		coreComponents, dataComponents, bootstrap, status := qualSP224BlockCreateMockComponentHolders()
		bootstrap.Coordinator = shards
		dataComponents.BlockChain = &testscommon.ChainHandlerStub{
			GetLastExecutionResultCalled: func() data.BaseExecutionResultHandler {
				return &block.MetaExecutionResult{ExecutionResult: &block.BaseMetaExecutionResult{AccumulatedFeesInEpoch: big.NewInt(10), DevFeesInEpoch: big.NewInt(10)}}
			},
			GetLastExecutedBlockHeaderCalled: func() data.HeaderHandler { return last },
		}
		args := qualSP224BlockCreateMockMetaArguments(coreComponents, dataComponents, bootstrap, status)
		args.BlockChainHook, args.TxCoordinator = c.hook, coordinator
		processor, err := blproc.NewMetaProcessor(args)
		require.NoError(t, err)
		_, pass.result = processor.ProcessBlockProposal(header, []byte("SP2-24 proposal"), &block.Body{})
		return pass
	}
	coreComponents, dataComponents, bootstrap, status := qualSP224BlockCreateComponentHolderMocks()
	bootstrap.Coordinator = shards
	args := qualSP224BlockCreateMockArguments(coreComponents, dataComponents, bootstrap, status)
	args.BlockChainHook, args.TxCoordinator = c.hook, coordinator
	processor, err := blproc.NewShardProcessor(args)
	require.NoError(t, err)
	_, pass.result = processor.ProcessBlockProposal(header, []byte("SP2-24 proposal"), &block.Body{})
	return pass
}

func qualSP224AllConsumers() map[string]func(t *testing.T) *qualSP224Consumer {
	one := func(build func(t *testing.T) (*qualSP224Consumer, *qualScopedFixture)) func(t *testing.T) *qualSP224Consumer {
		return func(t *testing.T) *qualSP224Consumer { c, _ := build(t); return c }
	}
	scoped := func(operation string) func(t *testing.T) *qualSP224Consumer {
		return one(func(t *testing.T) (*qualSP224Consumer, *qualScopedFixture) {
			return qualSP224ScopedConsumer(t, operation)
		})
	}
	gas := func(operation string) func(t *testing.T) *qualSP224Consumer {
		return func(t *testing.T) *qualSP224Consumer { c, _, _ := qualSP224GASConsumer(t, operation); return c }
	}
	f06 := func(operation string) func(t *testing.T) *qualSP224Consumer {
		return func(t *testing.T) *qualSP224Consumer { c, _ := qualSP224F06Consumer(t, operation); return c }
	}
	return map[string]func(t *testing.T) *qualSP224Consumer{
		"scoped_install": scoped("install"), "scoped_admit": scoped("admit"), "scoped_withdraw": scoped("withdraw"), "scoped_read": scoped("read"),
		"gas_initialize": gas("initialize"), "gas_propose": gas("propose"), "gas_authorize": gas("authorize"), "gas_start": gas("start"), "gas_cleanup": gas("cleanup"),
		"f06_install": f06("install"), "f06_consume": f06("consume"), "f06_close_expired": f06("close_expired"),
		"registration_creation": func(t *testing.T) *qualSP224Consumer { return qualSP224RegistrationConsumer(t, "creation", 1) },
		"registration_retain":   func(t *testing.T) *qualSP224Consumer { return qualSP224RegistrationConsumer(t, "retain_intent", 1) },
		"cancellation":          func(t *testing.T) *qualSP224Consumer { c, _ := qualSP224CancellationConsumer(t); return c },
		"native_call":           qualSP224NativeCallConsumer,
		"bootstrap_proof":       qualSP224BootstrapProofConsumer,
		"current_lifecycle":     qualSP224LifecycleConsumer,
		"setup_initialization":  qualSP224SetupConsumer,
		"supply_operation":      qualSP224SupplyConsumer,
		"authority_check": func(t *testing.T) *qualSP224Consumer {
			return qualSP224AuthorityConsumer(t, qualSP227Rosters(t), scopedEmergencyAdd, scopedDirect,
				[]scopedAuthorityRequirement{qualSP227Want(scopedEA, "add", scopedCurrent)})
		},
	}
}

func TestQualSP224EveryConsumerInsideARealBlockProcessingPass(t *testing.T) {
	shardPasses, metaPasses := 0, 0
	for name, build := range qualSP224AllConsumers() {
		t.Run(name+"/the_block_in_execution", func(t *testing.T) {
			c := build(t)
			header := qualSP224PassHeader(c, c.at)
			pass := qualSP224RunPass(t, c, header, true)
			require.Equal(t, 1, pass.ran)
			require.NoError(t, pass.inside, "the consumer read the block's context and acted")
			require.NoError(t, pass.result)
			if c.shard == core.MetachainShardId {
				metaPasses++
			} else {
				shardPasses++
			}
			// The context ended with the block.
			_, err := pass.captured.Milliseconds()
			require.ErrorIs(t, err, ErrInactiveHeaderTime)
			_, err = c.hook.EvaluatedHeaderTimeContext()
			require.ErrorIs(t, err, ErrInactiveHeaderTime)
		})
		t.Run(name+"/after_the_block", func(t *testing.T) {
			// A pass whose execution step does nothing; afterwards the consumer
			// is run with the context that pass had.
			c := build(t)
			idle := *c
			idle.run = func(*HeaderTimeContext) error { return nil }
			pass := qualSP224RunPass(t, &idle, qualSP224PassHeader(c, c.at), true)
			require.NoError(t, pass.result)
			root, journal := qualSP224State(t, c.store)
			require.Error(t, c.run(pass.captured))
			after, afterJournal := qualSP224State(t, c.store)
			require.Equal(t, root, after)
			require.Equal(t, journal, afterJournal)
		})
		t.Run(name+"/block_before_supernova_activation", func(t *testing.T) {
			c := build(t)
			header := qualSP224PassHeader(c, c.at)
			require.NoError(t, header.SetEpoch(header.GetEpoch()-1))
			require.NoError(t, c.hook.SetEpochStartHeader(header))
			root, journal := qualSP224State(t, c.store)
			pass := qualSP224RunPass(t, c, header, false)
			require.Equal(t, 1, pass.ran)
			require.Error(t, pass.inside)
			require.ErrorIs(t, pass.result, pass.inside, "the refusal is the block's execution error")
			after, afterJournal := qualSP224State(t, c.store)
			require.Equal(t, root, after)
			require.Equal(t, journal, afterJournal)
		})
	}
	require.NotZero(t, shardPasses, "at least one consumer ran in a shard processor")
	require.NotZero(t, metaPasses, "at least one consumer ran in the metachain processor")
	t.Logf("SP2-24 consumers inside a real pass: shard %d, metachain %d", shardPasses, metaPasses)
}

// The bounds again, with the header time coming from the block the processor
// executes: F06 on the shard, the governed-action start on the metachain.
func TestQualSP224BoundsInsideARealBlockProcessingPass(t *testing.T) {
	for _, row := range []struct {
		name     string
		build    func(t *testing.T) *qualSP224Consumer
		admitted map[uint64]bool
	}{
		{"shard_f06_debit_before_expiry", func(t *testing.T) *qualSP224Consumer { c, _ := qualSP224F06Consumer(t, "consume"); return c }, map[uint64]bool{111: true, 112: false, 113: false}},
		{"shard_f06_close_at_expiry", func(t *testing.T) *qualSP224Consumer { c, _ := qualSP224F06Consumer(t, "close_expired"); return c }, map[uint64]bool{111: false, 112: true}},
		{"meta_gas_start_window", func(t *testing.T) *qualSP224Consumer { c, _, _ := qualSP224GASConsumer(t, "start"); return c }, map[uint64]bool{104: false, 105: true, 119: true, 120: false}},
		{"meta_scoped_admission_expiry", func(t *testing.T) *qualSP224Consumer { c, _ := qualSP224ScopedConsumer(t, "read"); return c }, map[uint64]bool{200: true, 201: false}},
	} {
		for at, admitted := range row.admitted {
			c := row.build(t)
			root, journal := qualSP224State(t, c.store)
			pass := qualSP224RunPass(t, c, qualSP224PassHeader(c, at), true)
			require.Equal(t, 1, pass.ran, row.name)
			if admitted {
				require.NoError(t, pass.result, "%s at %d", row.name, at)
				continue
			}
			require.Error(t, pass.inside, "%s at %d", row.name, at)
			require.ErrorIs(t, pass.result, pass.inside)
			after, afterJournal := qualSP224State(t, c.store)
			require.Equal(t, root, after, "%s at %d", row.name, at)
			require.Equal(t, journal, afterJournal)
		}
	}
}
