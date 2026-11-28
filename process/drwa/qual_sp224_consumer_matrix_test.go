package drwa

import (
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/stretchr/testify/require"
)

// SP2-24 (Part A N-02/M-04): every time consumer, through its real function,
// with the context of the actual block-chain hook. A consumer is described by
// the hook it is bound to, a header time at which its operation is admitted and
// a function that runs the operation with a given context. Proof, authority and
// funding hosts stay the synthetic fixtures of the consumer's own tests: these
// cases prove what the consumer does with time, nothing else.
type qualSP224Store interface {
	RootHash() ([]byte, error)
	JournalLen() int
}

type qualSP224Consumer struct {
	hook  *hooks.BlockChainHookImpl
	shard uint32
	store qualSP224Store
	at    uint64
	// run executes the operation. ownLookup marks a consumer that reads the
	// context from its bound source itself and ignores the argument.
	run       func(*HeaderTimeContext) error
	ownLookup bool
	// header builds the consumer's block header for a time; nil means the
	// common synthetic V3 header of the T42 fixtures.
	header func(time uint64) data.HeaderHandler
	// identity computes the header identity as this consumer's hook does; nil
	// means the proto marshaller and Blake2b of the T42 hook fixture.
	identity func(data.HeaderHandler) ([]byte, error)
}

func (c *qualSP224Consumer) identityOf(header data.HeaderHandler) ([]byte, error) {
	if c.identity != nil {
		return c.identity(header)
	}
	return core.CalculateHash(&marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), header)
}

func (c *qualSP224Consumer) headerAt(time uint64) data.HeaderHandler {
	if c.header != nil {
		return c.header(time)
	}
	return qualT42Header(c.shard, time)
}

// qualSP224Begin installs one header as the block processor does and returns
// the context the hook then exposes (nil with the hook's error when it exposes
// none) and the end of that evaluation.
func qualSP224Begin(t *testing.T, hook *hooks.BlockChainHookImpl, header data.HeaderHandler) (*HeaderTimeContext, func(), error) {
	t.Helper()
	install, end, err := hook.BeginDRWAHeaderEvaluation()
	require.NoError(t, err)
	t.Cleanup(end)
	require.NoError(t, install(header))
	context, err := hook.EvaluatedHeaderTimeContext()
	return context, end, err
}

func qualSP224State(t *testing.T, store qualSP224Store) ([]byte, int) {
	t.Helper()
	root, err := store.RootHash()
	require.NoError(t, err)
	return root, store.JournalLen()
}

// qualSP224Refusals runs the operation under every context that is not the
// evaluated header of the block in execution, and then once under a valid one.
// build must return a fresh consumer with no evaluation active.
func qualSP224Refusals(t *testing.T, build func(t *testing.T) *qualSP224Consumer) {
	t.Helper()
	refused := func(t *testing.T, c *qualSP224Consumer, context *HeaderTimeContext) {
		t.Helper()
		root, journal := qualSP224State(t, c.store)
		require.Error(t, c.run(context))
		after, afterJournal := qualSP224State(t, c.store)
		require.Equal(t, root, after, "a refused operation changes no state")
		require.Equal(t, journal, afterJournal)
	}
	t.Run("no_evaluation_begun", func(t *testing.T) {
		c := build(t)
		_, err := c.hook.EvaluatedHeaderTimeContext()
		require.ErrorIs(t, err, ErrInactiveHeaderTime)
		refused(t, c, nil)
	})
	t.Run("ended", func(t *testing.T) {
		c := build(t)
		context, end, err := qualSP224Begin(t, c.hook, c.headerAt(c.at))
		require.NoError(t, err)
		end()
		refused(t, c, context)
	})
	t.Run("raw_installation", func(t *testing.T) {
		// The same header installed by the plain setter, without an owning
		// evaluation, issues no context: an accessor is not a time source.
		c := build(t)
		require.NoError(t, c.hook.SetCurrentHeader(c.headerAt(c.at)))
		require.Equal(t, c.at, c.hook.CurrentTimeStampMs())
		_, err := c.hook.EvaluatedHeaderTimeContext()
		require.ErrorIs(t, err, ErrInactiveHeaderTime)
		refused(t, c, nil)
	})
	t.Run("replaced_by_raw_installation", func(t *testing.T) {
		c := build(t)
		context, _, err := qualSP224Begin(t, c.hook, c.headerAt(c.at))
		require.NoError(t, err)
		require.NoError(t, c.hook.SetCurrentHeader(c.headerAt(c.at)))
		refused(t, c, context)
	})
	t.Run("replaced_by_the_next_block", func(t *testing.T) {
		if build(t).ownLookup {
			t.Skip("the consumer holds no context between blocks; it reads the next block's own context")
		}
		c := build(t)
		context, end, err := qualSP224Begin(t, c.hook, c.headerAt(c.at))
		require.NoError(t, err)
		end()
		// Another block, even with the same time, is another context.
		next := c.headerAt(c.at)
		require.NoError(t, next.SetNonce(next.GetNonce()+1))
		current, _, err := qualSP224Begin(t, c.hook, next)
		require.NoError(t, err)
		require.NotSame(t, context, current)
		refused(t, c, context)
		_, err = current.Milliseconds()
		require.NoError(t, err, "the refusal left the current block's context intact")
	})
	t.Run("before_supernova_activation", func(t *testing.T) {
		c := build(t)
		header := c.headerAt(c.at)
		require.NotZero(t, header.GetEpoch())
		require.NoError(t, header.SetEpoch(header.GetEpoch()-1))
		require.NoError(t, c.hook.SetEpochStartHeader(header))
		context, _, err := qualSP224Begin(t, c.hook, header)
		require.ErrorIs(t, err, ErrUnavailableHeaderTime)
		require.Nil(t, context)
		// Before activation the header field holds seconds. The ordinary accessor
		// still answers, with its own conversion; it is not the typed view.
		require.Equal(t, c.at*1000, c.hook.CurrentTimeStampMs())
		refused(t, c, nil)
	})
	t.Run("legacy_header", func(t *testing.T) {
		c := build(t)
		epoch := c.headerAt(c.at).GetEpoch()
		var header data.HeaderHandler = &block.Header{Epoch: epoch, ShardID: c.shard, TimeStamp: c.at}
		if c.shard == core.MetachainShardId {
			header = &block.MetaBlock{Epoch: epoch, TimeStamp: c.at}
		}
		context, _, err := qualSP224Begin(t, c.hook, header)
		require.Error(t, err)
		require.Nil(t, context)
		refused(t, c, nil)
	})
	t.Run("header_time_zero", func(t *testing.T) {
		// Owner decision SP2-24 D-1 (b): the header is installed natively and
		// the ordinary accessor answers; the typed view gives no context.
		c := build(t)
		header := c.headerAt(0)
		context, _, err := qualSP224Begin(t, c.hook, header)
		require.ErrorIs(t, err, ErrUnavailableHeaderTime)
		require.Nil(t, context)
		require.Equal(t, uint64(0), c.hook.CurrentTimeStampMs())
		require.Equal(t, header.GetRound(), c.hook.CurrentRound())
		refused(t, c, nil)
	})
	t.Run("context_of_another_hook", func(t *testing.T) {
		if probe := build(t); probe.ownLookup {
			t.Skip("the consumer accepts no context from its caller")
		}
		c := build(t)
		_, _, err := qualSP224Begin(t, c.hook, c.headerAt(c.at))
		require.NoError(t, err)
		other, _ := qualT42Hook(t, qualRegistrationStore(t, 0), c.shard, true)
		foreign, _, err := qualSP224Begin(t, other, c.headerAt(c.at))
		require.NoError(t, err)
		refused(t, c, foreign)
	})
	t.Run("context_of_a_free_clock", func(t *testing.T) {
		if probe := build(t); probe.ownLookup {
			t.Skip("the consumer accepts no context from its caller")
		}
		c := build(t)
		_, _, err := qualSP224Begin(t, c.hook, c.headerAt(c.at))
		require.NoError(t, err)
		free := qualHeaderTimeOwner(t)
		foreign, err := free.Begin(c.headerAt(c.at))
		require.NoError(t, err)
		refused(t, c, foreign)
	})
	t.Run("the_block_in_execution", func(t *testing.T) {
		c := build(t)
		context, _, err := qualSP224Begin(t, c.hook, c.headerAt(c.at))
		require.NoError(t, err)
		require.NoError(t, c.run(context), "control: only the context differs from the refusals above")
	})
}

func qualSP224ScopedConsumer(t *testing.T, operation string) (*qualSP224Consumer, *qualScopedFixture) {
	t.Helper()
	f := qualScopedNew(t)
	hook, _ := qualT42Hook(t, f.store, core.MetachainShardId, true)
	var err error
	f.records, err = newScopedAdmissionRecords(f.store, f.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"),
		scopedAdmissionLimits{4096, 100, 1 << 20, 100}, f.mandates, hook)
	require.NoError(t, err)
	c := &qualSP224Consumer{hook: hook, shard: core.MetachainShardId, store: f.store, at: 100}
	if operation != "install" {
		context, end := qualT42Install(t, hook, core.MetachainShardId, 100)
		f.context = context
		f.enroll(t)
		if operation != "admit" {
			f.admit(t)
		}
		end()
	}
	switch operation {
	case "install":
		c.run = func(context *HeaderTimeContext) error {
			return f.records.install(context, f.d.owner, f.d.program, nil, f.versionBody, f.mandates.proof("ENROLL", nil, f.d.authority))
		}
	case "admit":
		c.run = func(context *HeaderTimeContext) error {
			return f.records.admit(context, f.d, f.mandates.proof("ADMISSION", f.d.authority, qualScopedHash("ADMISSION", f.body())))
		}
	case "withdraw":
		c.run = func(context *HeaderTimeContext) error { return f.records.withdraw(context, f.d, f.withdrawProof()) }
	default:
		c.run = func(context *HeaderTimeContext) error { return f.checkDecision(context, f.d) }
	}
	return c, f
}

func qualSP224GASConsumer(t *testing.T, operation string) (*qualSP224Consumer, *qualGovernedActionFixture, []byte) {
	t.Helper()
	f := qualGovernedActionNew(t)
	hook, _ := qualT42Hook(t, f.s, core.MetachainShardId, true)
	var err error
	f.g, err = newGovernedActionRecords(f.s, f.o, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, []byte("n"), 4, 2, 2, f.h, hook)
	require.NoError(t, err)
	c := &qualSP224Consumer{hook: hook, shard: core.MetachainShardId, store: f.s, at: 100}
	envelope, _, id := f.expected(100)
	f.h.envelope = envelope
	if operation == "initialize" {
		c.run = func(context *HeaderTimeContext) error {
			return f.g.initialize(context, f.p.subject, f.p.class, f.p.token)
		}
		return c, f, id
	}
	context, end := qualT42Install(t, hook, core.MetachainShardId, 100)
	f.x = context
	f.initialize(t)
	if operation == "propose" {
		end()
		c.run = func(context *HeaderTimeContext) error { _, e := f.g.propose(context, f.p); return e }
		return c, f, id
	}
	require.Equal(t, id, f.propose(t))
	end()
	switch operation {
	case "authorize":
		c.at = 105
		c.run = func(context *HeaderTimeContext) error {
			return f.g.authorize(context, id, []byte("synthetic-full-authorize"))
		}
	case "start":
		context, end = qualT42Install(t, hook, core.MetachainShardId, 105)
		require.NoError(t, f.g.authorize(context, id, []byte("synthetic-full-authorize")))
		end()
		c.at = 105
		c.run = func(context *HeaderTimeContext) error {
			return f.g.start(context, id, []byte("synthetic-current-start"))
		}
	default: // cleanup of an expired action
		c.at = 120
		c.run = func(context *HeaderTimeContext) error {
			return f.g.cleanup(context, id, "EXPIRED", []byte("synthetic-no-irreversible-proof"))
		}
	}
	return c, f, id
}

func qualSP224F06Consumer(t *testing.T, operation string) (*qualSP224Consumer, *qualSourceGrantFixture) {
	t.Helper()
	f := qualSourceGrantNew(t)
	hook, _ := qualT42Hook(t, f.store, 1, true)
	var err error
	f.records, err = newSourceGrantRecords(f.store, f.owner, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, 1, f.host, hook)
	require.NoError(t, err)
	c := &qualSP224Consumer{hook: hook, shard: 1, store: f.store, at: 111}
	if operation == "install" {
		c.run = func(context *HeaderTimeContext) error {
			return f.records.install(context, f.p, []byte("synthetic-canonical-proof"))
		}
		return c, f
	}
	context, end := qualT42Install(t, hook, 1, 111)
	f.context = context
	f.install(t)
	end()
	if operation == "consume" {
		c.run = func(context *HeaderTimeContext) error { f.context = context; return f.consume() }
		return c, f
	}
	c.at = 112
	c.run = func(context *HeaderTimeContext) error { f.context = context; return f.close("EXPIRED") }
	return c, f
}

func TestQualSP224ScopedAdmissionRefusesEveryOtherContext(t *testing.T) {
	for _, operation := range []string{"install", "admit", "withdraw", "read"} {
		t.Run(operation, func(t *testing.T) {
			qualSP224Refusals(t, func(t *testing.T) *qualSP224Consumer { c, _ := qualSP224ScopedConsumer(t, operation); return c })
		})
	}
}

func TestQualSP224GovernedActionRefusesEveryOtherContext(t *testing.T) {
	for _, operation := range []string{"initialize", "propose", "authorize", "start", "cleanup"} {
		t.Run(operation, func(t *testing.T) {
			qualSP224Refusals(t, func(t *testing.T) *qualSP224Consumer { c, _, _ := qualSP224GASConsumer(t, operation); return c })
		})
	}
}

func TestQualSP224SourceGrantRefusesEveryOtherContext(t *testing.T) {
	for _, operation := range []string{"install", "consume", "close_expired"} {
		t.Run(operation, func(t *testing.T) {
			qualSP224Refusals(t, func(t *testing.T) *qualSP224Consumer { c, _ := qualSP224F06Consumer(t, operation); return c })
		})
	}
}

// qualSP224Bound runs one consumer operation at one header time.
func qualSP224At(t *testing.T, c *qualSP224Consumer, time uint64) error {
	t.Helper()
	context, end, err := qualSP224Begin(t, c.hook, c.headerAt(time))
	require.NoError(t, err)
	defer end()
	root, journal := qualSP224State(t, c.store)
	err = c.run(context)
	if err != nil {
		after, afterJournal := qualSP224State(t, c.store)
		require.Equal(t, root, after, "time %d: a refused operation changes no state", time)
		require.Equal(t, journal, afterJournal)
	}
	return err
}

// Every bound a consumer decides, just before, at and just after it, through
// the consumer with the hook's context. true = admitted.
func TestQualSP224ConsumerBoundsWithTheNativeContext(t *testing.T) {
	for _, row := range []struct {
		name  string
		build func(t *testing.T) *qualSP224Consumer
		times map[uint64]bool
	}{
		// Admission is valid through validUntil = 200 inclusive.
		{"scoped_admit_until", func(t *testing.T) *qualSP224Consumer { c, _ := qualSP224ScopedConsumer(t, "admit"); return c }, map[uint64]bool{199: true, 200: true, 201: false}},
		{"scoped_read_until", func(t *testing.T) *qualSP224Consumer { c, _ := qualSP224ScopedConsumer(t, "read"); return c }, map[uint64]bool{199: true, 200: true, 201: false}},
		// Proposal window: earliest 105 needs a timelock of 5, until 120 a lifetime of at most 20.
		{"gas_propose_geometry", func(t *testing.T) *qualSP224Consumer { c, _, _ := qualSP224GASConsumer(t, "propose"); return c }, map[uint64]bool{99: false, 100: true, 101: false}},
		// Start: timelock 105 inclusive, window end 120 exclusive.
		{"gas_authorize_before_timelock", func(t *testing.T) *qualSP224Consumer { c, _, _ := qualSP224GASConsumer(t, "authorize"); return c }, map[uint64]bool{104: false, 105: true, 119: true, 120: false, 121: false}},
		{"gas_start_window", func(t *testing.T) *qualSP224Consumer { c, _, _ := qualSP224GASConsumer(t, "start"); return c }, map[uint64]bool{104: false, 105: true, 106: true, 119: true, 120: false, 121: false}},
		// Expiry cleanup only from the window end on.
		{"gas_cleanup_expired", func(t *testing.T) *qualSP224Consumer { c, _, _ := qualSP224GASConsumer(t, "cleanup"); return c }, map[uint64]bool{119: false, 120: true, 121: true}},
		// F06 on the source shard: debit while t < E = 112, expiry closure from t >= E.
		{"f06_consume_before_expiry", func(t *testing.T) *qualSP224Consumer { c, _ := qualSP224F06Consumer(t, "consume"); return c }, map[uint64]bool{110: true, 111: true, 112: false, 113: false}},
		{"f06_close_at_expiry", func(t *testing.T) *qualSP224Consumer { c, _ := qualSP224F06Consumer(t, "close_expired"); return c }, map[uint64]bool{111: false, 112: true, 113: true}},
	} {
		for time, admitted := range row.times {
			t.Run(fmt.Sprintf("%s/%d", row.name, time), func(t *testing.T) {
				err := qualSP224At(t, row.build(t), time)
				if admitted {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
				}
			})
		}
	}
}
