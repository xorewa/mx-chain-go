package drwa

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/stretchr/testify/require"
)

// Owner answers of 28 November 2026 to the SP2-24 decision table.

// D-3 (a): the authority check owns its time source. It runs inside the
// source's current context and refuses a view that carries any other one.
func TestQualSP224AuthorityCheckOwnsItsTimeSource(t *testing.T) {
	all := qualSP227Rosters(t)
	wants := []scopedAuthorityRequirement{qualSP227Want(scopedEA, "add", scopedCurrent)}
	build := func(t *testing.T) (*qualSP227Constitution, []scopedAuthorityProof) {
		f := qualSP227ConstitutionNew(t, all, qualSP227Programmes(all)[0])
		f.r.use, f.r.phase = scopedEmergencyAdd, scopedDirect
		f.bindRequest()
		return f, f.sign(t, wants)
	}
	t.Run("control", func(t *testing.T) {
		f, p := build(t)
		require.NoError(t, f.verify(p))
	})
	t.Run("no_source", func(t *testing.T) {
		f, p := build(t)
		require.ErrorIs(t, verifyScopedAuthority(nil, f.codec, f.s, f.r, p, f.limits), errInvalidAuthoritySignatures)
		var typed *hooks.BlockChainHookImpl
		require.ErrorIs(t, verifyScopedAuthority(typed, f.codec, f.s, f.r, p, f.limits), errInvalidAuthoritySignatures)
	})
	t.Run("source_without_a_context", func(t *testing.T) {
		f, p := build(t)
		// The view still carries a live context of its own clock.
		f.source = qualClockSource(qualHeaderTimeOwner(t), nil)
		_, err := f.s.v.time.Milliseconds()
		require.NoError(t, err)
		require.ErrorIs(t, f.verify(p), ErrInactiveHeaderTime)
	})
	t.Run("view_context_of_another_live_clock", func(t *testing.T) {
		// Same locus and same time on both clocks: only the owner differs.
		f, p := build(t)
		other := qualHeaderTimeOwner(t)
		foreign := qualGovernedContext(t, other, core.MetachainShardId, 110)
		_, err := foreign.Milliseconds()
		require.NoError(t, err)
		f.s.v.time = foreign
		require.ErrorIs(t, f.verify(p), errInvalidAuthoritySignatures)
		// The same foreign context is admitted by nobody: with the foreign clock
		// as source the view matches, which is the control for this case.
		f.source = qualClockSource(other, nil)
		require.NoError(t, f.verify(p))
	})
	t.Run("view_context_of_the_previous_block", func(t *testing.T) {
		f, p := build(t)
		previous := f.s.v.time
		current := qualGovernedContext(t, f.clock, core.MetachainShardId, 110)
		require.NotSame(t, previous, current)
		require.ErrorIs(t, f.verify(p), errInvalidAuthoritySignatures)
		f.s.v.time = current
		require.NoError(t, f.verify(p))
	})
	t.Run("header_replaced_during_the_check", func(t *testing.T) {
		// A plain installation while the reader is read, inside the time
		// boundary: the context is dead for the rest of the check. (Until SP2-78
		// the reader also returned the signing digest and this case replaced
		// the header there; the product now builds the signed bytes itself.)
		f, _ := build(t)
		hook, _ := qualT42Hook(t, qualRegistrationStore(t, 0), core.MetachainShardId, true)
		f.source = hook
		context, _ := qualT42Install(t, hook, core.MetachainShardId, 110)
		f.s.v.time = context
		p := f.sign(t, wants)
		require.NoError(t, f.verify(p), "control")
		calls := 0
		f.s.afterRead = func() {
			calls++
			require.NoError(t, hook.SetCurrentHeader(qualT42Header(core.MetachainShardId, 110)))
		}
		require.ErrorIs(t, f.verify(p), ErrInactiveHeaderTime)
		require.Equal(t, 1, calls)
	})
	t.Run("source_error_is_returned", func(t *testing.T) {
		// A header with time zero: the hook's own error, not a generic one.
		f, p := build(t)
		hook, _ := qualT42Hook(t, qualRegistrationStore(t, 0), core.MetachainShardId, true)
		f.source = hook
		context, _, err := qualSP224Begin(t, hook, qualT42Header(core.MetachainShardId, 0))
		require.ErrorIs(t, err, ErrUnavailableHeaderTime)
		require.Nil(t, context)
		require.ErrorIs(t, f.verify(p), ErrUnavailableHeaderTime)
	})
	t.Run("native_hook_as_source", func(t *testing.T) {
		f, _ := build(t)
		hook, _ := qualT42Hook(t, qualRegistrationStore(t, 0), core.MetachainShardId, true)
		f.source = hook
		context, end := qualT42Install(t, hook, core.MetachainShardId, 110)
		f.s.v.time = context
		p := f.sign(t, wants)
		require.NoError(t, f.verify(p))
		end()
		require.ErrorIs(t, f.verify(p), ErrInactiveHeaderTime)
	})
}

// D-1 (b): a block whose header carries time zero is installed and processed
// by the real processors as before; only the typed view gives no context, so
// every time consumer inside that block is refused without a state change.
func TestQualSP224HeaderTimeZeroInsideARealBlockProcessingPass(t *testing.T) {
	shardPasses, metaPasses := 0, 0
	for name, build := range qualSP224AllConsumers() {
		t.Run(name+"/ordinary_pass", func(t *testing.T) {
			c := build(t)
			idle := *c
			idle.run = func(*HeaderTimeContext) error { return nil }
			header := qualSP224PassHeader(c, 0)
			require.Zero(t, header.GetTimeStamp())
			root, journal := qualSP224State(t, c.store)
			pass := qualSP224RunPass(t, &idle, header, false)
			require.Equal(t, 1, pass.ran)
			require.NoError(t, pass.result, "the block itself is processed as before")
			require.Equal(t, uint64(0), c.hook.CurrentTimeStampMs())
			require.Equal(t, header.GetRound(), c.hook.CurrentRound())
			after, afterJournal := qualSP224State(t, c.store)
			require.Equal(t, root, after)
			require.Equal(t, journal, afterJournal)
			if c.shard == core.MetachainShardId {
				metaPasses++
			} else {
				shardPasses++
			}
		})
		t.Run(name+"/consumer_refused", func(t *testing.T) {
			c := build(t)
			root, journal := qualSP224State(t, c.store)
			pass := qualSP224RunPass(t, c, qualSP224PassHeader(c, 0), false)
			require.Equal(t, 1, pass.ran)
			require.Error(t, pass.inside)
			require.ErrorIs(t, pass.result, pass.inside, "the refusal is the block's execution error")
			after, afterJournal := qualSP224State(t, c.store)
			require.Equal(t, root, after)
			require.Equal(t, journal, afterJournal)
		})
	}
	require.NotZero(t, shardPasses)
	require.NotZero(t, metaPasses)
	// The same block on hooks without the typed view (a node without DRWA).
	for _, shard := range []uint32{1, core.MetachainShardId} {
		hook, _ := qualT42Hook(t, qualRegistrationStore(t, 0), shard, false)
		c := &qualSP224Consumer{hook: hook, shard: shard, run: func(*HeaderTimeContext) error { return nil }}
		pass := qualSP224RunPass(t, c, qualSP224PassHeader(c, 0), false)
		require.Equal(t, 1, pass.ran)
		require.NoError(t, pass.result)
		require.Equal(t, uint64(0), hook.CurrentTimeStampMs())
	}
	t.Logf("SP2-24 zero-time passes: shard %d, metachain %d", shardPasses, metaPasses)
}
