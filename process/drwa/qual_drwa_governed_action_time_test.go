package drwa

import (
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"
)

// T21 expected model was authored before execution. These synthetic windows
// select no profile bounds and prove no GAS authority, canonical projection,
// durable UNUSED closure, native header installation or destination outcome.
func qualGovernedContext(t *testing.T, owner *EvaluatedHeaderTime, shard uint32, time uint64) *HeaderTimeContext {
	t.Helper()
	if shard == core.MetachainShardId {
		context, err := owner.Begin(&block.MetaBlockV3{Epoch: 10, TimestampMs: time})
		require.NoError(t, err)
		return context
	}
	context, err := owner.Begin(&block.HeaderV3{Epoch: 10, ShardID: shard, TimestampMs: time})
	require.NoError(t, err)
	return context
}

func TestQualDRWAGovernedActionTimeGeometry(t *testing.T) {
	cases := []struct {
		name                                string
		proposed, min, max, earliest, until uint64
		wantError                           error
	}{
		{"minimum", 100, 5, 20, 105, 120, nil},
		{"below_minimum", 100, 5, 20, 104, 120, errGovernedActionTime},
		{"reversed", 100, 5, 20, 105, 104, errGovernedActionTime},
		{"equal_end", 100, 5, 20, 105, 105, errGovernedActionTime},
		{"over_maximum", 100, 5, 20, 105, 121, errGovernedActionTime},
		{"impossible_window", 100, 20, 20, 120, 121, errGovernedActionTime},
		{"lower_overflow", math.MaxUint64 - 1, 2, 2, math.MaxUint64, math.MaxUint64, core.ErrAdditionOverflow},
		{"lower_only_overflow_hostile_bounds", math.MaxUint64 - 1, 2, 1, math.MaxUint64, math.MaxUint64, core.ErrAdditionOverflow},
		{"upper_overflow", math.MaxUint64 - 10, 1, 11, math.MaxUint64 - 9, math.MaxUint64, core.ErrAdditionOverflow},
		{"zero_coordinate", 0, 5, 20, 5, 20, nil},
		{"last_representable", math.MaxUint64 - 20, 5, 20, math.MaxUint64 - 15, math.MaxUint64, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			context := qualGovernedContext(t, qualHeaderTimeOwner(t), core.MetachainShardId, c.proposed)
			window, err := newGovernedActionWindow(context, HeaderMilliseconds(c.min), HeaderMilliseconds(c.max), HeaderMilliseconds(c.earliest), HeaderMilliseconds(c.until))
			if c.wantError != nil {
				require.ErrorIs(t, err, c.wantError)
				require.Nil(t, window)
				return
			}
			require.NoError(t, err)
			require.Equal(t, &governedActionWindow{HeaderMilliseconds(c.proposed), HeaderMilliseconds(c.earliest), HeaderMilliseconds(c.until)}, window)
		})
	}
}

func TestQualDRWAGovernedActionTimeStartAndArm(t *testing.T) {
	for _, c := range []struct {
		name string
		time uint64
		ok   bool
	}{
		{"before", 104, false}, {"equal_earliest", 105, true}, {"last", 119, true},
		{"equal_until", 120, false}, {"after", 121, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			owner := qualHeaderTimeOwner(t)
			window, err := newGovernedActionWindow(qualGovernedContext(t, owner, core.MetachainShardId, 100), 5, 20, 105, 120)
			require.NoError(t, err)
			context := qualGovernedContext(t, owner, core.MetachainShardId, c.time)
			err = window.mayStart(context)
			expiry, armErr := window.projectionExpiry(context, 7)
			if c.ok {
				require.NoError(t, err)
				require.NoError(t, armErr)
				require.Equal(t, HeaderMilliseconds(c.time+7), expiry)
			} else {
				require.ErrorIs(t, err, errGovernedActionTime)
				require.ErrorIs(t, armErr, errGovernedActionTime)
				require.Zero(t, expiry)
			}
		})
	}
	t.Run("projection_overflow", func(t *testing.T) {
		owner := qualHeaderTimeOwner(t)
		window, err := newGovernedActionWindow(qualGovernedContext(t, owner, core.MetachainShardId, math.MaxUint64-20), 5, 20, math.MaxUint64-15, math.MaxUint64)
		require.NoError(t, err)
		expiry, err := window.projectionExpiry(qualGovernedContext(t, owner, core.MetachainShardId, math.MaxUint64-1), 2)
		require.ErrorIs(t, err, core.ErrAdditionOverflow)
		require.Zero(t, expiry)
	})
	t.Run("zero_lifetime_arithmetic", func(t *testing.T) {
		owner := qualHeaderTimeOwner(t)
		window, err := newGovernedActionWindow(qualGovernedContext(t, owner, core.MetachainShardId, 100), 5, 20, 105, 120)
		require.NoError(t, err)
		expiry, err := window.projectionExpiry(qualGovernedContext(t, owner, core.MetachainShardId, 105), 0)
		require.NoError(t, err)
		require.Equal(t, HeaderMilliseconds(105), expiry)
	})
}

func TestQualDRWAGovernedActionTimeSource(t *testing.T) {
	for _, c := range []struct {
		name string
		time uint64
		want bool
	}{
		{"before", 111, true}, {"equal", 112, false}, {"after", 113, false},
		{"validated_zero", 0, true}, {"last_representable", math.MaxUint64, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			context := qualGovernedContext(t, qualHeaderTimeOwner(t), 1, c.time)
			before, err := sourceProjectionBeforeExpiry(context, 1, 112)
			require.NoError(t, err)
			require.Equal(t, c.want, before)
			// !before is time eligibility only, never canonical UNUSED evidence.
		})
	}
}

func TestQualDRWAGovernedActionTimeInvalidContext(t *testing.T) {
	for _, name := range []string{"nil", "ended", "reset", "failed_begin", "ABA", "wrong_meta_locus", "wrong_source_locus", "meta_as_source"} {
		t.Run(name, func(t *testing.T) {
			owner := qualHeaderTimeOwner(t)
			context := qualGovernedContext(t, owner, 1, 111)
			want := ErrInactiveHeaderTime
			source := uint32(1)
			switch name {
			case "nil":
				context = nil
			case "ended":
				owner.End(context)
			case "reset":
				owner.Reset()
			case "failed_begin":
				_, err := owner.Begin(nil)
				require.Error(t, err)
			case "ABA":
				qualGovernedContext(t, owner, 1, 112)
				qualGovernedContext(t, owner, 1, 111)
			case "wrong_meta_locus":
				window, err := newGovernedActionWindow(context, 5, 20, 116, 131)
				require.ErrorIs(t, err, errGovernedActionTime)
				require.Nil(t, window)
				err = (&governedActionWindow{100, 105, 120}).mayStart(context)
				require.ErrorIs(t, err, errGovernedActionTime)
				return
			case "wrong_source_locus":
				source, want = 2, errGovernedActionTime
			case "meta_as_source":
				context = qualGovernedContext(t, owner, core.MetachainShardId, 111)
				source, want = core.MetachainShardId, errGovernedActionTime
			}
			before, err := sourceProjectionBeforeExpiry(context, source, 112)
			require.ErrorIs(t, err, want)
			require.False(t, before)
		})
	}
	for _, window := range []*governedActionWindow{nil, {}, {100, 99, 120}, {100, 105, 105}} {
		t.Run("invalid_geometry", func(t *testing.T) {
			context := qualGovernedContext(t, qualHeaderTimeOwner(t), core.MetachainShardId, 110)
			require.ErrorIs(t, window.mayStart(context), errGovernedActionTime)
		})
	}
}

func TestQualDRWAGovernedActionTimeConcurrentReset(t *testing.T) {
	owner := qualHeaderTimeOwner(t)
	window, err := newGovernedActionWindow(qualGovernedContext(t, owner, core.MetachainShardId, 100), 5, 20, 105, 120)
	require.NoError(t, err)
	context := qualGovernedContext(t, owner, core.MetachainShardId, 105)
	var wg sync.WaitGroup
	results := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			expiry, armErr := window.projectionExpiry(context, 7)
			if armErr != nil && !errors.Is(armErr, ErrInactiveHeaderTime) || armErr == nil && expiry != 112 {
				results <- errors.New("mixed arm coordinate or unexpected failure")
				return
			}
		}
	}()
	owner.Reset()
	wg.Wait()
	close(results)
	for result := range results {
		require.NoError(t, result)
	}
	_, err = window.projectionExpiry(context, 7)
	require.ErrorIs(t, err, ErrInactiveHeaderTime)
}
