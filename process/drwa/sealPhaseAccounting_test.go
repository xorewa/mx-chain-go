package drwa

import (
	"slices"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

func sp237PhaseView(phase, activation string) lifecycleReadView {
	return lifecycleReadView{token: []byte("fixture-token"), cebHash: []byte("fixture-current-ceb"),
		cebEpoch: 7, activation: activation, lifecycle: phase}
}

// Independent finite model: the permitted local phase labels are enumerated
// directly from the normative seal ordering. These are detached synthetic
// observations, not route attempts, authenticated ACKs or node state.
func TestSP237SealPhaseAccountingModel(t *testing.T) {
	cases := []struct {
		meta, activation string
		local            []string
	}{
		{"SETUP", "Active", []string{"SETUP"}},
		{"SETUP_SEALED", "Active", []string{"SETUP", "SETUP_SEALED"}},
		{"OPEN", "Active", []string{"SETUP_SEALED", "OPEN"}},
		{"WIND_DOWN", "WindDownDeny", []string{"WIND_DOWN"}},
		{"WIND_DOWN_SEALED", "WindDownDeny", []string{"WIND_DOWN", "WIND_DOWN_SEALED"}},
	}
	labels := []string{"SETUP", "SETUP_SEALED", "OPEN", "WIND_DOWN", "WIND_DOWN_SEALED", "REQUALIFYING"}
	for _, c := range cases {
		t.Run(c.meta, func(t *testing.T) {
			for _, a := range labels {
				for _, b := range labels {
					for _, d := range labels {
						states := []string{a, b, d}
						locals := make([]sealShardLifecycleObservation, len(states))
						valid := true
						var expected sealPhaseAccounting
						for i, label := range states {
							locals[i] = sealShardLifecycleObservation{uint32(i), sp237PhaseView(label, c.activation)}
							valid = valid && slices.Contains(c.local, label)
							switch label {
							case "SETUP", "WIND_DOWN":
								expected.before++
							case "SETUP_SEALED", "WIND_DOWN_SEALED":
								expected.sealed++
							case "OPEN":
								expected.advanced++
							}
						}
						actual, err := accountSealLifecyclePhases(sp237PhaseView(c.meta, c.activation), 3, locals)
						if valid {
							require.NoError(t, err, "%v", states)
							require.Equal(t, expected, actual)
							require.Equal(t, uint32(3), actual.before+actual.sealed+actual.advanced)
						} else {
							require.ErrorIs(t, err, errSetupLifecycle, "%v", states)
							require.Empty(t, actual)
						}
					}
				}
			}
		})
	}
}

func TestSP237SealPhaseAccountingScope(t *testing.T) {
	// One nominal open replica and one lagging sealed replica describe an
	// already-open same-CEB snapshot; no state or mutation is attempted here.
	meta := sp237PhaseView("OPEN", "Active")
	newLocals := func() []sealShardLifecycleObservation {
		return []sealShardLifecycleObservation{
			{0, sp237PhaseView("OPEN", "Active")}, {1, sp237PhaseView("SETUP_SEALED", "Active")},
		}
	}
	actual, err := accountSealLifecyclePhases(meta, 2, newLocals())
	require.NoError(t, err)
	require.Equal(t, sealPhaseAccounting{sealed: 1, advanced: 1}, actual)

	for _, tc := range []struct {
		name string
		edit func(*lifecycleReadView, *uint32, []sealShardLifecycleObservation)
	}{
		{"empty roster", func(_ *lifecycleReadView, n *uint32, _ []sealShardLifecycleObservation) { *n = 0 }},
		{"different roster size", func(_ *lifecycleReadView, n *uint32, _ []sealShardLifecycleObservation) { *n = 3 }},
		{"uninitialized epoch", func(m *lifecycleReadView, _ *uint32, _ []sealShardLifecycleObservation) { m.cebEpoch = 0 }},
		{"unset token", func(m *lifecycleReadView, _ *uint32, _ []sealShardLifecycleObservation) { m.token = nil }},
		{"unset CEB", func(m *lifecycleReadView, _ *uint32, _ []sealShardLifecycleObservation) { m.cebHash = nil }},
		{"unrelated activation", func(m *lifecycleReadView, _ *uint32, _ []sealShardLifecycleObservation) {
			m.activation = "WindDownDeny"
		}},
		{"separate transition", func(m *lifecycleReadView, _ *uint32, _ []sealShardLifecycleObservation) { m.lifecycle = "REQUALIFYING" }},
		{"other roster index", func(_ *lifecycleReadView, _ *uint32, l []sealShardLifecycleObservation) { l[1].shard = 2 }},
		{"other activation", func(_ *lifecycleReadView, _ *uint32, l []sealShardLifecycleObservation) {
			l[1].view.activation = "WindDownDeny"
		}},
		{"other epoch", func(_ *lifecycleReadView, _ *uint32, l []sealShardLifecycleObservation) { l[1].view.cebEpoch = 8 }},
		{"other token", func(_ *lifecycleReadView, _ *uint32, l []sealShardLifecycleObservation) {
			l[1].view.token = []byte("other fixture token")
		}},
		{"other CEB", func(_ *lifecycleReadView, _ *uint32, l []sealShardLifecycleObservation) {
			l[1].view.cebHash = []byte("other fixture CEB")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, n, local := meta, uint32(2), newLocals()
			tc.edit(&m, &n, local)
			actual, err := accountSealLifecyclePhases(m, n, local)
			require.ErrorIs(t, err, errSetupLifecycle)
			require.Empty(t, actual)
		})
	}
}

// Each locus has its own observation. The independent model expects a zero
// count at all four loci; no global sum or execution-only result is used.
func TestSP237SealZeroEffectAccountingModel(t *testing.T) {
	binding := []byte("fixture authenticated seal generation")
	newReadbacks := func() (sealZeroEffectObservation, []sealZeroEffectObservation) {
		return sealZeroEffectObservation{shard: core.MetachainShardId, binding: binding}, []sealZeroEffectObservation{
			{shard: 0, binding: binding}, {shard: 1, binding: binding}, {shard: 2, binding: binding},
		}
	}
	for mask := 0; mask < 1<<4; mask++ {
		meta, locals := newReadbacks()
		meta.openEffectCount = uint64(mask & 1)
		for i := range locals {
			locals[i].openEffectCount = uint64((mask >> (i + 1)) & 1)
		}
		err := checkSealZeroEffectAccounting(binding, 3, meta, locals)
		require.Equal(t, mask == 0, err == nil, "local count snapshot %d", mask)
	}
	for _, tc := range []struct {
		name string
		edit func(*[]byte, *uint32, *sealZeroEffectObservation, []sealZeroEffectObservation)
	}{
		{"unset generation", func(b *[]byte, _ *uint32, _ *sealZeroEffectObservation, _ []sealZeroEffectObservation) { *b = nil }},
		{"empty roster", func(_ *[]byte, n *uint32, _ *sealZeroEffectObservation, _ []sealZeroEffectObservation) { *n = 0 }},
		{"different roster size", func(_ *[]byte, n *uint32, _ *sealZeroEffectObservation, _ []sealZeroEffectObservation) { *n = 4 }},
		{"wrong meta locus", func(_ *[]byte, _ *uint32, m *sealZeroEffectObservation, _ []sealZeroEffectObservation) { m.shard = 0 }},
		{"other meta generation", func(_ *[]byte, _ *uint32, m *sealZeroEffectObservation, _ []sealZeroEffectObservation) {
			m.binding = []byte("other fixture generation")
		}},
		{"other execution locus", func(_ *[]byte, _ *uint32, _ *sealZeroEffectObservation, l []sealZeroEffectObservation) {
			l[1].shard = 4
		}},
		{"other execution generation", func(_ *[]byte, _ *uint32, _ *sealZeroEffectObservation, l []sealZeroEffectObservation) {
			l[1].binding = []byte("other fixture generation")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, n := binding, uint32(3)
			meta, locals := newReadbacks()
			tc.edit(&b, &n, &meta, locals)
			require.ErrorIs(t, checkSealZeroEffectAccounting(b, n, meta, locals), errSetupLifecycle)
		})
	}
}
