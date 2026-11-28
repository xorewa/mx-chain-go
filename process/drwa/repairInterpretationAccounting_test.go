package drwa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRepairInterpretationObservationFixture(t *testing.T) {
	f := qualCurrentLocalNew(t)
	journal := f.store.JournalLen()
	view, err := f.resolve()
	require.NoError(t, err)

	// The pre-existing fixture assembles its own keys and serialized materials
	// independently of the production resolver. Count its known seven pairs,
	// rather than deriving expected totals from the observed view.
	expected := repairInterpretationObservation{
		recordVisits:  7,
		keyBytes:      uint64(len(f.pointerKey) + len(f.bodyKey)),
		materialBytes: uint64(len(f.pointer) + len(f.body)),
	}
	t.Logf("pointer key=%d material=%d; body key=%d material=%d", len(f.pointerKey), len(f.pointer), len(f.bodyKey), len(f.body))
	for i := range f.keys {
		t.Logf("dependency kind=%s key=%d material=%d", f.host.refs[i].kind, len(f.keys[i]), len(f.materials[i]))
		expected.keyBytes += uint64(len(f.keys[i]))
		expected.materialBytes += uint64(len(f.materials[i]))
	}
	budget := repairInterpretationObservationBounds{expected.recordVisits, expected.keyBytes + expected.materialBytes}
	t.Logf("detached observations=%d serialized key bytes=%d material bytes=%d total bytes=%d", expected.recordVisits, expected.keyBytes, expected.materialBytes, budget.serializedBytes)

	t.Run("exact_observation_budget", func(t *testing.T) {
		got, err := measureRepairInterpretationObservations([]*currentLocalView{view}, budget)
		require.NoError(t, err)
		require.Equal(t, expected, got)
	})
	t.Run("larger_observation_budget", func(t *testing.T) {
		got, err := measureRepairInterpretationObservations([]*currentLocalView{view}, repairInterpretationObservationBounds{budget.recordVisits + 1, budget.serializedBytes + 1})
		require.NoError(t, err)
		require.Equal(t, expected, got)
	})
	t.Run("repeated_observation_not_unique_storage", func(t *testing.T) {
		bounds := repairInterpretationObservationBounds{2 * budget.recordVisits, 2 * budget.serializedBytes}
		got, err := measureRepairInterpretationObservations([]*currentLocalView{view, view}, bounds)
		require.NoError(t, err)
		require.Equal(t, repairInterpretationObservation{2 * expected.recordVisits, 2 * expected.keyBytes, 2 * expected.materialBytes}, got)
	})
	t.Run("smaller_diagnostic_budget_has_no_report", func(t *testing.T) {
		got, err := measureRepairInterpretationObservations([]*currentLocalView{view}, repairInterpretationObservationBounds{budget.recordVisits - 1, budget.serializedBytes})
		require.ErrorIs(t, err, errRepairInterpretationObservation)
		require.Zero(t, got)
		got, err = measureRepairInterpretationObservations([]*currentLocalView{view}, repairInterpretationObservationBounds{budget.recordVisits, budget.serializedBytes - 1})
		require.ErrorIs(t, err, errRepairInterpretationObservation)
		require.Zero(t, got)
	})
	t.Run("unavailable_diagnostic_budget", func(t *testing.T) {
		got, err := measureRepairInterpretationObservations([]*currentLocalView{view}, repairInterpretationObservationBounds{})
		require.ErrorIs(t, err, errRepairInterpretationObservation)
		require.Zero(t, got)
	})
	require.Equal(t, journal, f.store.JournalLen(), "detached accounting never mutates the underlying fixture")
}
