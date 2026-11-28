package drwa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// SP2-31, F04 (Part A E.8.6). Expected outcomes are written here from E.8.4,
// not derived from the product.

// E.8.6 bullet 1, registration: withdrawal effective first refuses the exact
// pre-signed registration; consumption completed first is preserved.
func TestQualSP231RegistrationWithdrawalFirstAndConsumptionFirst(t *testing.T) {
	t.Run("withdrawal_effective_first", func(t *testing.T) {
		w := qualSP231New(t, 200, true)
		require.Equal(t, admissionDecisionAdmitted, w.status(w.d))
		w.withdrawn()
		require.Equal(t, admissionDecisionWithdrawn, w.status(w.d))
		root, journal := w.state()
		created := 0
		require.ErrorIs(t, w.register(&created), errScopedAdmission)
		require.Zero(t, created, "the native creation never ran")
		require.Empty(t, w.f.verify.calls, "no proof was looked at")
		after, afterJournal := w.state()
		require.Equal(t, root, after)
		require.Equal(t, journal, afterJournal)
		require.Equal(t, "OPEN", w.intentStatus(), "the refusal does not consume or cancel the intent")
	})
	t.Run("consumption_completed_first", func(t *testing.T) {
		w := qualSP231New(t, 200, true)
		created := 0
		require.NoError(t, w.register(&created))
		require.Equal(t, 1, created)
		require.Equal(t, qualRegistrationPurposes, w.f.verify.calls, "the other required approvals were all still required")
		require.Equal(t, "CONSUMED", w.intentStatus())
		w.withdrawn()
		require.Equal(t, "CONSUMED", w.intentStatus(), "a completed registration is not undone")
		record, _, err := w.f.owner.records.registeredToken([]byte(qualSP231Token))
		require.NoError(t, err)
		require.Equal(t, "CONSUMED", record.status)
	})
	t.Run("unbound_owner_is_as_before_this_row", func(t *testing.T) {
		w := qualSP231New(t, 200, false)
		w.withdrawn()
		created := 0
		require.NoError(t, w.register(&created), "without the binding the owner relies on its external verifier only")
		require.Equal(t, 1, created)
	})
}

// E.8.6 bullet 1, activation: registered but not activated; withdrawal first
// refuses activation, activation's own checks run when it is not withdrawn.
func TestQualSP231ActivationWithdrawalFirst(t *testing.T) {
	t.Run("not_withdrawn", func(t *testing.T) {
		w := qualSP231New(t, 200, true)
		created := 0
		require.NoError(t, w.register(&created))
		x := w.activation(true)
		err, asked := w.activate(x)
		require.Equal(t, 1, asked, "the admission check passed and the activation host was asked")
		require.NotErrorIs(t, err, errScopedAdmission)
	})
	t.Run("withdrawal_effective_first", func(t *testing.T) {
		w := qualSP231New(t, 200, true)
		created := 0
		require.NoError(t, w.register(&created))
		x := w.activation(true)
		w.withdrawn()
		root, journal := w.state()
		err, asked := w.activate(x)
		require.ErrorIs(t, err, errScopedAdmission)
		require.Zero(t, asked, "the activation host was never asked")
		after, afterJournal := w.state()
		require.Equal(t, root, after)
		require.Equal(t, journal, afterJournal)
		record, _, regErr := w.f.owner.records.registeredToken([]byte(qualSP231Token))
		require.NoError(t, regErr)
		require.Equal(t, "CONSUMED", record.status, "registered but inactive: nothing reversed, nothing activated")
	})
}
