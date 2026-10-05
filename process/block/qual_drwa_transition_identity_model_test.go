package block

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// This is an executable, NON-NORMATIVE expected-model draft for Part A 3.1
// (G3/AM-011/AR-15) and 7.2. It is not a production implementation or an accepted
// oracle. Opaque strings below stand for already established identities, NOT
// serialized fields or numeric discriminator choices.
//
// The model assumes an external adapter supplies authenticated transition and
// applied-result evidence. It does not implement/prove that adapter, AR-01/P13,
// ID allocation, signing, transport, gas, journal persistence or phase commitment.
// It cannot justify wiring a production ACK consumer before those gates close.
type qualTransitionBinding struct {
	family, instance, phase, subject, target, dependencies, requiredShardSet string
}

type qualApplicationEvidence struct {
	binding qualTransitionBinding
	shard   uint32
	// The opaque origin denotes the canonical transition realization, separate
	// from a reused identifier on a discarded branch. This is a fixture marker,
	// not an additional proposed wire field.
	origin                                                       string
	authenticated, canonicalFinal, applied, dependenciesResolved bool
}

type qualConvergenceModel struct {
	binding      qualTransitionBinding
	origin       string
	required     map[uint32]bool
	acknowledged map[uint32]bool
}

var errQualAckRejected = errors.New("model: acknowledgement rejected")

func (m *qualConvergenceModel) observe(e qualApplicationEvidence) error {
	if !e.authenticated || !e.canonicalFinal || !e.applied || !e.dependenciesResolved ||
		e.binding != m.binding || e.origin != m.origin || !m.required[e.shard] {
		return errQualAckRejected
	}
	m.acknowledged[e.shard] = true
	return nil
}

func (m *qualConvergenceModel) complete() bool {
	for shard := range m.required {
		if !m.acknowledged[shard] {
			return false
		}
	}
	return true
}

func qualNewConvergenceFixture() (*qualConvergenceModel, qualApplicationEvidence) {
	binding := qualTransitionBinding{"family-A", "instance-A", "phase-A", "token-A", "target-A", "dependencies-A", "shard-set-A"}
	m := &qualConvergenceModel{
		binding: binding, origin: "canonical-realization-A",
		required: map[uint32]bool{0: true, 1: true, 2: true}, acknowledged: make(map[uint32]bool),
	}
	return m, qualApplicationEvidence{binding: binding, shard: 0, origin: m.origin,
		authenticated: true, canonicalFinal: true, applied: true, dependenciesResolved: true}
}

func TestQualDRWATransitionIdentityModelRejectsMismatchedEvidence(t *testing.T) {
	cases := []struct {
		name   string
		change func(*qualApplicationEvidence)
	}{
		{"family", func(e *qualApplicationEvidence) { e.binding.family = "family-B" }},
		{"instance", func(e *qualApplicationEvidence) { e.binding.instance = "instance-B" }},
		{"phase", func(e *qualApplicationEvidence) { e.binding.phase = "phase-B" }},
		{"subject", func(e *qualApplicationEvidence) { e.binding.subject = "token-B" }},
		{"target", func(e *qualApplicationEvidence) { e.binding.target = "target-B" }},
		{"dependencies", func(e *qualApplicationEvidence) { e.binding.dependencies = "dependencies-B" }},
		{"required_shard_set", func(e *qualApplicationEvidence) { e.binding.requiredShardSet = "shard-set-B" }},
		{"wrong_shard", func(e *qualApplicationEvidence) { e.shard = 3 }},
		{"unauthenticated", func(e *qualApplicationEvidence) { e.authenticated = false }},
		{"speculative_result", func(e *qualApplicationEvidence) { e.canonicalFinal = false }},
		{"received_but_not_applied", func(e *qualApplicationEvidence) { e.applied = false }},
		{"dependency_not_resolved", func(e *qualApplicationEvidence) { e.dependenciesResolved = false }},
		{"discarded_branch_same_numeric_identity", func(e *qualApplicationEvidence) { e.origin = "discarded-realization" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, e := qualNewConvergenceFixture()
			require.NoError(t, m.observe(e)) // earlier valid progress must survive denial
			e.shard = 1
			tc.change(&e)
			require.ErrorIs(t, m.observe(e), errQualAckRejected)
			require.Equal(t, map[uint32]bool{0: true}, m.acknowledged)
			require.False(t, m.complete())
		})
	}
}

func TestQualDRWATransitionIdentityModelConvergence(t *testing.T) {
	// All delivery permutations for this three-shard fixture. Three is the
	// qualification topology, not a hardcoded production shard-count default.
	orders := [][]uint32{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, order := range orders {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			m, e := qualNewConvergenceFixture()
			for i, shard := range order {
				e.shard = shard
				require.NoError(t, m.observe(e))
				require.NoError(t, m.observe(e)) // same canonical duplicate sets one bit
				require.Len(t, m.acknowledged, i+1)
				require.Equal(t, i == 2, m.complete())
			}
			require.Equal(t, map[uint32]bool{0: true, 1: true, 2: true}, m.acknowledged)
		})
	}
	// No event or passage of time changes progress: this model deliberately has
	// no timeout-to-success operation. Actual timeout scheduling is not tested.
}

func TestQualDRWATransitionIdentityModelPhaseAndFamilyIsolation(t *testing.T) {
	t.Run("same_instance_target_new_phase", func(t *testing.T) {
		m, old := qualNewConvergenceFixture()
		m.binding.phase = "phase-B"
		require.ErrorIs(t, m.observe(old), errQualAckRejected)
		require.Empty(t, m.acknowledged)
		current := old
		current.binding.phase = "phase-B"
		require.NoError(t, m.observe(current))
	})
	t.Run("same_instance_target_other_family", func(t *testing.T) {
		m, old := qualNewConvergenceFixture()
		m.binding.family = "family-B"
		require.ErrorIs(t, m.observe(old), errQualAckRejected)
		require.Empty(t, m.acknowledged)
		current := old
		current.binding.family = "family-B"
		require.NoError(t, m.observe(current))
	})
	t.Run("completed_predecessor_cannot_fill_successor", func(t *testing.T) {
		predecessor, old := qualNewConvergenceFixture()
		for _, shard := range []uint32{0, 1, 2} {
			old.shard = shard
			require.NoError(t, predecessor.observe(old))
		}
		require.True(t, predecessor.complete())
		successor, _ := qualNewConvergenceFixture()
		successor.binding.instance = "instance-B"
		require.ErrorIs(t, successor.observe(old), errQualAckRejected)
		require.Empty(t, successor.acknowledged)
		require.False(t, successor.complete())
	})
}

func TestQualDRWATransitionIdentityModelCopyBoundary(t *testing.T) {
	// Pure-model snapshot copies exercise the oracle's expected rollback/replay
	// distinction. They prove nothing about AccountsDB, crash safety or storage.
	m, e := qualNewConvergenceFixture()
	require.NoError(t, m.observe(e))
	snapshot := *m
	snapshot.acknowledged = map[uint32]bool{0: true}
	e.shard = 1
	require.NoError(t, m.observe(e))
	require.Equal(t, map[uint32]bool{0: true}, snapshot.acknowledged)
	require.NoError(t, snapshot.observe(e)) // legitimate replay after restoring prior progress
	require.NoError(t, snapshot.observe(e)) // repeat does not duplicate credit
	require.Equal(t, m.acknowledged, snapshot.acknowledged)
	require.False(t, snapshot.complete())
}
