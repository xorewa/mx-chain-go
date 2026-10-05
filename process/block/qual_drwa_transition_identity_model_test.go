package block

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// This is an executable, NON-NORMATIVE expected-model draft for Part A 3.1,
// 6.1 and 7.2 (G3/AM-011/AR-01/AR-15). It is not a production
// implementation or an accepted oracle. Strings stand for already established
// canonical identities or commitments; they do not select a codec, hash
// algorithm, storage key, protobuf field or numeric discriminator.
//
// The model separates the stable transition/action binding from the result
// that carries each acknowledgement. A native adapter still has to establish
// the complete S -> result/root -> H -> M -> B relation below from authenticated
// committed inputs. An SCR content hash, OriginalTxHash, PrevTxHash or nonce is
// not accepted as that adapter.
type qualTransitionBinding struct {
	family, instance, phase, subject, target, dependencies, requiredShardSet string
}

type qualCanonicalAction struct {
	actionID     string
	actionDigest string
	binding      qualTransitionBinding
}

type qualAckPayload struct {
	binding                qualTransitionBinding
	actionID, actionDigest string
	shard                  uint32
	localExecutionIdentity string
	appliedStateHash       string
}

type qualExecutionResult struct {
	identity, executedHeader, rootHash string
	ack                                qualAckPayload
}

type qualCarryingHeader struct {
	identity string
	results  map[string]qualExecutionResult
}

type qualReferenceEntry struct {
	carryingHeader, executedHeader, executionResult string
}

type qualMetachainReference struct {
	identity string
	entries  []qualReferenceEntry
}

type qualConsumingBlock struct {
	identity, authenticatedReference string
}

type qualResultWitness struct {
	executedHeader, executionResult, carryingHeader, metachainReference, consumingBlock string
	fullResult                                                                          qualExecutionResult
}

type qualCanonicalInputs struct {
	action     qualCanonicalAction
	carriers   map[string]qualCarryingHeader
	references map[string]qualMetachainReference
	consumers  map[string]qualConsumingBlock
}

type qualApplicationEvidence struct {
	ack     qualAckPayload
	witness qualResultWitness
}

type qualConvergenceModel struct {
	inputs       qualCanonicalInputs
	required     map[uint32]bool
	acknowledged map[uint32]bool
}

var errQualAckRejected = errors.New("model: acknowledgement rejected")

func (m *qualConvergenceModel) observe(e qualApplicationEvidence) error {
	if !m.required[e.ack.shard] || e.ack.binding != m.inputs.action.binding ||
		e.ack.actionID != m.inputs.action.actionID || e.ack.actionDigest != m.inputs.action.actionDigest ||
		e.ack.appliedStateHash != m.inputs.action.binding.target ||
		!qualCanonicalResultBindsAck(m.inputs, e) {
		return errQualAckRejected
	}
	m.acknowledged[e.ack.shard] = true
	return nil
}

func qualCanonicalResultBindsAck(inputs qualCanonicalInputs, e qualApplicationEvidence) bool {
	w := e.witness
	if w.fullResult.identity != w.executionResult || w.fullResult.executedHeader != w.executedHeader ||
		w.fullResult.ack != e.ack {
		return false
	}

	carrier, ok := inputs.carriers[w.carryingHeader]
	if !ok || carrier.identity != w.carryingHeader {
		return false
	}
	committedResult, ok := carrier.results[w.executionResult]
	if !ok || committedResult != w.fullResult {
		return false
	}

	reference, ok := inputs.references[w.metachainReference]
	if !ok || reference.identity != w.metachainReference {
		return false
	}
	foundBoundEntry := false
	for _, entry := range reference.entries {
		if entry == (qualReferenceEntry{
			carryingHeader:  w.carryingHeader,
			executedHeader:  w.executedHeader,
			executionResult: w.executionResult,
		}) {
			foundBoundEntry = true
			break
		}
	}
	if !foundBoundEntry {
		return false
	}

	consumer, ok := inputs.consumers[w.consumingBlock]
	return ok && consumer.identity == w.consumingBlock &&
		consumer.authenticatedReference == w.metachainReference
}

func (m *qualConvergenceModel) complete() bool {
	for shard := range m.required {
		if !m.acknowledged[shard] {
			return false
		}
	}
	return true
}

func qualNewConvergenceFixture() (*qualConvergenceModel, map[uint32]qualApplicationEvidence) {
	binding := qualTransitionBinding{
		family: "CEB_CURRENTIZATION", instance: "gas-action-A", phase: "CURRENT_ACK",
		subject: "token-A", target: "ceb-target-A", dependencies: "dependencies-A",
		requiredShardSet: "shard-set-A",
	}
	action := qualCanonicalAction{actionID: binding.instance, actionDigest: "action-digest-A", binding: binding}
	inputs := qualCanonicalInputs{
		action: action, carriers: make(map[string]qualCarryingHeader),
		references: make(map[string]qualMetachainReference), consumers: make(map[string]qualConsumingBlock),
	}
	evidence := make(map[uint32]qualApplicationEvidence)
	for shard := uint32(0); shard < 3; shard++ {
		suffix := fmt.Sprint(shard)
		ack := qualAckPayload{
			binding: binding, actionID: action.actionID, actionDigest: action.actionDigest, shard: shard,
			localExecutionIdentity: "local-apply-S" + suffix, appliedStateHash: binding.target,
		}
		result := qualExecutionResult{
			identity: "R" + suffix, executedHeader: "S" + suffix, rootHash: "root-" + suffix, ack: ack,
		}
		carrier := qualCarryingHeader{identity: "H" + suffix, results: map[string]qualExecutionResult{result.identity: result}}
		reference := qualMetachainReference{identity: "M" + suffix, entries: []qualReferenceEntry{{
			carryingHeader: carrier.identity, executedHeader: result.executedHeader, executionResult: result.identity,
		}}}
		consumer := qualConsumingBlock{identity: "B" + suffix, authenticatedReference: reference.identity}
		inputs.carriers[carrier.identity] = carrier
		inputs.references[reference.identity] = reference
		inputs.consumers[consumer.identity] = consumer
		evidence[shard] = qualApplicationEvidence{ack: ack, witness: qualResultWitness{
			executedHeader: result.executedHeader, executionResult: result.identity, carryingHeader: carrier.identity,
			metachainReference: reference.identity, consumingBlock: consumer.identity, fullResult: result,
		}}
	}
	return &qualConvergenceModel{
		inputs: inputs, required: map[uint32]bool{0: true, 1: true, 2: true},
		acknowledged: make(map[uint32]bool),
	}, evidence
}

func TestQualDRWATransitionIdentityModelRejectsMismatchedEvidence(t *testing.T) {
	cases := []struct {
		name          string
		syncResultAck bool
		change        func(*qualApplicationEvidence)
	}{
		{"family", true, func(e *qualApplicationEvidence) { e.ack.binding.family = "OTHER_FAMILY" }},
		{"instance", true, func(e *qualApplicationEvidence) { e.ack.binding.instance = "gas-action-B" }},
		{"phase", true, func(e *qualApplicationEvidence) { e.ack.binding.phase = "PREPARED_ACK" }},
		{"subject", true, func(e *qualApplicationEvidence) { e.ack.binding.subject = "token-B" }},
		{"target", true, func(e *qualApplicationEvidence) { e.ack.binding.target = "ceb-target-B" }},
		{"dependencies", true, func(e *qualApplicationEvidence) { e.ack.binding.dependencies = "dependencies-B" }},
		{"required_shard_set", true, func(e *qualApplicationEvidence) { e.ack.binding.requiredShardSet = "shard-set-B" }},
		{"action_id", true, func(e *qualApplicationEvidence) { e.ack.actionID = "gas-action-B" }},
		{"action_digest", true, func(e *qualApplicationEvidence) { e.ack.actionDigest = "action-digest-B" }},
		{"wrong_shard", true, func(e *qualApplicationEvidence) { e.ack.shard = 3 }},
		{"wrong_applied_state", true, func(e *qualApplicationEvidence) { e.ack.appliedStateHash = "different-state" }},
		{"ack_payload_substitution", false, func(e *qualApplicationEvidence) { e.witness.fullResult.ack.localExecutionIdentity = "other-apply" }},
		{"root_substitution", false, func(e *qualApplicationEvidence) { e.witness.fullResult.rootHash = "other-root" }},
		{"execution_result_substitution", false, func(e *qualApplicationEvidence) { e.witness.executionResult = "other-result" }},
		{"executed_header_substitution", false, func(e *qualApplicationEvidence) { e.witness.executedHeader = "other-S" }},
		{"carrying_header_substitution", false, func(e *qualApplicationEvidence) { e.witness.carryingHeader = "other-H" }},
		{"metachain_reference_substitution", false, func(e *qualApplicationEvidence) { e.witness.metachainReference = "other-M" }},
		{"discarded_consumer_branch", false, func(e *qualApplicationEvidence) { e.witness.consumingBlock = "discarded-B" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, evidence := qualNewConvergenceFixture()
			require.NoError(t, m.observe(evidence[0])) // earlier valid progress must survive denial
			candidate := evidence[1]
			tc.change(&candidate)
			if tc.syncResultAck {
				candidate.witness.fullResult.ack = candidate.ack
				carrier := m.inputs.carriers[candidate.witness.carryingHeader]
				carrier.results[candidate.witness.executionResult] = candidate.witness.fullResult
				m.inputs.carriers[carrier.identity] = carrier
			}
			require.ErrorIs(t, m.observe(candidate), errQualAckRejected)
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
			m, evidence := qualNewConvergenceFixture()
			for i, shard := range order {
				require.NoError(t, m.observe(evidence[shard]))
				require.NoError(t, m.observe(evidence[shard])) // same canonical result sets one bit
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
	t.Run("same_action_target_new_phase", func(t *testing.T) {
		m, evidence := qualNewConvergenceFixture()
		old := evidence[0]
		m.inputs.action.binding.phase = "TERMINAL_ACK"
		require.ErrorIs(t, m.observe(old), errQualAckRejected)
		require.Empty(t, m.acknowledged)
	})
	t.Run("same_action_target_other_family", func(t *testing.T) {
		m, evidence := qualNewConvergenceFixture()
		old := evidence[0]
		m.inputs.action.binding.family = "RECOVERY_CEB"
		require.ErrorIs(t, m.observe(old), errQualAckRejected)
		require.Empty(t, m.acknowledged)
	})
	t.Run("completed_predecessor_cannot_fill_successor", func(t *testing.T) {
		predecessor, evidence := qualNewConvergenceFixture()
		for _, shard := range []uint32{0, 1, 2} {
			require.NoError(t, predecessor.observe(evidence[shard]))
		}
		require.True(t, predecessor.complete())
		successor, _ := qualNewConvergenceFixture()
		successor.inputs.action.actionID = "gas-action-B"
		successor.inputs.action.binding.instance = "gas-action-B"
		require.ErrorIs(t, successor.observe(evidence[0]), errQualAckRejected)
		require.Empty(t, successor.acknowledged)
		require.False(t, successor.complete())
	})
}

func TestQualDRWATransitionIdentityModelBoundReferenceRelation(t *testing.T) {
	m, evidence := qualNewConvergenceFixture()
	e := evidence[0]
	reference := m.inputs.references[e.witness.metachainReference]
	// Legitimate co-presence of the same S and H identities in different entries
	// does not prove the required H -> result(S) relation.
	reference.entries = []qualReferenceEntry{
		{carryingHeader: e.witness.carryingHeader, executedHeader: "other-S", executionResult: "other-R"},
		{carryingHeader: "other-H", executedHeader: e.witness.executedHeader, executionResult: e.witness.executionResult},
	}
	m.inputs.references[reference.identity] = reference
	require.ErrorIs(t, m.observe(e), errQualAckRejected)
	require.Empty(t, m.acknowledged)
}

func TestQualDRWATransitionIdentityModelCopyBoundary(t *testing.T) {
	// Pure-model snapshot copies exercise the oracle's expected rollback/replay
	// distinction. They prove nothing about AccountsDB, crash safety or storage.
	m, evidence := qualNewConvergenceFixture()
	require.NoError(t, m.observe(evidence[0]))
	snapshot := *m
	snapshot.acknowledged = map[uint32]bool{0: true}
	require.NoError(t, m.observe(evidence[1]))
	require.Equal(t, map[uint32]bool{0: true}, snapshot.acknowledged)
	require.NoError(t, snapshot.observe(evidence[1])) // legitimate replay after restoring prior progress
	require.NoError(t, snapshot.observe(evidence[1])) // repeat does not duplicate credit
	require.Equal(t, m.acknowledged, snapshot.acknowledged)
	require.False(t, snapshot.complete())
}
