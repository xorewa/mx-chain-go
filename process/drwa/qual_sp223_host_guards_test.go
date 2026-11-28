package drwa

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

// SP2-23, mutant round on this row's own host (H04, H06, H19, H22, H24, H25).
// Each case is valid in everything but the one property its guard checks, so
// no other check can deny it first.
func TestQualSP223HostGuardsDenyOnTheirOwn(t *testing.T) {
	w := sp223New(t, sp223Ample())
	tr := w.transition(ConvergenceFamilyRoot, "ROOT_FENCE_ACK", 150, true)
	require.NoError(t, w.records.create(tr))
	binding := w.binding(tr)
	good := sp223Acknowledge(t, 1, 11, binding)
	w.enter(good)
	shardOne := []byte{0, 0, 0, 1}
	evidence := good.evidence(t, binding)

	// Control: this acknowledgement is accepted as it stands.
	shard, err := w.host.VerifyAck(binding, qualRecordFrame(binding, shardOne, good.origin), evidence)
	require.NoError(t, err)
	require.Equal(t, uint32(1), shard)

	// An owner that is nil is not installed, and the family stays free.
	bare, err := NewConvergenceHost(ArgsConvergenceHost{Accounts: w.store, Records: w.host.args.Records, Reader: w.reader, Block: w.block,
		Limits: w.limits, EvidenceBytes: 1 << 20})
	require.NoError(t, err)
	require.ErrorIs(t, bare.SetFamilyOwner(ConvergenceFamilyRoot, nil), errConvergence)
	require.ErrorIs(t, bare.VerifyTransition(binding), errConvergence)
	require.NoError(t, bare.SetFamilyOwner(ConvergenceFamilyRoot, w.owner))
	require.NoError(t, bare.VerifyTransition(binding))

	// The legacy pair has one encoding: the admitted binding with one more
	// field decodes to the same identity and is refused.
	legacy := w.binding(w.transition(ConvergenceFamilyCEB, "CURRENT_ACK", 151, true))
	require.NoError(t, w.host.VerifyTransition(legacy))
	require.ErrorIs(t, w.host.VerifyTransition(append(bytes.Clone(legacy), qualRecordFrame([]byte("l"))...)), errConvergence)

	// The payload names another admitted binding; shard, local execution and
	// evidence are those of the control.
	other := w.transition(ConvergenceFamilyRoot, "ROOT_FENCE_ACK", 152, true)
	_, err = w.host.VerifyAck(binding, qualRecordFrame(w.binding(other), shardOne, good.origin), evidence)
	require.ErrorIs(t, err, errConvergence)

	// The metachain is never an acknowledging execution shard; the reader is
	// not consulted for it.
	_, err = w.host.VerifyAck(binding, qualRecordFrame(binding, []byte{0xff, 0xff, 0xff, 0xff}, good.origin), evidence)
	require.ErrorIs(t, err, errConvergence)

	// Shard 1's account holds, canonically final and under the phase's key,
	// the item of shard 2's identity: it is not shard 1's acknowledgement.
	foreign := sp223AcknowledgeAs(t, 1, 2, 11, binding)
	w.enter(foreign)
	_, err = w.host.VerifyAck(binding, qualRecordFrame(binding, shardOne, foreign.origin), foreign.evidence(t, binding))
	require.ErrorIs(t, err, errConvergence)
	w.denied("the item of another shard identity", func() error {
		return w.records.acknowledge(tr, 1, foreign.origin, foreign.evidence(t, binding))
	})
	require.NoError(t, w.deliver(tr, good))
}

// Evidence must carry its own proof: after one acknowledgement of a result was
// read, a second item of the same result presented without the account proof
// is refused, although the first read had those nodes. And the cache is the
// evidence in hand only, so it cannot grow with the number of reads.
func TestQualSP223ProofCacheHoldsOnlyTheEvidenceInHand(t *testing.T) {
	w := sp223New(t, sp223Ample())
	exclusions, err := common.NewRoundExclusionHandler(nil)
	require.NoError(t, err)
	host, err := NewNativeConvergenceHost(ArgsNativeConvergenceHost{Accounts: w.store, Marshaller: &marshal.GogoProtoMarshalizer{}, Hasher: w.hasher,
		EnableEpochsHandler: w.reader.accounts.args.EnableEpochsHandler, MaxTrieLevelInMemory: 5,
		Validator: w.reader.validator, Proofs: w.reader.proofs, Integrity: w.reader.integrity, Exclusions: exclusions,
		Block: w.block, Limits: w.limits, RecordBytes: 4096, EvidenceBytes: 1 << 20,
		Owners: map[string]ConvergenceFamilyOwner{ConvergenceFamilyRoot: w.owner}})
	require.NoError(t, err)
	boundary, err := NewRollbackContainment(w.store)
	require.NoError(t, err)
	records, err := newConvergenceRecords(w.store, boundary, &marshal.GogoProtoMarshalizer{}, w.hasher, 4096, 16, host)
	require.NoError(t, err)
	first := w.transition(ConvergenceFamilyRoot, "ROOT_FENCE_ACK", 160, true)
	second := w.transition(ConvergenceFamilyRoot, "ROOT_CURRENT_ACK", 161, true)
	require.NoError(t, records.create(first))
	require.NoError(t, records.create(second))
	both := sp223Acknowledge(t, 0, 11, w.binding(first), w.binding(second))
	w.enter(both)
	require.NoError(t, records.acknowledge(first, 0, both.origin, both.evidence(t, w.binding(first))))
	require.NotEmpty(t, host.cache.nodes)

	for name, strip := range map[string]func(*canonicalResultWitness){
		"no account proof": func(x *canonicalResultWitness) { x.Account.AccountProof = nil },
		"account proof without its root node": func(x *canonicalResultWitness) {
			x.Account.AccountProof = x.Account.AccountProof[1:]
		},
	} {
		witness := both.witness(t, w.binding(second))
		require.NotEmpty(t, witness.Account.AccountProof)
		strip(&witness)
		root, journal := w.root(), w.store.JournalLen()
		require.Error(t, records.acknowledge(second, 0, both.origin, sp223Evidence(t, witness)), name)
		require.Equal(t, root, w.root(), name)
		require.Equal(t, journal, w.store.JournalLen(), name)
	}
	require.NoError(t, records.acknowledge(second, 0, both.origin, both.evidence(t, w.binding(second))))

	// The cache does not grow with the reads: after an acknowledgement of
	// another result it holds no more than the nodes of that evidence.
	third := w.transition(ConvergenceFamilyRoot, "ROOT_FENCE_CLEAR_ACK", 162, true)
	require.NoError(t, records.create(third))
	later := sp223Acknowledge(t, 1, 12, w.binding(third))
	w.enter(later)
	witness := later.witness(t, w.binding(third))
	held := len(host.cache.nodes)
	require.NotZero(t, held)
	require.NoError(t, records.acknowledge(third, 1, later.origin, sp223Evidence(t, witness)))
	require.LessOrEqual(t, len(host.cache.nodes), len(witness.Account.AccountProof)+len(witness.Account.DataProof))
	for _, node := range witness.Account.DataProof {
		_, err = host.cache.Get(w.hasher.Compute(string(node)))
		require.NoError(t, err)
	}
}
