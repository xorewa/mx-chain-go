package drwa

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// The literal family/phase and bytes are experimental. The expected frame
// comes from the independent Batch writer, never convergenceRecords.encode.
func qualBootstrapReadinessPhase(f *qualConvergenceFixture, owner *RegistrationIntentOwner, domain, body []byte,
	change func(*convergenceTransition)) {
	h := blake2b.NewBlake2b()
	token := []byte("TOKEN-abcdef")
	association := qualRecordFrame(token, owner.id, owner.digest, body, owner.manager)
	f.tr.action, f.tr.digest = bytes.Clone(owner.id), bytes.Clone(owner.digest)
	f.tr.token, f.tr.version = token, 1
	f.tr.context = &convergencePhaseContext{
		family:      []byte("BOOTSTRAP_READINESS"),
		phase:       []byte("TYPE_PROFILE_READINESS"),
		lineage:     qualRecordFrame(domain, token, owner.id, owner.digest, []byte("CONSUMED")),
		predecessor: h.Compute(string(association)),
	}
	if change != nil {
		change(&f.tr)
	}
	indices := make([][]byte, len(f.tr.shards))
	for i, shard := range f.tr.shards {
		indices[i] = binary.BigEndian.AppendUint32(nil, shard)
	}
	set := qualRecordFrame(indices...)
	f.tr.requiredSet = h.Compute(string(set))
	ctx := f.tr.context
	f.key = append([]byte(convergencePrefix), qualRecordFrame(ctx.family, f.tr.action, ctx.phase, ctx.lineage)...)
	f.binding = qualRecordFrame(ctx.family, f.tr.action, f.tr.digest, ctx.phase, f.tr.token,
		binary.BigEndian.AppendUint64(nil, f.tr.version), f.tr.target, f.tr.dependencies,
		f.tr.requiredSet, set, ctx.lineage, ctx.predecessor)
	f.host.key, f.host.binding = f.key, f.binding
	for shard, local := range f.local {
		ack := qualRecordFrame(f.binding, binary.BigEndian.AppendUint32(nil, shard), local)
		f.host.acks[string(ack)] = shard
	}
}

func TestQualDRWARegistrationBootstrapPhaseBinding(t *testing.T) {
	t.Run("registration phase becomes the activation input", func(t *testing.T) {
		f := qualRegistrationAdmission(t, core.FungibleESDT)
		t.Cleanup(f.end)
		phase := qualConvergenceNew(t, 3)
		phase.store, phase.host.store = f.store, f.store
		h := blake2b.NewBlake2b()
		var err error
		phase.records, err = newConvergenceRecords(f.store, f.boundary, &marshal.GogoProtoMarshalizer{}, h, 4096, 3, phase.host)
		require.NoError(t, err)
		qualBootstrapReadinessPhase(phase, f.owner, f.body.networkDomain, f.verify.body, nil)
		f.owner, err = f.owner.withConvergence(phase.records, func(token []byte) (convergenceTransition, error) {
			require.Equal(t, phase.tr.token, token)
			return phase.tr, nil
		})
		require.NoError(t, err)
		prior := f.admit
		f.admit, err = f.owner.WithRegistrationAdmission(prior.source, prior.domain, prior.enableEpoch,
			prior.limits, prior.verifier, f.proofs)
		require.NoError(t, err)
		require.NoError(t, f.register(t, qualRegistrationCreator(t, "TOKEN-abcdef")))
		phase.assert(t, "PENDING")

		x := qualActivationAfterRegistration(t, f)
		phase.records, err = newConvergenceRecords(f.store, f.boundary, &marshal.GogoProtoMarshalizer{}, h, 4096, 3, phase.host)
		require.NoError(t, err)
		for _, shard := range phase.tr.shards {
			require.NoError(t, phase.ack(shard))
		}
		phase.assert(t, "PENDING", 0, 1, 2)
		ctx, err := f.hook.EvaluatedHeaderTimeContext()
		require.NoError(t, err)
		require.NoError(t, f.boundary.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
			out, activationErr := x.a.activateFromReadinessOwned(operation, ctx, phase.records, phase.tr, x.genesis,
				[]byte("synthetic-complete-activation-proof"))
			return []*vmcommon.VMOutput{out}, activationErr
		}))
		phase.assert(t, "COMPLETE", 0, 1, 2)
		_, commitment := phase.expected("COMPLETE", 0, 1, 2)
		require.Equal(t, qualRecordFrame(phase.tr.token, f.owner.id, []byte("Active"), commitment),
			qualRegistryValue(t, f.store, registrationActivationPrefix+string(phase.tr.token)))
	})

	for _, v := range []struct {
		name   string
		change func(*convergenceTransition)
	}{
		{"action", func(p *convergenceTransition) { p.action[0] ^= 1 }},
		{"digest", func(p *convergenceTransition) { p.digest[0] ^= 1 }},
		{"family", func(p *convergenceTransition) { p.context.family = []byte("other-family") }},
		{"phase", func(p *convergenceTransition) { p.context.phase = []byte("other-phase") }},
		{"version", func(p *convergenceTransition) { p.version++ }},
		{"shard count", func(p *convergenceTransition) { p.shards = []uint32{0, 1} }},
		{"shard identity", func(p *convergenceTransition) { p.shards = []uint32{0, 1, 3} }},
	} {
		t.Run(v.name, func(t *testing.T) {
			f := qualCandidateRecords(t, false, false, core.FungibleESDT)
			// The reconstructed candidate fixture uses a structural coordinator.
			// Select three configured shards explicitly for this phase assertion.
			f.owner.shards = 3
			phase := qualConvergenceNew(t, 3)
			phase.store, phase.host.store = f.store.qualNativeStore, f.store.qualNativeStore
			boundary := f.candidate.writer.boundary
			var err error
			phase.records, err = newConvergenceRecords(f.store, boundary, &marshal.GogoProtoMarshalizer{},
				blake2b.NewBlake2b(), 4096, 3, phase.host)
			require.NoError(t, err)
			// The local host recognizes the exact altered record. Only the
			// original registration-bound guard can reject this substitution.
			qualBootstrapReadinessPhase(phase, f.owner, f.body.networkDomain, f.encoded, v.change)
			f.owner, err = f.owner.withConvergence(phase.records, func([]byte) (convergenceTransition, error) {
				return phase.tr, nil
			})
			require.NoError(t, err)
			root, err := f.store.RootHash()
			require.NoError(t, err)
			journal := f.store.JournalLen()
			require.ErrorIs(t, f.create(qualRegistrationCreator(t, "TOKEN-abcdef")), errInvalidRegistrationRecord)
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.store.JournalLen())
			require.Empty(t, boundary.outputs)
			require.Empty(t, f.candidate.view.added)
			require.Empty(t, qualRegistryValue(t, phase.store, string(phase.key)))
			require.Empty(t, qualRegistryValue(t, phase.store, registrationAssociationPrefix+"TOKEN-abcdef"))
			original, err := f.owner.records.intent(f.owner.id)
			require.NoError(t, err)
			require.Equal(t, "OPEN", original.status)
			require.Zero(t, phase.host.verifyCalls)
			require.Zero(t, phase.host.admissionCalls)
		})
	}
}
