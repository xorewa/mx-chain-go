package drwa

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// sp223Join is the original registration of SP2-29's world with the bootstrap
// readiness phase created in the same operation by the production host.
type sp223Join struct {
	w       *sp229World
	block   *sp223Block
	owner   *sp223Owner
	host    *ConvergenceHost
	records *convergenceRecords
	intent  sp229Intent
}

func sp223JoinNew(t *testing.T, lim sp229Limits) *sp223Join {
	t.Helper()
	base := newCanonicalTestFixture(t, 0, core.MetachainShardId)
	j := &sp223Join{w: sp229New(t, lim), owner: &sp223Owner{admitted: map[string]struct{}{}}, intent: sp229IntentFor(1),
		block: &sp223Block{epoch: 10, hash: base.bHash, header: base.w.Consumer}}
	codec, err := newRegistrationRecords(j.w.store, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), lim.recordBytes)
	require.NoError(t, err)
	j.host, err = NewConvergenceHost(ArgsConvergenceHost{Accounts: j.w.store, Records: codec, Reader: base.reader, Block: j.block,
		Limits: j.w.resources(), EvidenceBytes: 1 << 20, Owners: map[string]ConvergenceFamilyOwner{ConvergenceFamilyBootstrap: j.owner}})
	require.NoError(t, err)
	j.records, err = newConvergenceRecords(j.w.store, j.w.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), lim.recordBytes, 16, j.host)
	require.NoError(t, err)
	require.True(t, j.w.apply(sp229OpenIntent(j.intent), "intent"))
	return j
}

// phase is the bootstrap readiness phase the consumed intent identifies
// (model Q1: the existing intent id in a family namespace).
func (j *sp223Join) phase() convergenceTransition {
	set := qualRecordFrame([]byte{0, 0, 0, 0}, []byte{0, 0, 0, 1}, []byte{0, 0, 0, 2})
	return convergenceTransition{action: j.intent.id, digest: j.intent.digest, token: []byte(j.intent.token),
		target: bytes.Repeat([]byte{0x31}, 32), dependencies: bytes.Repeat([]byte{0x32}, 32),
		requiredSet: blake2b.NewBlake2b().Compute(string(set)), version: 1, shards: []uint32{0, 1, 2},
		context: &convergencePhaseContext{family: []byte("BOOTSTRAP_READINESS"), phase: []byte("TYPE_PROFILE_READINESS"),
			lineage: j.intent.id, predecessor: j.intent.digest}}
}

func (j *sp223Join) register(t *testing.T, build func([]byte) (convergenceTransition, error)) error {
	t.Helper()
	i := j.intent
	manager := bytes.Repeat([]byte{0x22}, 32)
	owner, err := j.w.registration.BindIntent(i.id, i.digest, manager, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), j.w.lim.recordBytes)
	require.NoError(t, err)
	bound, err := owner.withConvergence(j.records, build)
	require.NoError(t, err)
	p := []byte("synthetic")
	admit, err := bound.WithRegistrationAdmission(qualClockSource(j.w.clock, j.w.store), []byte("n"), 10, j.w.resources(), j.w.verifier,
		RegistrationProofs{p, p, p, p, p, p, p, p})
	require.NoError(t, err)
	token := []byte(i.token)
	return admit.RegisterTokenForAuthenticatedCreation(i.id, i.v.body, i.body.issuer, manager, i.body.requestedTokenFamily,
		i.v.profile, i.v.name, i.v.ticker, 6,
		func(state.AccountsAdapter, []byte, []byte, []byte, []byte, []byte, uint32, [][]byte) ([]byte, *vmcommon.VMOutput, error) {
			return bytes.Clone(token), &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, ReturnData: [][]byte{bytes.Clone(token)}}, nil
		})
}

// The original registration writes the bootstrap readiness phase in its own
// operation, under the production host: keyed by the consumed intent, with its
// creation receipt, and charged to the global retained budget (owner ruling of
// 27 November 2026, Part A L2222-2223). Completion then uses that written
// phase and no other.
func TestQualSP223RegistrationCreatesTheBootstrapPhaseAndChargesIt(t *testing.T) {
	j := sp223JoinNew(t, sp229Ample())
	tr := j.phase()
	key, binding, err := j.records.encode(tr)
	require.NoError(t, err)
	decoded, err := j.host.decode(binding)
	require.NoError(t, err)
	j.owner.admitted[sp223BindingID(*decoded)] = struct{}{}
	before := bytes.Clone(qualRegistryValue(t, j.w.store, sp229BudgetKey))
	require.NoError(t, j.register(t, func(token []byte) (convergenceTransition, error) {
		require.Equal(t, []byte(j.intent.token), token)
		return tr, nil
	}))
	identity := qualRecordFrame([]byte("BOOTSTRAP_READINESS"), j.intent.id, []byte("TYPE_PROFILE_READINESS"), j.intent.id)
	require.Equal(t, append([]byte("ELRONDDRWA@convergence@"), identity...), key)
	require.NotEmpty(t, qualRegistryValue(t, j.w.store, string(key)))
	h := blake2b.NewBlake2b()
	require.Equal(t, h.Compute(string(binding)), qualRegistryValue(t, j.w.store, "ELRONDDRWA@convergenceReceipt@"+string(h.Compute(string(identity)))))
	after := qualRegistryValue(t, j.w.store, sp229BudgetKey)
	// Two registration records (association, BootstrapDeny), the phase receipt and the phase itself.
	require.Equal(t, binary.BigEndian.Uint64(before)+4, binary.BigEndian.Uint64(after))
	registration := sp229Register(j.intent)
	var registered uint64
	for n, write := range registration.writes {
		registered += uint64(len(write.value))
		if n < 2 {
			registered += uint64(len(write.key))
		}
	}
	registered -= uint64(len(sp229OpenIntent(j.intent).writes[0].value))
	require.Greater(t, binary.BigEndian.Uint64(after[8:])-binary.BigEndian.Uint64(before[8:]), registered+uint64(len(key)+len(binding)))
	require.Equal(t, uint64(1), binary.BigEndian.Uint64(qualRegistryValue(t, j.w.store, registryCountKey)))

	// The written phase is the one acknowledged and completed.
	for shard := uint32(0); shard < 3; shard++ {
		ack := sp223Acknowledge(t, shard, 11, binding)
		j.block.hash, j.block.header = ack.f.bHash, ack.f.w.Consumer
		require.NoError(t, j.records.acknowledge(tr, shard, ack.origin, ack.evidence(t, binding)))
	}
	require.NoError(t, j.records.complete(tr))
	_, progress, err := j.records.observe(tr)
	require.NoError(t, err)
	require.Equal(t, "COMPLETE", progress.status)
}

// An alternate action, digest, family or phase for the same token is refused
// at the original registration boundary, and the refusal keeps the intent
// OPEN, the registry count, the budget and the whole account state.
func TestQualSP223RegistrationRefusesAnotherPhaseForTheSameToken(t *testing.T) {
	changes := map[string]func(*convergenceTransition){
		"another action":  func(v *convergenceTransition) { v.action = bytes.Repeat([]byte{0x55}, 32) },
		"another digest":  func(v *convergenceTransition) { v.digest = bytes.Repeat([]byte{0x55}, 32) },
		"another family":  func(v *convergenceTransition) { v.context.family = []byte(ConvergenceFamilySetup) },
		"another phase":   func(v *convergenceTransition) { v.context.phase = []byte("SETUP_READY_ACK") },
		"another version": func(v *convergenceTransition) { v.version = 2 },
		"another token":   func(v *convergenceTransition) { v.token = []byte("OTHER-abcdef") },
		"two shards": func(v *convergenceTransition) {
			v.shards = []uint32{0, 1}
			v.requiredSet = blake2b.NewBlake2b().Compute(string(qualRecordFrame([]byte{0, 0, 0, 0}, []byte{0, 0, 0, 1})))
		},
		"shards out of place": func(v *convergenceTransition) {
			v.shards = []uint32{0, 1, 3}
			v.requiredSet = blake2b.NewBlake2b().Compute(string(qualRecordFrame([]byte{0, 0, 0, 0}, []byte{0, 0, 0, 1}, []byte{0, 0, 0, 3})))
		},
		"not created by the owning row": func(*convergenceTransition) {},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			j := sp223JoinNew(t, sp229Ample())
			tr := j.phase()
			change(&tr)
			if name != "not created by the owning row" {
				// Even an owner that would admit it cannot move the boundary's own check.
				if _, binding, err := j.records.encode(tr); err == nil {
					if decoded, e := j.host.decode(binding); e == nil {
						j.owner.admitted[sp223BindingID(*decoded)] = struct{}{}
					}
				}
			}
			root, journal := j.w.root(), j.w.store.JournalLen()
			budget := bytes.Clone(qualRegistryValue(t, j.w.store, sp229BudgetKey))
			open := bytes.Clone(qualRegistryValue(t, j.w.store, "ELRONDDRWA@registration@intent@"+string(j.intent.id)))
			require.Error(t, j.register(t, func([]byte) (convergenceTransition, error) { return tr, nil }))
			require.Equal(t, root, j.w.root())
			require.Equal(t, journal, j.w.store.JournalLen())
			require.Equal(t, budget, qualRegistryValue(t, j.w.store, sp229BudgetKey))
			require.Equal(t, open, qualRegistryValue(t, j.w.store, "ELRONDDRWA@registration@intent@"+string(j.intent.id)))
			require.Equal(t, uint64(0), binary.BigEndian.Uint64(qualRegistryValue(t, j.w.store, registryCountKey)))
		})
	}
}

// The phase created at registration is inside the budget: with room for the
// registration records but not for the phase, the whole registration is denied.
func TestQualSP223RegistrationWithoutRoomForItsPhaseIsDenied(t *testing.T) {
	for offset, admitted := range map[int]bool{-1: false, 0: true} {
		lim := sp229Ample()
		lim.records = uint64(6 + offset) // budget, intent, association, activation, receipt, phase
		j := sp223JoinNew(t, lim)
		tr := j.phase()
		_, binding, err := j.records.encode(tr)
		require.NoError(t, err)
		decoded, err := j.host.decode(binding)
		require.NoError(t, err)
		j.owner.admitted[sp223BindingID(*decoded)] = struct{}{}
		root := j.w.root()
		err = j.register(t, func([]byte) (convergenceTransition, error) { return tr, nil })
		require.Equal(t, admitted, err == nil, "%v", err)
		if !admitted {
			require.Equal(t, root, j.w.root())
			require.Equal(t, uint64(0), binary.BigEndian.Uint64(qualRegistryValue(t, j.w.store, registryCountKey)))
		}
	}
}
