package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-37, metachain side and the composition with three execution shards.
//
// The metachain is the real activated store of the lifecycle tests: the
// token is Active, its lifecycle record is SETUP of CEB epoch 1, written by
// the real activation. Over it run the real setupLifecycle (the one writer of
// the metachain's SETUP_SEALED and OPEN), the production convergence host of
// SP2-23 with this row's family owner, the production funding owner of
// SP2-79 and this row's origin. Each shard is SP2-32's real shard with this
// row's seal owner. Acknowledgements are the shard's own item, settled and
// read as canonically final through SP2-22's reader.
//
// Fixtures, because another row owns their production form: the Program
// Administration authorization of a setup transition and its resource
// reservation (setupLifecycleHost, SP2-38); the canonical lifecycle and CEB
// field providers of the lifecycle reader (SP2-26 remainder, SP2-38); the
// price entries (owner decision 25.1); the producers of the readiness and
// quiescence acknowledgements on a shard (SP2-38, and the OpenEffect rows),
// which here write SP2-23's item directly.

const sp237Token = "TOKEN-abcdef"

type sp237Authority struct {
	err             error
	calls, reserves int
}

func (a *sp237Authority) IsInterfaceNil() bool { return a == nil }
func (a *sp237Authority) VerifySetupTransition(*HeaderTimeContext, lifecycleReadView, string, []setupPhaseEvidence, []byte) error {
	a.calls++
	return a.err
}
func (a *sp237Authority) ReserveSetupTransition([]byte, uint64, []byte, []byte, []byte) error {
	a.reserves++
	return nil
}

type sp237Prices struct{ price CarrierPrice }

func (p *sp237Prices) IsInterfaceNil() bool { return p == nil }
func (p *sp237Prices) CarrierPrice(class string) (CarrierPrice, error) {
	if class != LifecycleSealCarrierClass {
		return CarrierPrice{}, ErrCarrierFunding
	}
	return p.price, nil
}

// sp237LegGas is the gas of one call under the test price: destination work,
// the larger outcome and completion.
const sp237LegGas = 40 + 9 + 30

type sp237World struct {
	t         *testing.T
	f         *qualLifecycleFixture
	block     *sp223Block
	authority *sp237Authority
	funding   *CarrierFunding
	origin    *LifecycleSealOrigin
	host      *ConvergenceHost
	life      *setupLifecycle
	shards    []*sp232Shard
	seals     []*LifecycleSeal
}

func sp237New(t *testing.T) *sp237World {
	t.Helper()
	w := &sp237World{t: t, f: qualLifecycleNew(t), authority: &sp237Authority{}}
	t.Cleanup(w.f.x.f.end)
	store := w.f.x.f.store
	if len(qualRegistryValue(t, store, sp223BudgetKey)) == 0 {
		budget := binary.BigEndian.AppendUint64(nil, 1)
		budget = binary.BigEndian.AppendUint64(budget, uint64(len(sp223BudgetKey)+32))
		budget = binary.BigEndian.AppendUint64(budget, 10)
		budget = binary.BigEndian.AppendUint64(budget, 0)
		qualRecordPut(t, store, []byte(sp223BudgetKey), budget)
	}
	base := newCanonicalTestFixture(t, 0, core.MetachainShardId)
	require.Equal(t, blake2b.NewBlake2b().Compute("x"), base.reader.accounts.args.Hasher.Compute("x"))
	w.block = &sp223Block{epoch: 10, hash: base.bHash, header: base.w.Consumer}
	w.build(base.reader)
	for id := uint32(0); id < 3; id++ {
		s := sp232ShardNew(t, id)
		// The token is the second member of the shard's registry.
		_, err := s.registry.DeltaFunction().ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{CallerAddr: core.ESDTSCAddress, CallValue: big.NewInt(0), CallType: vmData.AsynchronousCall,
				Arguments: [][]byte{[]byte(sp237Token), binary.BigEndian.AppendUint64(nil, 1)}},
			RecipientAddr: registryDeltaSystemAddress(id), Function: RegistryDeltaFunctionName})
		require.NoError(t, err)
		w.shards, w.seals = append(w.shards, s), append(w.seals, sp237Install(t, s))
		sp237Put(t, s, sp237Token, 1, "SETUP")
		// The shard holds the metachain's current CEB of the token.
		qualRecordPut(t, s.store, sp237Pointer(sp237Token), qualRecordFrame(binary.BigEndian.AppendUint64(nil, 1), w.f.hash))
		s.commit()
	}
	return w
}

func (w *sp237World) build(reader *canonicalResultReader) {
	w.t.Helper()
	store, hasher := w.f.x.f.store, blake2b.NewBlake2b()
	codec, err := newRegistrationRecords(store, &marshal.GogoProtoMarshalizer{}, hasher, 4096)
	require.NoError(w.t, err)
	w.funding, err = NewCarrierFunding(ArgsCarrierFunding{Accounts: store, Marshaller: &marshal.GogoProtoMarshalizer{}, Hasher: hasher,
		Block: w.block, Prices: &sp237Prices{CarrierPrice{Source: 100, Destination: 40, Success: 7, Refund: 9, Completion: 30}},
		Limits: sp223Ample(), RecordBytes: 4096})
	require.NoError(w.t, err)
	w.origin, err = NewLifecycleSealOrigin(ArgsLifecycleSealOrigin{Accounts: store, Marshaller: &marshal.GogoProtoMarshalizer{},
		Hasher: hasher, Funding: w.funding, Shards: 3, RecordBytes: 4096})
	require.NoError(w.t, err)
	require.False(w.t, w.origin.IsInterfaceNil())
	w.host, err = NewConvergenceHost(ArgsConvergenceHost{Accounts: store, Records: codec, Reader: reader, Block: w.block,
		Limits: sp223Ample(), EvidenceBytes: 1 << 20, Owners: map[string]ConvergenceFamilyOwner{}})
	require.NoError(w.t, err)
	// As the node factory installs it.
	require.NoError(w.t, w.host.SetFamilyOwner(ConvergenceFamilySetup, w.origin))
	w.life, err = newSetupLifecycle(w.f.r, w.host, w.authority)
	require.NoError(w.t, err)
}

func (w *sp237World) root() []byte {
	root, err := w.f.x.f.store.RootHash()
	require.NoError(w.t, err)
	return root
}

func (w *sp237World) held() []byte {
	return qualActivationValue(w.t, w.f.x.f.store, sp237Key(sp237Token))
}

func sp237Hash(fields ...[]byte) []byte {
	return blake2b.NewBlake2b().Compute(string(qualRecordFrame(fields...)))
}

// transition is the independently computed transition of one setup phase for
// the metachain state it belongs to and the state before it.
func (w *sp237World) transition(phase, state, before string) convergenceTransition {
	epoch := binary.BigEndian.AppendUint64(nil, 1)
	ids := [][]byte{{0, 0, 0, 0}, {0, 0, 0, 1}, {0, 0, 0, 2}}
	predecessor := bytes.Clone(w.f.hash)
	if before != "" {
		predecessor = blake2b.NewBlake2b().Compute(string(sp237Record(sp237Token, 1, before)))
	}
	return convergenceTransition{action: sp237Hash([]byte("SETUP_LIFECYCLE"), []byte(sp237Token), epoch, w.f.hash), digest: bytes.Clone(w.f.hash),
		token: []byte(sp237Token), target: blake2b.NewBlake2b().Compute(string(sp237Record(sp237Token, 1, state))),
		dependencies: blake2b.NewBlake2b().Compute("setup dependency commitment"), requiredSet: sp237Hash(ids...), version: 1,
		shards: []uint32{0, 1, 2}, context: &convergencePhaseContext{family: []byte("SETUP_LIFECYCLE"), phase: []byte(phase),
			lineage: qualRecordFrame([]byte(sp237Token), epoch, w.f.hash), predecessor: predecessor}}
}

func (w *sp237World) ready() convergenceTransition {
	return w.transition("SETUP_READY_ACK", "SETUP", "")
}
func (w *sp237World) sealed() convergenceTransition {
	return w.transition("SETUP_SEALED", "SETUP_SEALED", "SETUP")
}
func (w *sp237World) quiescent() convergenceTransition {
	return w.transition("DRWAQuiescenceAck", "SETUP_SEALED", "SETUP_SEALED")
}

func (w *sp237World) binding(tr convergenceTransition) []byte {
	_, binding, err := w.life.phases.encode(tr)
	require.NoError(w.t, err)
	return binding
}

// acknowledge settles the shard's block and presents its item for tr as
// canonical-final evidence to the metachain.
func (w *sp237World) acknowledge(tr convergenceTransition, s *sp232Shard) error {
	w.t.Helper()
	key, _ := sp237AckItem(s, w.binding(tr))
	s.settle()
	w.block.hash, w.block.header = s.f.bHash, s.f.w.Consumer
	return w.life.phases.acknowledge(tr, s.id, s.f.hash(s.f.w.Account.ExecutedHeader), sp223Evidence(w.t, s.witness(key)))
}

// produce stands for the shard-side producer of a readiness or quiescence
// acknowledgement, which another row owns.
func (w *sp237World) produce(tr convergenceTransition, s *sp232Shard) {
	w.t.Helper()
	codec, err := newRegistrationRecords(s.store, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(w.t, err)
	writer, err := NewConvergenceAckWriter(codec, s.id)
	require.NoError(w.t, err)
	require.NoError(w.t, writer.Acknowledge(w.binding(tr)))
}

func (w *sp237World) advance(next string, phases ...convergenceTransition) error {
	return w.f.x.f.boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		output, err := w.life.advanceOwned(op, w.f.context, []byte(sp237Token), 1, w.f.hash, next, phases, []byte("setup certificate"))
		return []*vmcommon.VMOutput{output}, err
	})
}

// denied requires an error from a metachain request and no write.
func (w *sp237World) denied(label string, run func() error) {
	w.t.Helper()
	root, journal := w.root(), w.f.x.f.store.JournalLen()
	require.Error(w.t, run(), label)
	require.Equal(w.t, root, w.root(), label)
	require.Equal(w.t, journal, w.f.x.f.store.JournalLen(), label)
}

func (w *sp237World) replicate(phase string, binding []byte) []vmcommon.OutputTransfer {
	w.t.Helper()
	output := &vmcommon.VMOutput{}
	left, err := w.origin.Replicate(output, []byte(sp237Token), 1, phase, binding, 100+3*sp237LegGas+5)
	require.NoError(w.t, err)
	require.Equal(w.t, uint64(5), left)
	transfers := sp232Transfers(output)
	require.Len(w.t, transfers, 3)
	for shard, transfer := range transfers {
		require.Equal(w.t, uint64(sp237LegGas), transfer.GasLimit)
		require.Equal(w.t, vmData.AsynchronousCall, transfer.CallType)
		require.Equal(w.t, core.ESDTSCAddress, transfer.SenderAddress)
		require.Contains(w.t, output.OutputAccounts, string(registryDeltaSystemAddress(uint32(shard))))
	}
	return transfers
}

func (w *sp237World) deliver(s *sp232Shard, transfer vmcommon.OutputTransfer) (*vmcommon.VMOutput, error) {
	return s.call(sp232Input(w.t, registryDeltaSystemAddress(s.id), transfer, "seal result hash"))
}

// setupLeg is the seal's answer to a setup-only admin leg on one shard.
func (w *sp237World) setupLeg(shard int) error {
	return w.seals[shard].VerifyAdminEffect(AdminEffect{TokenID: []byte(sp237Token), Binding: "CURRENT_CEB", Epoch: 1})
}

// callback is the native callback of a delivered call, as the metachain
// receives it.
func sp237Callback(shard uint32, output *vmcommon.VMOutput) *vmcommon.ContractCallInput {
	arguments := append([][]byte{{byte(vmcommon.Ok)}}, output.ReturnData...)
	return &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: registryDeltaSystemAddress(shard), CallValue: big.NewInt(0),
		CallType: vmData.AsynchronousCallBack, GasProvided: output.GasRemaining, Arguments: arguments},
		RecipientAddr: bytes.Clone(core.ESDTSCAddress), Function: RegistryAcknowledgmentFunctionName}
}

func TestQualSP237SetupSealComposition(t *testing.T) {
	w := sp237New(t)
	ready, sealed, quiescent := w.ready(), w.sealed(), w.quiescent()
	require.Equal(t, sp237Record(sp237Token, 1, "SETUP"), w.held())

	// The owner derives exactly the independently computed coordinates.
	action, digest, target, lineage, predecessor, epoch, err := w.origin.SetupPhaseCoordinates([]byte(sp237Token), "SETUP_READY_ACK")
	require.NoError(t, err)
	require.Equal(t, [][]byte{ready.action, ready.digest, ready.target, ready.context.lineage, ready.context.predecessor},
		[][]byte{action, digest, target, lineage, predecessor})
	require.Equal(t, uint64(1), epoch)

	// SETUP: no seal phase exists, nothing can be replicated, nothing opens.
	w.denied("seal phase while SETUP", func() error { return w.life.phases.create(sealed) })
	w.denied("quiescence phase while SETUP", func() error { return w.life.phases.create(quiescent) })
	w.denied("replicate a seal the metachain does not hold", func() error {
		_, e := w.origin.Replicate(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "SETUP_SEALED", w.binding(sealed), 1<<20)
		return e
	})
	w.denied("replicate OPEN while SETUP", func() error {
		_, e := w.origin.Replicate(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "OPEN", nil, 1<<20)
		return e
	})
	for shard := range w.shards {
		require.NoError(t, w.setupLeg(shard), "setup-only legs are admitted in SETUP")
	}

	// Readiness of every shard is required before the seal.
	require.NoError(t, w.life.phases.create(ready))
	for _, s := range w.shards[:2] {
		w.produce(ready, s)
		require.NoError(t, w.acknowledge(ready, s))
	}
	w.denied("readiness incomplete", func() error { return w.life.phases.complete(ready) })
	w.denied("seal with one shard's readiness missing", func() error { return w.advance("SETUP_SEALED", ready) })
	w.produce(ready, w.shards[2])
	require.NoError(t, w.acknowledge(ready, w.shards[2]))
	require.NoError(t, w.life.phases.complete(ready))
	w.denied("OPEN from SETUP", func() error { return w.advance("OPEN", ready, ready) })
	w.authority.err = errors.New("Program Administration refuses")
	w.denied("seal without the authorization", func() error { return w.advance("SETUP_SEALED", ready) })
	w.authority.err = nil
	require.NoError(t, w.advance("SETUP_SEALED", ready))
	require.Equal(t, sp237Record(sp237Token, 1, "SETUP_SEALED"), w.held())

	// The metachain is sealed: readiness is no longer a phase, and the seal
	// cannot be taken back or repeated.
	w.denied("readiness phase after the seal", func() error { return w.host.VerifyTransition(w.binding(ready)) })
	w.denied("seal twice", func() error { return w.advance("SETUP_SEALED", ready) })

	// The seal is replicated, once, funded for all three shards.
	require.NoError(t, w.life.phases.create(sealed))
	binding := w.binding(sealed)
	w.denied("underfunded replication", func() error {
		_, e := w.origin.Replicate(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "SETUP_SEALED", binding, 100+3*sp237LegGas-1)
		return e
	})
	w.denied("the seal without its binding", func() error {
		_, e := w.origin.Replicate(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "SETUP_SEALED", nil, 1<<20)
		return e
	})
	w.denied("the seal under the readiness binding", func() error {
		_, e := w.origin.Replicate(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "SETUP_SEALED", w.binding(ready), 1<<20)
		return e
	})
	w.denied("the seal under the quiescence binding", func() error {
		_, e := w.origin.Replicate(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "SETUP_SEALED", w.binding(quiescent), 1<<20)
		return e
	})
	w.denied("another epoch", func() error {
		_, e := w.origin.Replicate(&vmcommon.VMOutput{}, []byte(sp237Token), 2, "SETUP_SEALED", binding, 1<<20)
		return e
	})
	w.denied("the terminal seal is not this owner's", func() error {
		_, e := w.origin.Replicate(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "WIND_DOWN_SEALED", binding, 1<<20)
		return e
	})
	w.denied("no output", func() error {
		_, e := w.origin.Replicate(nil, []byte(sp237Token), 1, "SETUP_SEALED", binding, 1<<20)
		return e
	})
	legs := w.replicate("SETUP_SEALED", binding)
	w.denied("replicated once", func() error {
		_, e := w.origin.Replicate(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "SETUP_SEALED", binding, 1<<20)
		return e
	})

	// Shards 0 and 1 apply the seal; shard 2 lags.
	outputs := make([]*vmcommon.VMOutput, 3)
	for id := 0; id < 2; id++ {
		outputs[id], err = w.deliver(w.shards[id], legs[id])
		require.NoError(t, err)
		require.Equal(t, sp237Record(sp237Token, 1, "SETUP_SEALED"), w.shards[id].sp237Held(sp237Token))
		require.ErrorIs(t, w.setupLeg(id), ErrLifecycleSeal, "a sealed shard refuses setup-only legs")
		require.NoError(t, w.acknowledge(sealed, w.shards[id]))
	}
	// A leg addressed to another shard is not this shard's.
	_, err = w.deliver(w.shards[2], legs[0])
	require.NoError(t, err, "the same seal of the same epoch, whichever copy carries it")
	require.NoError(t, w.shards[2].store.RevertToSnapshot(0))
	require.Equal(t, sp237Record(sp237Token, 1, "SETUP"), w.shards[2].sp237Held(sp237Token))

	// With shard 2 lagging the metachain cannot open: its seal acknowledgement
	// is missing, whatever else is presented.
	w.denied("seal phase incomplete", func() error { return w.life.phases.complete(sealed) })
	require.NoError(t, w.life.phases.create(quiescent))
	for _, s := range w.shards {
		w.produce(quiescent, s)
		require.NoError(t, w.acknowledge(quiescent, s))
	}
	require.NoError(t, w.life.phases.complete(quiescent))
	w.denied("OPEN with one seal acknowledgement missing", func() error { return w.advance("OPEN", sealed, quiescent) })
	w.denied("OPEN with the quiescence twice", func() error { return w.advance("OPEN", quiescent, quiescent) })
	w.denied("OPEN with readiness for the seal", func() error { return w.advance("OPEN", ready, quiescent) })
	w.denied("a seal acknowledgement of shard 2 from shard 1's item", func() error {
		key, _ := sp237AckItem(w.shards[1], binding)
		return w.life.phases.acknowledge(sealed, 2, w.shards[1].f.hash(w.shards[1].f.w.Account.ExecutedHeader),
			sp223Evidence(t, w.shards[1].witness(key)))
	})
	w.denied("replicate OPEN while sealed", func() error {
		_, e := w.origin.Replicate(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "OPEN", nil, 1<<20)
		return e
	})
	require.Equal(t, sp237Record(sp237Token, 1, "SETUP_SEALED"), w.held())

	// The lagging shard: OPEN out of order and altered seals are refused and
	// leave nothing; then the real seal arrives late, and twice.
	lagging := w.shards[2]
	lagging.sp237Refused("OPEN before the seal", sp237Seal(2, sp237Token, 1, "OPEN", nil))
	altered := bytes.Clone(binding)
	altered[len(altered)-1] ^= 1
	lagging.sp237Refused("a binding with another predecessor", sp237Seal(2, sp237Token, 1, "SETUP_SEALED", altered))
	absent, _ := sp237AckItem(lagging, binding)
	require.Empty(t, lagging.value(core.SystemAccountAddress, absent), "a lagging shard holds no acknowledgement")
	lagging.sp237Refused("the quiescence binding as a seal", sp237Seal(2, sp237Token, 1, "SETUP_SEALED", w.binding(quiescent)))
	lagging.sp237Refused("the seal of another epoch", sp237Seal(2, sp237Token, 2, "SETUP_SEALED", binding))
	require.Equal(t, sp237Record(sp237Token, 1, "SETUP"), lagging.sp237Held(sp237Token))

	// The outcome of shards 0 and 1 is funded once; shard 2 is redriven.
	for id := uint32(0); id < 2; id++ {
		outcome, result, e := w.origin.Outcome(sp237Callback(id, outputs[id]))
		require.NoError(t, e)
		require.Equal(t, &LifecycleSealOutcome{Shard: id, TokenID: []byte(sp237Token), Epoch: 1, Phase: "SETUP_SEALED"}, outcome)
		require.True(t, result.Applied)
		require.False(t, result.Terminal)
		_, result, e = w.origin.Outcome(sp237Callback(id, outputs[id]))
		require.NoError(t, e)
		require.False(t, result.Applied, "a repeated outcome changes nothing")
	}
	w.denied("redrive of a shard that answered", func() error {
		_, e := w.origin.Redrive(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "SETUP_SEALED", binding, 0, 1<<20)
		return e
	})
	w.denied("redrive of a shard outside", func() error {
		_, e := w.origin.Redrive(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "SETUP_SEALED", binding, 3, 1<<20)
		return e
	})
	w.denied("redrive under another binding", func() error {
		_, e := w.origin.Redrive(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "SETUP_SEALED", altered, 2, 1<<20)
		return e
	})
	redriven := &vmcommon.VMOutput{}
	_, err = w.origin.Redrive(redriven, []byte(sp237Token), 1, "SETUP_SEALED", binding, 2, 1<<20)
	require.NoError(t, err)
	again := sp232Transfers(redriven)
	require.Len(t, again, 1)
	require.Equal(t, legs[2].Data, again[0].Data, "the same call")
	require.Equal(t, legs[2].AsyncData, again[0].AsyncData)
	outputs[2], err = w.deliver(lagging, again[0])
	require.NoError(t, err)
	sealedRoot := lagging.commit()
	_, err = w.deliver(lagging, legs[2])
	require.NoError(t, err, "the first copy, late")
	require.Equal(t, sealedRoot, lagging.commit(), "delivered twice: nothing changes")
	require.ErrorIs(t, w.setupLeg(2), ErrLifecycleSeal)
	_, result, err := w.origin.Outcome(sp237Callback(2, outputs[2]))
	require.NoError(t, err)
	require.True(t, result.Applied)
	require.True(t, result.Terminal)

	// Only now, with the complete set, the seal phase completes and OPEN is
	// admitted.
	require.NoError(t, w.acknowledge(sealed, lagging))
	require.NoError(t, w.life.phases.complete(sealed))
	require.NoError(t, w.advance("OPEN", sealed, quiescent))
	require.Equal(t, sp237Record(sp237Token, 1, "OPEN"), w.held())

	// OPEN is no way back, and the seal's phases do not survive it.
	w.denied("seal after OPEN", func() error { return w.advance("SETUP_SEALED", ready) })
	w.denied("OPEN twice", func() error { return w.advance("OPEN", sealed, quiescent) })
	w.denied("seal phase after OPEN", func() error { return w.host.VerifyTransition(binding) })
	w.denied("replicate the seal after OPEN", func() error {
		_, e := w.origin.Redrive(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "SETUP_SEALED", binding, 2, 1<<20)
		return e
	})
	w.denied("OPEN with a binding", func() error {
		_, e := w.origin.Replicate(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "OPEN", binding, 1<<20)
		return e
	})

	// OPEN propagates; the lagging shard stays sealed, never back in setup.
	open := w.replicate("OPEN", nil)
	for id := 0; id < 2; id++ {
		_, err = w.deliver(w.shards[id], open[id])
		require.NoError(t, err)
		require.Equal(t, sp237Record(sp237Token, 1, "OPEN"), w.shards[id].sp237Held(sp237Token))
	}
	require.Equal(t, sp237Record(sp237Token, 1, "SETUP_SEALED"), lagging.sp237Held(sp237Token))
	for shard := range w.shards {
		require.ErrorIs(t, w.setupLeg(shard), ErrLifecycleSeal, "no setup-only leg on an open or a lagging shard")
	}
	_, err = w.deliver(lagging, open[2])
	require.NoError(t, err)
	require.Equal(t, sp237Record(sp237Token, 1, "OPEN"), lagging.sp237Held(sp237Token))
	require.ErrorIs(t, w.setupLeg(2), ErrLifecycleSeal)
}

func TestQualSP237RestartKeepsEveryDecision(t *testing.T) {
	w := sp237New(t)
	ready, sealed := w.ready(), w.sealed()
	require.NoError(t, w.life.phases.create(ready))
	for _, s := range w.shards {
		w.produce(ready, s)
		require.NoError(t, w.acknowledge(ready, s))
	}
	require.NoError(t, w.life.phases.complete(ready))
	require.NoError(t, w.advance("SETUP_SEALED", ready))
	require.NoError(t, w.life.phases.create(sealed))
	binding := w.binding(sealed)
	legs := w.replicate("SETUP_SEALED", binding)
	_, err := w.deliver(w.shards[0], legs[0])
	require.NoError(t, err)

	// The metachain store is committed and reopened; every owner is rebuilt.
	store := w.f.x.f.store
	root, err := store.Commit()
	require.NoError(t, err)
	require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	base := newCanonicalTestFixture(t, 0, core.MetachainShardId)
	w.build(base.reader)
	require.Equal(t, sp237Record(sp237Token, 1, "SETUP_SEALED"), w.held())
	require.NoError(t, w.host.VerifyTransition(binding))
	w.denied("readiness after restart", func() error { return w.host.VerifyTransition(w.binding(ready)) })
	w.denied("replicated once, after restart", func() error {
		_, e := w.origin.Replicate(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "SETUP_SEALED", binding, 1<<20)
		return e
	})
	w.denied("OPEN after restart, seal not acknowledged", func() error {
		_, e := w.origin.Replicate(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "OPEN", nil, 1<<20)
		return e
	})
	redriven := &vmcommon.VMOutput{}
	_, err = w.origin.Redrive(redriven, []byte(sp237Token), 1, "SETUP_SEALED", binding, 1, 1<<20)
	require.NoError(t, err)
	require.Equal(t, legs[1].Data, sp232Transfers(redriven)[0].Data)

	// The shards are reopened too: the sealed one stays sealed, the lagging
	// ones apply the redriven and the first call exactly once.
	for _, s := range w.shards {
		s.restart()
	}
	require.ErrorIs(t, w.setupLeg(0), ErrLifecycleSeal)
	require.NoError(t, w.setupLeg(1))
	_, err = w.deliver(w.shards[1], sp232Transfers(redriven)[0])
	require.NoError(t, err)
	after := w.shards[1].commit()
	_, err = w.deliver(w.shards[1], legs[1])
	require.NoError(t, err)
	require.Equal(t, after, w.shards[1].commit())
	require.ErrorIs(t, w.setupLeg(1), ErrLifecycleSeal)
}

// A governed requalification is the only way out of a sealed epoch. Its
// transitions belong to SP2-52; here the state it leaves (the next CEB epoch
// in SETUP, on a shard and on the metachain) is put into the stores, and the
// old epoch's seal must be worth nothing in it.
func TestQualSP237OldSealNeverAuthorizesTheNextEpoch(t *testing.T) {
	w := sp237New(t)
	ready, sealed := w.ready(), w.sealed()
	require.NoError(t, w.life.phases.create(ready))
	for _, s := range w.shards {
		w.produce(ready, s)
		require.NoError(t, w.acknowledge(ready, s))
	}
	require.NoError(t, w.life.phases.complete(ready))
	require.NoError(t, w.advance("SETUP_SEALED", ready))
	require.NoError(t, w.life.phases.create(sealed))
	old := w.binding(sealed)
	legs := w.replicate("SETUP_SEALED", old)
	s := w.shards[0]
	_, err := w.deliver(s, legs[0])
	require.NoError(t, err)
	oldKey, oldValue := sp237AckItem(s, old)

	// The shard after requalification: epoch 2, SETUP again.
	sp237Put(t, s, sp237Token, 2, "SETUP")
	require.ErrorIs(t, w.setupLeg(0), ErrLifecycleSeal, "a setup leg of the old epoch")
	require.NoError(t, w.seals[0].VerifyAdminEffect(AdminEffect{TokenID: []byte(sp237Token), Binding: "CURRENT_CEB", Epoch: 2}))
	s.sp237Refused("the old epoch's seal", sp232Input(t, registryDeltaSystemAddress(0), legs[0], "seal result hash"))
	s.sp237Refused("the old binding under the new epoch", sp237Seal(0, sp237Token, 2, "SETUP_SEALED", old))
	s.sp237Refused("OPEN of the new epoch without its seal", sp237Seal(0, sp237Token, 2, "OPEN", nil))
	fresh := sp237Binding(s, ConvergenceFamilySetup, "SETUP_SEALED", sp237Token, 2, "SETUP_SEALED", 0, 1, 2)
	s.sp237Applied("the new epoch's seal", sp237Seal(0, sp237Token, 2, "SETUP_SEALED", fresh))
	key, value := sp237AckItem(s, fresh)
	require.Equal(t, value, s.value(core.SystemAccountAddress, key))
	require.Equal(t, oldValue, s.value(core.SystemAccountAddress, oldKey), "the old item stays what it was")
	s.sp237Refused("the old binding after the new seal", sp237Seal(0, sp237Token, 2, "SETUP_SEALED", old))

	// The metachain after requalification: epoch 2 and its CEB, SETUP.
	store := w.f.x.f.store
	next := blake2b.NewBlake2b().Compute("the next CEB")
	qualRecordPut(t, store, sp237Key(sp237Token), sp237Record(sp237Token, 2, "SETUP"))
	w.denied("lifecycle of epoch 2 under the pointer of epoch 1", func() error { return w.host.VerifyTransition(old) })
	qualRecordPut(t, store, append([]byte(currentLocalPointerPrefix), qualRecordFrame([]byte(sp237Token))...),
		qualRecordFrame(binary.BigEndian.AppendUint64(nil, 2), next))
	w.denied("the old seal phase", func() error { return w.host.VerifyTransition(old) })
	w.denied("the old readiness phase", func() error { return w.host.VerifyTransition(w.binding(ready)) })
	w.denied("replicating the old seal", func() error {
		_, e := w.origin.Redrive(&vmcommon.VMOutput{}, []byte(sp237Token), 1, "SETUP_SEALED", old, 1, 1<<20)
		return e
	})
	action, digest, _, lineage, predecessor, epoch, err := w.origin.SetupPhaseCoordinates([]byte(sp237Token), "SETUP_READY_ACK")
	require.NoError(t, err)
	require.Equal(t, uint64(2), epoch)
	require.Equal(t, next, digest)
	require.Equal(t, next, predecessor)
	require.NotEqual(t, ready.action, action)
	require.NotEqual(t, ready.context.lineage, lineage)
}

func TestQualSP237OriginRefusals(t *testing.T) {
	w := sp237New(t)
	token := []byte(sp237Token)
	// Construction.
	args := ArgsLifecycleSealOrigin{Accounts: w.f.x.f.store, Marshaller: &marshal.GogoProtoMarshalizer{}, Hasher: blake2b.NewBlake2b(),
		Funding: w.funding, Shards: 3, RecordBytes: 4096}
	for label, change := range map[string]func(*ArgsLifecycleSealOrigin){
		"no store":           func(a *ArgsLifecycleSealOrigin) { a.Accounts = nil },
		"no funding":         func(a *ArgsLifecycleSealOrigin) { a.Funding = nil },
		"too many shards":    func(a *ArgsLifecycleSealOrigin) { a.Shards = maxCarrierLegs + 1 },
		"no hasher":          func(a *ArgsLifecycleSealOrigin) { a.Hasher = nil },
		"no record capacity": func(a *ArgsLifecycleSealOrigin) { a.RecordBytes = 0 },
	} {
		changed := args
		change(&changed)
		origin, err := NewLifecycleSealOrigin(changed)
		require.Error(t, err, label)
		require.Nil(t, origin, label)
	}
	require.True(t, (*LifecycleSealOrigin)(nil).IsInterfaceNil())

	// The family owner: each coordinate, altered alone.
	ready := w.ready()
	good, err := decodeConvergenceBinding(w.host.args.Records, w.binding(ready))
	require.NoError(t, err)
	require.NoError(t, w.origin.VerifyTransition(*good))
	other := bytes.Repeat([]byte{9}, 32)
	for label, change := range map[string]func(*ConvergenceBinding){
		"another family":    func(b *ConvergenceBinding) { b.Family = []byte(ConvergenceFamilyCEB) },
		"unknown phase":     func(b *ConvergenceBinding) { b.Phase = []byte("SETUP_OPEN") },
		"a later phase":     func(b *ConvergenceBinding) { b.Phase = []byte("SETUP_SEALED") },
		"another token":     func(b *ConvergenceBinding) { b.Token = []byte("OTHER-0a1b2c") },
		"invalid token":     func(b *ConvergenceBinding) { b.Token = []byte("x") },
		"another epoch":     func(b *ConvergenceBinding) { b.Version = 2 },
		"another instance":  func(b *ConvergenceBinding) { b.Action = other },
		"another CEB":       func(b *ConvergenceBinding) { b.Digest = other },
		"another target":    func(b *ConvergenceBinding) { b.Target = other },
		"another lineage":   func(b *ConvergenceBinding) { b.Lineage = []byte("lineage") },
		"another parent":    func(b *ConvergenceBinding) { b.Predecessor = other },
		"a shard missing":   func(b *ConvergenceBinding) { b.Shards = []uint32{0, 1} },
		"shards reordered":  func(b *ConvergenceBinding) { b.Shards = []uint32{0, 2, 1} },
		"a shard too many":  func(b *ConvergenceBinding) { b.Shards = []uint32{0, 1, 2, 3} },
		"another shard set": func(b *ConvergenceBinding) { b.Shards = []uint32{1, 2, 3} },
	} {
		changed := *good
		change(&changed)
		require.ErrorIs(t, w.origin.VerifyTransition(changed), ErrLifecycleSeal, label)
	}
	_, _, _, _, _, _, err = w.origin.SetupPhaseCoordinates(token, "WIND_DOWN_SEALED")
	require.ErrorIs(t, err, ErrLifecycleSeal)
	_, _, _, _, _, _, err = w.origin.SetupPhaseCoordinates([]byte("OTHER-0a1b2c"), "SETUP_READY_ACK")
	require.ErrorIs(t, err, ErrLifecycleSeal, "a token without a lifecycle record")

	// The callback: its form, and an outcome nobody funded.
	output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: sp237LegGas,
		ReturnData: [][]byte{token, binary.BigEndian.AppendUint64(nil, 1), []byte("SETUP_SEALED")}}
	form := func(change func(*vmcommon.ContractCallInput)) error {
		input := sp237Callback(1, output)
		change(input)
		_, _, e := w.origin.Outcome(input)
		return e
	}
	for label, change := range map[string]func(*vmcommon.ContractCallInput){
		"not a callback":    func(i *vmcommon.ContractCallInput) { i.CallType = vmData.AsynchronousCall },
		"another function":  func(i *vmcommon.ContractCallInput) { i.Function = "other" },
		"another recipient": func(i *vmcommon.ContractCallInput) { i.RecipientAddr = registryDeltaSystemAddress(0) },
		"with value":        func(i *vmcommon.ContractCallInput) { i.CallValue = big.NewInt(1) },
		"without a value":   func(i *vmcommon.ContractCallInput) { i.CallValue = nil },
		"a short sender":    func(i *vmcommon.ContractCallInput) { i.CallerAddr = []byte{1} },
		"another sender":    func(i *vmcommon.ContractCallInput) { i.CallerAddr = bytes.Repeat([]byte{7}, 32) },
		"a sender that ends as a shard": func(i *vmcommon.ContractCallInput) {
			i.CallerAddr = append(bytes.Repeat([]byte{7}, 31), 1)
		},
		"a shard outside":      func(i *vmcommon.ContractCallInput) { i.CallerAddr = registryDeltaSystemAddress(3) },
		"a refused call":       func(i *vmcommon.ContractCallInput) { i.Arguments[0] = []byte{byte(vmcommon.UserError)} },
		"three arguments":      func(i *vmcommon.ContractCallInput) { i.Arguments = i.Arguments[:3] },
		"a short epoch":        func(i *vmcommon.ContractCallInput) { i.Arguments[2] = []byte{1} },
		"an invalid token":     func(i *vmcommon.ContractCallInput) { i.Arguments[1] = []byte("x") },
		"a phase not replicat": func(i *vmcommon.ContractCallInput) { i.Arguments[3] = []byte("SETUP") },
	} {
		w.denied(label, func() error { return form(change) })
		require.ErrorIs(t, form(change), ErrLifecycleSeal, label)
	}
	_, _, err = w.origin.Outcome(nil)
	require.ErrorIs(t, err, ErrLifecycleSeal)
	// The terminal seal is another family's: with the metachain's record in
	// that state and a well-formed retirement binding, this owner refuses.
	store := w.f.x.f.store
	qualRecordPut(t, store, sp237Key(sp237Token), sp237Record(sp237Token, 1, "WIND_DOWN_SEALED"))
	retirement := sp237BindingOf(w.shards[0], sp237SetupCoordinates(w.shards[0], sp237Token, 1, w.f.hash), ConvergenceFamilyRetirement,
		"WIND_DOWN_SEALED", sp237Token, 1, "WIND_DOWN_SEALED", 0, 1, 2)
	_, err = w.origin.Replicate(&vmcommon.VMOutput{}, token, 1, "WIND_DOWN_SEALED", retirement, 1<<20)
	require.ErrorIs(t, err, ErrLifecycleSeal)
	qualRecordPut(t, store, sp237Key(sp237Token), sp237Record(sp237Token, 1, "SETUP"))
	w.denied("an outcome of a seal that was never replicated", func() error { return form(func(*vmcommon.ContractCallInput) {}) })
}
