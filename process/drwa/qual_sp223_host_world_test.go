package drwa

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/stretchr/testify/require"
)

// SP2-23. The host, the progress owner, the canonical result reader, the
// account and data tries, the journals and the retained budget are production
// code. Synthetic and labelled so: the header-proof, ancestry and integrity
// oracles of the canonical fixture, and the family owners, which belong to the
// rows that own each family's producer. Limits are experimental inputs.

// sp223Owner stands for a family's producing row: it admits exactly the
// transitions that row has created.
type sp223Owner struct {
	admitted map[string]struct{}
	calls    int
}

func (o *sp223Owner) IsInterfaceNil() bool { return o == nil }
func (o *sp223Owner) VerifyTransition(b ConvergenceBinding) error {
	o.calls++
	if _, exists := o.admitted[sp223BindingID(b)]; !exists {
		return errConvergence
	}
	return nil
}

func sp223BindingID(b ConvergenceBinding) string {
	ids := make([][]byte, len(b.Shards))
	for i, shard := range b.Shards {
		ids[i] = binary.BigEndian.AppendUint32(nil, shard)
	}
	return string(qualRecordFrame(b.Family, b.Action, b.Digest, b.Phase, b.Token, binary.BigEndian.AppendUint64(nil, b.Version),
		b.Target, b.Dependencies, b.RequiredSet, qualRecordFrame(ids...), b.Lineage, b.Predecessor))
}

type sp223Block struct {
	hash, header []byte
	epoch        uint32
}

func (b *sp223Block) IsInterfaceNil() bool { return b == nil }
func (b *sp223Block) ExecutingBlock() ([]byte, []byte, uint32, error) {
	if len(b.hash) == 0 {
		return nil, nil, 0, ErrFinalityImport
	}
	return bytes.Clone(b.hash), bytes.Clone(b.header), b.epoch, nil
}

type sp223World struct {
	t       *testing.T
	store   *qualNativeStore
	hasher  hashing.Hasher
	block   *sp223Block
	owner   *sp223Owner
	limits  RegistrationResourceLimits
	reader  *canonicalResultReader
	host    *ConvergenceHost
	records *convergenceRecords
}

func sp223New(t *testing.T, limits RegistrationResourceLimits) *sp223World {
	t.Helper()
	// One canonical fixture supplies the reader: its proof cache and oracles
	// do not depend on the producing shard.
	base := newCanonicalTestFixture(t, 0, core.MetachainShardId)
	w := &sp223World{t: t, store: qualRegistrationStore(t, 0), hasher: base.reader.accounts.args.Hasher, block: &sp223Block{epoch: 10, hash: base.bHash, header: base.w.Consumer},
		owner: &sp223Owner{admitted: map[string]struct{}{}}, limits: limits, reader: base.reader}
	t.Cleanup(func() { _ = w.store.Close() })
	budget := binary.BigEndian.AppendUint64(nil, 1)
	budget = binary.BigEndian.AppendUint64(budget, uint64(len(sp223BudgetKey)+32))
	budget = binary.BigEndian.AppendUint64(budget, 10)
	budget = binary.BigEndian.AppendUint64(budget, 0)
	qualRecordPut(t, w.store, []byte(sp223BudgetKey), budget)
	_, err := w.store.Commit()
	require.NoError(t, err)
	w.build()
	return w
}

const sp223BudgetKey = "ELRONDDRWA@scopedAdmission@budget"

func sp223Ample() RegistrationResourceLimits {
	return RegistrationResourceLimits{Records: 1 << 20, RetainedBytes: 1 << 40, NewRecordsPerEpoch: 1 << 20}
}

// build constructs every owner from the store and the configured inputs only.
func (w *sp223World) build() {
	boundary, err := NewRollbackContainment(w.store)
	require.NoError(w.t, err)
	codec, err := newRegistrationRecords(w.store, &marshal.GogoProtoMarshalizer{}, w.hasher, 4096)
	require.NoError(w.t, err)
	owners := map[string]ConvergenceFamilyOwner{}
	for family := range convergenceFamilies {
		owners[family] = w.owner
	}
	w.host, err = NewConvergenceHost(ArgsConvergenceHost{Accounts: w.store, Records: codec, Reader: w.reader, Block: w.block,
		Limits: w.limits, EvidenceBytes: 1 << 20, Owners: owners})
	require.NoError(w.t, err)
	w.records, err = newConvergenceRecords(w.store, boundary, &marshal.GogoProtoMarshalizer{}, w.hasher, 4096, 16, w.host)
	require.NoError(w.t, err)
}

func (w *sp223World) restart() {
	root, err := w.store.Commit()
	require.NoError(w.t, err)
	require.NoError(w.t, w.store.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	require.Zero(w.t, w.store.JournalLen())
	w.build()
}

func (w *sp223World) root() []byte {
	root, err := w.store.RootHash()
	require.NoError(w.t, err)
	return root
}

// transition builds a three-shard transition of a family and phase; seed
// separates instances. The owner admits it unless admit is false.
func (w *sp223World) transition(family, phase string, seed byte, admit bool) convergenceTransition {
	shards := []uint32{0, 1, 2}
	ids := make([][]byte, len(shards))
	for i, shard := range shards {
		ids[i] = binary.BigEndian.AppendUint32(nil, shard)
	}
	t := convergenceTransition{action: bytes.Repeat([]byte{seed}, 32), digest: bytes.Repeat([]byte{seed + 1}, 32), token: []byte("TOKEN-abcdef"),
		target: bytes.Repeat([]byte{seed + 2}, 32), dependencies: bytes.Repeat([]byte{seed + 3}, 32),
		requiredSet: w.hasher.Compute(string(qualRecordFrame(ids...))), version: 7, shards: shards}
	if family != ConvergenceFamilyCEB || phase != "CURRENT_ACK" {
		t.context = &convergencePhaseContext{family: []byte(family), phase: []byte(phase), lineage: []byte{'l', seed}, predecessor: bytes.Repeat([]byte{seed + 4}, 32)}
	}
	if admit {
		w.admit(t)
	}
	return t
}

func (w *sp223World) admit(t convergenceTransition) {
	b, err := w.host.decode(w.binding(t))
	require.NoError(w.t, err)
	w.owner.admitted[sp223BindingID(*b)] = struct{}{}
}

func (w *sp223World) binding(t convergenceTransition) []byte {
	_, binding, err := w.records.encode(t)
	require.NoError(w.t, err)
	return binding
}

// sp223Ack is one execution shard's canonically final acknowledgement of one
// or more phase instances: the shard applied them in the executed block S,
// whose result root is carried by H and settled two metachain blocks deep
// below the consuming metachain block B.
type sp223Ack struct {
	f      *canonicalTestFixture
	shard  uint32
	origin []byte
	codec  *registrationRecords
}

func sp223Acknowledge(t *testing.T, shard uint32, nonce uint64, bindings ...[]byte) *sp223Ack {
	t.Helper()
	return sp223AcknowledgeAs(t, shard, shard, nonce, bindings...)
}

// sp223AcknowledgeAs lets the shard's account hold the item of another shard
// identity (written), under the same key.
func sp223AcknowledgeAs(t *testing.T, shard, written uint32, nonce uint64, bindings ...[]byte) *sp223Ack {
	t.Helper()
	f := newCanonicalTestFixture(t, shard, core.MetachainShardId)
	codec, err := newRegistrationRecords(f.s, f.reader.accounts.args.Marshaller, f.reader.accounts.args.Hasher, 4096)
	require.NoError(t, err)
	writer, err := NewConvergenceAckWriter(codec, written)
	require.NoError(t, err)
	for _, binding := range bindings {
		require.NoError(t, writer.Acknowledge(binding))
		require.NoError(t, writer.Acknowledge(binding), "an exact repeat writes nothing")
	}
	root, err := f.s.Commit()
	require.NoError(t, err)
	executed := &block.HeaderV3{Nonce: nonce, Round: 21, Epoch: 3, ShardID: shard, ChainID: []byte("unit-chain")}
	f.w.Account.ExecutedHeader = f.encode(t, executed)
	origin := f.hash(f.w.Account.ExecutedHeader)
	carrying := &block.HeaderV3{Nonce: 15, Round: 25, Epoch: 4, ShardID: shard, ChainID: []byte("unit-chain"),
		ExecutionResults: []*block.ExecutionResult{{BaseExecutionResult: &block.BaseExecutionResult{
			HeaderHash: origin, HeaderNonce: nonce, HeaderRound: 21, HeaderEpoch: 3, RootHash: root}}}}
	f.w.Account.Header = f.encode(t, carrying)
	f.w.HeaderProof = f.proof(t, carrying, f.w.Account.Header)
	f.metas[0].ShardInfoProposal[0].HeaderHash = f.hash(f.w.Account.Header)
	f.metas[0].ShardInfo[0].HeaderHash, f.metas[0].ShardInfo[0].Nonce = origin, nonce
	f.rechain(t)
	return &sp223Ack{f: f, shard: shard, origin: origin, codec: codec}
}

// witness is the canonical witness of this shard's item for one binding.
func (a *sp223Ack) witness(t *testing.T, binding []byte) canonicalResultWitness {
	t.Helper()
	key, _, err := convergenceAckItem(a.codec, binding, a.shard)
	require.NoError(t, err)
	w := cloneCanonicalResultWitness(a.f.w)
	w.Account, err = a.f.reader.accounts.BuildNativeWitness(a.f.s, a.f.hash(a.f.w.Account.Header), a.shard,
		core.SystemAccountAddress, key, a.f.w.Account, 1<<20)
	require.NoError(t, err)
	return w
}

func (a *sp223Ack) evidence(t *testing.T, binding []byte) []byte {
	t.Helper()
	return sp223Evidence(t, a.witness(t, binding))
}

func sp223Evidence(t *testing.T, w canonicalResultWitness) []byte {
	t.Helper()
	codec := &registrationRecords{marshaller: &marshal.GogoProtoMarshalizer{}, maxBytes: 1 << 20}
	evidence, err := encodeConvergenceEvidence(codec, w)
	require.NoError(t, err)
	return evidence
}

// enter makes this acknowledgement's consuming block the block in execution.
func (w *sp223World) enter(a *sp223Ack) {
	w.block.hash, w.block.header = a.f.bHash, a.f.w.Consumer
}

// deliver presents the acknowledgement of one shard for a transition.
func (w *sp223World) deliver(t convergenceTransition, a *sp223Ack) error {
	w.enter(a)
	return w.records.acknowledge(t, a.shard, a.origin, a.evidence(w.t, w.binding(t)))
}

// unchanged runs a request that must be denied and leave no state.
func (w *sp223World) denied(label string, run func() error) {
	w.t.Helper()
	root, journal := w.root(), w.store.JournalLen()
	require.Error(w.t, run(), label)
	require.Equal(w.t, root, w.root(), label)
	require.Equal(w.t, journal, w.store.JournalLen(), label)
}

func (w *sp223World) value(key string) []byte { return qualRegistryValue(w.t, w.store, key) }
