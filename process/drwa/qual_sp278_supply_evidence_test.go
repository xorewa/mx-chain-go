package drwa

import (
	"bytes"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

// SP2-78: closure-bound origin SupplyState evidence. The origin shard's real
// account store holds the SupplyState record and the attested item; the
// metachain verifier reads it through SP2-22's canonical result reader from
// evidence that is canonically final for the block in execution (the shard
// executed block S, its result root carried by H, settled below the consuming
// metachain block B), exactly as an acknowledgement of SP2-23 is read.

const qualSP278Token = "FIXT-0a1b2c"

func qualSP278Put(t *testing.T, accounts state.AccountsAdapter, key, value []byte) {
	t.Helper()
	a, err := accounts.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(key, value))
	require.NoError(t, accounts.SaveAccount(a))
}

func qualSP278Get(t *testing.T, accounts state.AccountsAdapter, key []byte) []byte {
	t.Helper()
	a, err := accounts.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	value, _, err := a.(state.UserAccountHandler).RetrieveValue(key)
	require.NoError(t, err)
	return value
}

type qualSP278Origin struct {
	f      *canonicalTestFixture
	shard  uint32
	codec  *registrationRecords
	leaves *rootLeafRecords
	writer *SupplyEvidenceWriter
}

func qualSP278Binding(shard uint32) SupplyEvidenceBinding {
	return SupplyEvidenceBinding{Token: []byte(qualSP278Token), CEBEpoch: 3, CEBHash: blake2b.NewBlake2b().Compute("current CEB"),
		Action: []byte("requalification action"), Closure: 4, OriginShard: shard}
}

func qualSP278OriginNew(t *testing.T, shard uint32) *qualSP278Origin {
	t.Helper()
	f := newCanonicalTestFixture(t, shard, core.MetachainShardId)
	codec, err := newRegistrationRecords(f.s, f.reader.accounts.args.Marshaller, f.reader.accounts.args.Hasher, 4096)
	require.NoError(t, err)
	leaves, err := newRootLeafRecords(codec, 32)
	require.NoError(t, err)
	writer, err := NewSupplyEvidenceWriter(codec, leaves, shard)
	require.NoError(t, err)
	require.False(t, writer.IsInterfaceNil())
	return &qualSP278Origin{f: f, shard: shard, codec: codec, leaves: leaves, writer: writer}
}

// supply writes the shard's SupplyState record as the supply owner does.
func (o *qualSP278Origin) supply(t *testing.T, token string, originShard uint32, cumulative, live int64) []byte {
	t.Helper()
	raw, err := o.leaves.encodeSupplyRecord(&initializedSupplyState{token: []byte(token), family: core.Fungible, origin: bytes.Repeat([]byte{0x33}, 32),
		originShard: originShard, accounting: &supplyAccounting{cumulativeIssued: big.NewInt(cumulative), liveSupply: big.NewInt(live), nextSupplyNonce: 12}})
	require.NoError(t, err)
	key, err := o.leaves.outerKey(supplyStatePrefix, []byte(token))
	require.NoError(t, err)
	qualSP278Put(t, o.f.s, key, raw)
	return raw
}

// settle commits the shard state and makes it the result of executed block S,
// carried by H and settled below the consuming metachain block.
func (o *qualSP278Origin) settle(t *testing.T, nonce uint64) {
	t.Helper()
	root, err := o.f.s.Commit()
	require.NoError(t, err)
	executed := &block.HeaderV3{Nonce: nonce, Round: 21, Epoch: 3, ShardID: o.shard, ChainID: []byte("unit-chain")}
	o.f.w.Account.ExecutedHeader = o.f.encode(t, executed)
	origin := o.f.hash(o.f.w.Account.ExecutedHeader)
	carrying := &block.HeaderV3{Nonce: 15, Round: 25, Epoch: 4, ShardID: o.shard, ChainID: []byte("unit-chain"),
		ExecutionResults: []*block.ExecutionResult{{BaseExecutionResult: &block.BaseExecutionResult{
			HeaderHash: origin, HeaderNonce: nonce, HeaderRound: 21, HeaderEpoch: 3, RootHash: root}}}}
	o.f.w.Account.Header = o.f.encode(t, carrying)
	o.f.w.HeaderProof = o.f.proof(t, carrying, o.f.w.Account.Header)
	o.f.metas[0].ShardInfoProposal[0].HeaderHash = o.f.hash(o.f.w.Account.Header)
	o.f.metas[0].ShardInfo[0].HeaderHash, o.f.metas[0].ShardInfo[0].Nonce = origin, nonce
	o.f.rechain(t)
}

func (o *qualSP278Origin) witness(t *testing.T, b SupplyEvidenceBinding) canonicalResultWitness {
	t.Helper()
	binding, err := b.encode(o.codec)
	require.NoError(t, err)
	key := append([]byte(supplyEvidencePrefix), o.codec.hasher.Compute(string(binding))...)
	w := cloneCanonicalResultWitness(o.f.w)
	w.Account, err = o.f.reader.accounts.BuildNativeWitness(o.f.s, o.f.hash(o.f.w.Account.Header), o.shard,
		core.SystemAccountAddress, key, o.f.w.Account, 1<<20)
	require.NoError(t, err)
	return w
}

func (o *qualSP278Origin) evidence(t *testing.T, b SupplyEvidenceBinding) []byte {
	t.Helper()
	return sp223Evidence(t, o.witness(t, b))
}

type qualSP278Meta struct {
	t        *testing.T
	store    *qualNativeStore
	block    *sp223Block
	verifier *SupplyEvidenceVerifier
}

// qualSP278MetaNew is the metachain side: its own store and a verifier over
// the reader of one canonical fixture (the reader's oracles do not depend on
// the producing shard).
func qualSP278MetaNew(t *testing.T) *qualSP278Meta {
	t.Helper()
	base := newCanonicalTestFixture(t, 0, core.MetachainShardId)
	m := &qualSP278Meta{t: t, store: qualRegistrationStore(t, 0), block: &sp223Block{epoch: 10, hash: base.bHash, header: base.w.Consumer}}
	codec, err := newRegistrationRecords(m.store, &marshal.GogoProtoMarshalizer{}, base.reader.accounts.args.Hasher, 4096)
	require.NoError(t, err)
	m.verifier, err = NewSupplyEvidenceVerifier(ArgsSupplyEvidenceVerifier{Records: codec, Reader: base.reader, Block: m.block, EvidenceBytes: 1 << 20})
	require.NoError(t, err)
	require.False(t, m.verifier.IsInterfaceNil())
	return m
}

func (m *qualSP278Meta) enter(o *qualSP278Origin) {
	m.block.hash, m.block.header = o.f.bHash, o.f.w.Consumer
}

func (m *qualSP278Meta) refused(label string, run func() (*big.Int, error)) {
	m.t.Helper()
	root, journal := qualSP224State(m.t, m.store)
	value, err := run()
	require.Error(m.t, err, label)
	require.Nil(m.t, value, label)
	after, afterJournal := qualSP224State(m.t, m.store)
	require.Equal(m.t, root, after, label)
	require.Equal(m.t, journal, afterJournal, label)
}

func TestQualSP278SupplyEvidenceFromTheCanonicalOrigin(t *testing.T) {
	origin := qualSP278OriginNew(t, 1)
	origin.supply(t, qualSP278Token, 1, 1_000_000, 999_000)
	binding := qualSP278Binding(1)
	require.NoError(t, origin.writer.Attest(binding))
	origin.settle(t, 11)
	meta := qualSP278MetaNew(t)
	meta.enter(origin)
	evidence := origin.evidence(t, binding)

	root, journal := qualSP224State(t, meta.store)
	cumulative, err := meta.verifier.CumulativeIssued(binding, evidence)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(1_000_000), cumulative)
	after, afterJournal := qualSP224State(t, meta.store)
	require.Equal(t, root, after, "the verifier writes nothing")
	require.Equal(t, journal, afterJournal)

	// The cap rule of target CEB validation (Part A L2673-2677).
	for name, c := range map[string]struct {
		cap   *big.Int
		admit bool
	}{
		"no cap": {nil, true}, "cap equal to cumulative issued": {big.NewInt(1_000_000), true}, "cap above": {big.NewInt(1_000_001), true},
		"cap one below": {big.NewInt(999_999), false}, "cap at live supply": {big.NewInt(999_000), false}, "cap zero": {big.NewInt(0), false},
		"negative cap": {big.NewInt(-1), false},
	} {
		value, capErr := meta.verifier.ValidateCap(binding, c.cap, evidence)
		if c.admit {
			require.NoError(t, capErr, name)
			require.Equal(t, big.NewInt(1_000_000), value, name)
		} else {
			require.ErrorIs(t, capErr, errSupplyEvidence, name)
			require.Nil(t, value, name)
		}
	}

	// Evidence that is canonical for one binding is presented for another.
	for name, change := range map[string]func(*SupplyEvidenceBinding){
		"another closure instance": func(b *SupplyEvidenceBinding) { b.Closure = 5 },
		"an earlier closure":       func(b *SupplyEvidenceBinding) { b.Closure = 3 },
		"another CEB epoch":        func(b *SupplyEvidenceBinding) { b.CEBEpoch = 4 },
		"another CEB hash":         func(b *SupplyEvidenceBinding) { b.CEBHash = blake2b.NewBlake2b().Compute("another CEB") },
		"another action":           func(b *SupplyEvidenceBinding) { b.Action = []byte("another action") },
		"another token":            func(b *SupplyEvidenceBinding) { b.Token = []byte("OTHR-0a1b2c") },
		"another origin shard":     func(b *SupplyEvidenceBinding) { b.OriginShard = 2 },
	} {
		other := binding
		change(&other)
		meta.refused(name, func() (*big.Int, error) { return meta.verifier.CumulativeIssued(other, evidence) })
		meta.refused(name+" (cap)", func() (*big.Int, error) { return meta.verifier.ValidateCap(other, nil, evidence) })
	}
	// A malformed binding is refused before any read.
	for name, change := range map[string]func(*SupplyEvidenceBinding){
		"no token": func(b *SupplyEvidenceBinding) { b.Token = nil }, "CEB epoch zero": func(b *SupplyEvidenceBinding) { b.CEBEpoch = 0 },
		"short CEB hash": func(b *SupplyEvidenceBinding) { b.CEBHash = []byte("short") }, "no action": func(b *SupplyEvidenceBinding) { b.Action = nil },
		"closure zero": func(b *SupplyEvidenceBinding) { b.Closure = 0 }, "metachain as origin": func(b *SupplyEvidenceBinding) { b.OriginShard = core.MetachainShardId },
		"token over the bound": func(b *SupplyEvidenceBinding) { b.Token = make([]byte, 5000) },
	} {
		other := binding
		change(&other)
		meta.refused(name, func() (*big.Int, error) { return meta.verifier.CumulativeIssued(other, evidence) })
		require.ErrorIs(t, origin.writer.Attest(other), errSupplyEvidence, name)
	}

	// Unauthenticated or non-canonical evidence.
	w := origin.witness(t, binding)
	tamper := func(change func(*canonicalResultWitness)) []byte {
		x := cloneCanonicalResultWitness(w)
		change(&x)
		return sp223Evidence(t, x)
	}
	for name, presented := range map[string][]byte{
		"no evidence":             nil,
		"not an evidence frame":   []byte("the cumulative issued value is 1"),
		"no header proof":         tamper(func(x *canonicalResultWitness) { x.HeaderProof = nil }),
		"another header proof":    tamper(func(x *canonicalResultWitness) { x.HeaderProof = append(bytes.Clone(x.HeaderProof), 1) }),
		"no account proof":        tamper(func(x *canonicalResultWitness) { x.Account.AccountProof = nil }),
		"no data proof":           tamper(func(x *canonicalResultWitness) { x.Account.DataProof = nil }),
		"data proof node changed": tamper(func(x *canonicalResultWitness) { x.Account.DataProof[0][len(x.Account.DataProof[0])-1] ^= 1 }),
		"another executed header": tamper(func(x *canonicalResultWitness) {
			x.Account.ExecutedHeader = append(bytes.Clone(x.Account.ExecutedHeader), 0)
		}),
		"no metachain headers":      tamper(func(x *canonicalResultWitness) { x.MetaHeaders, x.MetaProofs = nil, nil }),
		"metachain header replaced": tamper(func(x *canonicalResultWitness) { x.MetaHeaders[0] = append(bytes.Clone(x.MetaHeaders[0]), 0) }),
	} {
		meta.refused(name, func() (*big.Int, error) { return meta.verifier.CumulativeIssued(binding, presented) })
	}
	// Not final for the block in execution: another consuming block, and none.
	other := qualSP278OriginNew(t, 1)
	other.supply(t, qualSP278Token, 1, 5, 5)
	require.NoError(t, other.writer.Attest(binding))
	other.settle(t, 12)
	meta.enter(other)
	meta.refused("evidence of another consuming block", func() (*big.Int, error) { return meta.verifier.CumulativeIssued(binding, evidence) })
	meta.block.hash = nil
	meta.refused("no block in execution", func() (*big.Int, error) { return meta.verifier.CumulativeIssued(binding, evidence) })
	meta.enter(origin)
	cumulative, err = meta.verifier.CumulativeIssued(binding, evidence)
	require.NoError(t, err, "control after the refusals")
	require.Equal(t, big.NewInt(1_000_000), cumulative)
}

func TestQualSP278SupplyEvidenceStaleAndAbsent(t *testing.T) {
	// The shard attested closure 4 and later, with more supply, closure 5. The
	// evidence of closure 4 never answers for closure 5, and before the shard
	// attests closure 5 nothing does.
	origin := qualSP278OriginNew(t, 1)
	origin.supply(t, qualSP278Token, 1, 100, 100)
	fourth := qualSP278Binding(1)
	fifth := fourth
	fifth.Closure = 5
	require.NoError(t, origin.writer.Attest(fourth))
	origin.settle(t, 11)
	meta := qualSP278MetaNew(t)
	meta.enter(origin)
	stale := origin.evidence(t, fourth)
	value, err := meta.verifier.CumulativeIssued(fourth, stale)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(100), value)
	meta.refused("stale evidence for the next closure", func() (*big.Int, error) { return meta.verifier.CumulativeIssued(fifth, stale) })
	// The shard's own store has no item for closure 5 yet.
	fifthEncoded, err := fifth.encode(origin.codec)
	require.NoError(t, err)
	require.Empty(t, qualSP278Get(t, origin.f.s, append([]byte(supplyEvidencePrefix), origin.codec.hasher.Compute(string(fifthEncoded))...)))

	origin.supply(t, qualSP278Token, 1, 250, 240)
	require.NoError(t, origin.writer.Attest(fifth))
	origin.settle(t, 12)
	meta.enter(origin)
	value, err = meta.verifier.CumulativeIssued(fifth, origin.evidence(t, fifth))
	require.NoError(t, err)
	require.Equal(t, big.NewInt(250), value)
	value, err = meta.verifier.CumulativeIssued(fourth, origin.evidence(t, fourth))
	require.NoError(t, err)
	require.Equal(t, big.NewInt(100), value, "the value attested for closure 4 is still the one of closure 4")
	meta.refused("closure 4 evidence, old result", func() (*big.Int, error) { return meta.verifier.CumulativeIssued(fourth, stale) })
}

func TestQualSP278SupplyEvidenceWriter(t *testing.T) {
	origin := qualSP278OriginNew(t, 1)
	binding := qualSP278Binding(1)
	state := func() ([]byte, int) { return qualSP224State(t, origin.f.s) }
	denied := func(label string, run func() error) {
		t.Helper()
		root, journal := state()
		require.Error(t, run(), label)
		after, afterJournal := state()
		require.Equal(t, root, after, label)
		require.Equal(t, journal, afterJournal, label)
	}
	denied("no SupplyState record", func() error { return origin.writer.Attest(binding) })
	origin.supply(t, "OTHR-0a1b2c", 1, 9, 9)
	denied("record of another token only", func() error { return origin.writer.Attest(binding) })
	origin.supply(t, qualSP278Token, 2, 9, 9)
	denied("record names another origin shard", func() error { return origin.writer.Attest(binding) })
	key, err := origin.leaves.outerKey(supplyStatePrefix, []byte(qualSP278Token))
	require.NoError(t, err)
	qualSP278Put(t, origin.f.s, key, []byte("not a record"))
	denied("undecodable record", func() error { return origin.writer.Attest(binding) })
	foreign := binding
	foreign.OriginShard = 2
	denied("this shard is not the origin", func() error { return origin.writer.Attest(foreign) })
	invalid := binding
	invalid.Token = []byte("not a token")
	denied("invalid token", func() error { return origin.writer.Attest(invalid) })

	raw := origin.supply(t, qualSP278Token, 1, 1000, 990)
	_, err = origin.f.s.Commit()
	require.NoError(t, err)
	// With this shard's valid record in place: a binding that names another
	// origin shard is still refused, and so is a record of another token found
	// under this token's key.
	denied("valid record, binding names another origin", func() error { return origin.writer.Attest(foreign) })
	misplaced, err := origin.leaves.encodeSupplyRecord(&initializedSupplyState{token: []byte("OTHR-0a1b2c"), family: core.Fungible, origin: bytes.Repeat([]byte{0x33}, 32),
		originShard: 1, accounting: &supplyAccounting{cumulativeIssued: big.NewInt(5), liveSupply: big.NewInt(5)}})
	require.NoError(t, err)
	qualSP278Put(t, origin.f.s, key, misplaced)
	denied("another token's record under this key", func() error { return origin.writer.Attest(binding) })
	qualSP278Put(t, origin.f.s, key, raw)
	_, err = origin.f.s.Commit()
	require.NoError(t, err)
	require.NoError(t, origin.writer.Attest(binding))
	root, err := origin.f.s.Commit()
	require.NoError(t, err)
	encoded, err := binding.encode(origin.codec)
	require.NoError(t, err)
	itemKey, itemValue, err := supplyEvidenceItem(origin.codec, encoded, big.NewInt(1000), origin.codec.hasher.Compute(string(raw)))
	require.NoError(t, err)
	require.Equal(t, itemValue, qualSP278Get(t, origin.f.s, itemKey))

	// An exact repeat writes nothing.
	require.NoError(t, origin.writer.Attest(binding))
	again, err := origin.f.s.Commit()
	require.NoError(t, err)
	require.Equal(t, root, again)
	// The supply changed after the attestation: the attested value stays.
	origin.supply(t, qualSP278Token, 1, 1001, 991)
	_, err = origin.f.s.Commit()
	require.NoError(t, err)
	denied("another value under the same binding", func() error { return origin.writer.Attest(binding) })
	require.Equal(t, itemValue, qualSP278Get(t, origin.f.s, itemKey))

	// Restart of the origin shard: the item is still there, a repeat with the
	// original record writes nothing and a new writer decides the same.
	origin.supply(t, qualSP278Token, 1, 1000, 990)
	before, err := origin.f.s.Commit()
	require.NoError(t, err)
	reopened, err := newRegistrationRecords(origin.f.s, origin.codec.marshaller, origin.codec.hasher, 4096)
	require.NoError(t, err)
	leaves, err := newRootLeafRecords(reopened, 32)
	require.NoError(t, err)
	writer, err := NewSupplyEvidenceWriter(reopened, leaves, 1)
	require.NoError(t, err)
	require.NoError(t, writer.Attest(binding))
	afterRestart, err := origin.f.s.Commit()
	require.NoError(t, err)
	require.Equal(t, before, afterRestart)

	// Constructors.
	_, err = NewSupplyEvidenceWriter(nil, leaves, 1)
	require.ErrorIs(t, err, errSupplyEvidence)
	_, err = NewSupplyEvidenceWriter(reopened, nil, 1)
	require.ErrorIs(t, err, errSupplyEvidence)
	_, err = NewSupplyEvidenceWriter(reopened, leaves, core.MetachainShardId)
	require.ErrorIs(t, err, errSupplyEvidence)
	var none *SupplyEvidenceWriter
	require.True(t, none.IsInterfaceNil())
	_, _, err = supplyEvidenceItem(reopened, encoded, nil, origin.codec.hasher.Compute("x"))
	require.ErrorIs(t, err, errSupplyEvidence)
	_, _, err = supplyEvidenceItem(reopened, encoded, big.NewInt(-1), origin.codec.hasher.Compute("x"))
	require.ErrorIs(t, err, errSupplyEvidence)
	_, _, err = supplyEvidenceItem(reopened, encoded, big.NewInt(1), []byte("short"))
	require.ErrorIs(t, err, errSupplyEvidence)
	_, _, err = supplyEvidenceItem(reopened, make([]byte, 5000), big.NewInt(1), origin.codec.hasher.Compute("x"))
	require.NoError(t, err, "the binding is hashed, not framed")
}

func TestQualSP278SupplyEvidenceVerifierConstructionAndRestart(t *testing.T) {
	origin := qualSP278OriginNew(t, 1)
	origin.supply(t, qualSP278Token, 1, 77, 70)
	binding := qualSP278Binding(1)
	require.NoError(t, origin.writer.Attest(binding))
	origin.settle(t, 11)
	meta := qualSP278MetaNew(t)
	meta.enter(origin)
	evidence := origin.evidence(t, binding)
	value, err := meta.verifier.CumulativeIssued(binding, evidence)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(77), value)

	// Restart of the metachain node: a verifier built again over the reopened
	// store gives the same value and the same refusals.
	reopened := qualSP224Reopen(t, meta.store)
	codec, err := newRegistrationRecords(reopened, &marshal.GogoProtoMarshalizer{}, origin.codec.hasher, 4096)
	require.NoError(t, err)
	args := ArgsSupplyEvidenceVerifier{Records: codec, Reader: meta.verifier.args.Reader, Block: meta.block, EvidenceBytes: 1 << 20}
	rebuilt, err := NewSupplyEvidenceVerifier(args)
	require.NoError(t, err)
	value, err = rebuilt.CumulativeIssued(binding, evidence)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(77), value)
	later := binding
	later.Closure++
	_, err = rebuilt.CumulativeIssued(later, evidence)
	require.Error(t, err)

	// Evidence over the configured bound is refused.
	small := args
	small.EvidenceBytes = len(evidence) - 1
	bounded, err := NewSupplyEvidenceVerifier(small)
	require.NoError(t, err)
	_, err = bounded.CumulativeIssued(binding, evidence)
	require.ErrorIs(t, err, errSupplyEvidence)

	for name, change := range map[string]func(*ArgsSupplyEvidenceVerifier){
		"no records": func(a *ArgsSupplyEvidenceVerifier) { a.Records = nil }, "no reader": func(a *ArgsSupplyEvidenceVerifier) { a.Reader = nil },
		"no block source": func(a *ArgsSupplyEvidenceVerifier) { a.Block = nil }, "no evidence bound": func(a *ArgsSupplyEvidenceVerifier) { a.EvidenceBytes = 0 },
		"records without hasher": func(a *ArgsSupplyEvidenceVerifier) { a.Records = &registrationRecords{} },
	} {
		changed := args
		change(&changed)
		_, err = NewSupplyEvidenceVerifier(changed)
		require.ErrorIs(t, err, errSupplyEvidence, name)
	}
	var none *SupplyEvidenceVerifier
	require.True(t, none.IsInterfaceNil())
}

// The fixture file's supply-evidence bytes come from the separate Python
// implementation; the product reproduces the record, the binding, the key and
// the value, and the origin writer stores exactly that item.
func TestQualSP278IndependentlyExpectedSupplyEvidenceFixture(t *testing.T) {
	fixtures, _, _ := qualSP278Load(t)
	x := fixtures.Supply
	h := func(value string) []byte { return qualSP278Hex(t, value) }
	require.Equal(t, uint32(core.Fungible), x.Family)
	origin := qualSP278OriginNew(t, x.OriginShard)
	raw, err := origin.leaves.encodeSupplyRecord(&initializedSupplyState{token: h(x.Token), family: core.Fungible, origin: h(x.Origin), originShard: x.OriginShard,
		accounting: &supplyAccounting{cumulativeIssued: new(big.Int).SetUint64(x.Cumulative), liveSupply: new(big.Int).SetUint64(x.Live), nextSupplyNonce: x.NextNonce}})
	require.NoError(t, err)
	require.Equal(t, h(x.Record), raw)
	binding := SupplyEvidenceBinding{Token: h(x.Token), CEBEpoch: x.CEBEpoch, CEBHash: h(x.CEBHash), Action: h(x.Action), Closure: x.Closure, OriginShard: x.OriginShard}
	encoded, err := binding.encode(origin.codec)
	require.NoError(t, err)
	require.Equal(t, h(x.Binding), encoded)
	key, value, err := supplyEvidenceItem(origin.codec, encoded, new(big.Int).SetUint64(x.Cumulative), origin.codec.hasher.Compute(string(raw)))
	require.NoError(t, err)
	require.Equal(t, h(x.Key), key)
	require.Equal(t, h(x.Value), value)

	supplyKey, err := origin.leaves.outerKey(supplyStatePrefix, h(x.Token))
	require.NoError(t, err)
	qualSP278Put(t, origin.f.s, supplyKey, raw)
	require.NoError(t, origin.writer.Attest(binding))
	require.Equal(t, h(x.Value), qualSP278Get(t, origin.f.s, h(x.Key)))
	origin.settle(t, 11)
	meta := qualSP278MetaNew(t)
	meta.enter(origin)
	cumulative, err := meta.verifier.CumulativeIssued(binding, origin.evidence(t, binding))
	require.NoError(t, err)
	require.Equal(t, new(big.Int).SetUint64(x.Cumulative), cumulative)
}

// Conditional digest-length carry (SP2-81B3c G10.02): the pinned VM's
// ECDSAPlainMsg passes its input as the digest without a length check, so a
// DRWA consumer of it would have to enforce the digest length itself. No DRWA
// product file uses ECDSA, secp256k1 or the VM crypto hook: this test fails
// when one starts to. DRWA authority signatures are Ed25519 over a digest of
// exactly the hasher's size.
func TestQualSP278NoDRWAConsumerOfECDSAPlainMsg(t *testing.T) {
	root := filepath.Join("..", "..")
	checked := 0
	require.NoError(t, filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); name == ".git" || name == "vendor" || name == "testdata" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		relative := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		if !strings.HasSuffix(relative, ".go") || strings.HasSuffix(relative, "_test.go") || !strings.Contains(strings.ToLower(relative), "drwa") {
			return nil
		}
		source, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		checked++
		lower := strings.ToLower(string(source))
		for _, word := range []string{"ecdsaplainmsg", "ecdsa", "secp256", "verifysecp", "vmcrypto", "cryptohook"} {
			require.NotContains(t, lower, word, relative)
		}
		return nil
	}))
	require.Greater(t, checked, 80, "the DRWA product files were read")

	b := qualSP278New(t)
	raw, err := encodeCertificateBody(b.codec, b.body())
	require.NoError(t, err)
	digest, err := certificateDigest(b.codec, raw)
	require.NoError(t, err)
	require.Len(t, digest, 32)
}
