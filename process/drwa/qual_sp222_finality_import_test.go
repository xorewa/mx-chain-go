package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-22 qualification of the installed finalized-result import (Part A 6.1,
// AR-01-Q01 to Q07). Every case drives the production owner through
// BeginBlock/Stage/EndBlock on a real account store; headers, proofs and the
// proof oracle are test inputs, not signed network objects.

type sp222Class struct {
	gas       uint64
	admit     error
	charged   uint64
	positions []int
}

func (c *sp222Class) IsInterfaceNil() bool { return c == nil }
func (c *sp222Class) Admit(key []byte, _ uint64, _, body []byte) error {
	if len(key) == 0 || len(body) == 0 {
		return errors.New("empty record")
	}
	return c.admit
}
func (c *sp222Class) FinalizationGas(_ int, registered int) uint64 {
	c.positions = append(c.positions, registered)
	return c.gas
}

type sp222Source struct {
	headers map[string]data.HeaderHandler
	proofs  map[string]data.HeaderProofHandler
	asked   []string
	failure error
}

func (s *sp222Source) IsInterfaceNil() bool { return s == nil }
func (s *sp222Source) Header(_ uint32, hash []byte) (data.HeaderHandler, error) {
	s.asked = append(s.asked, "h:"+string(hash))
	if s.failure != nil {
		return nil, s.failure
	}
	h, ok := s.headers[string(hash)]
	if !ok {
		return nil, errors.New("header not held")
	}
	return h, nil
}
func (s *sp222Source) Proof(_ uint32, hash []byte) (data.HeaderProofHandler, error) {
	s.asked = append(s.asked, "p:"+string(hash))
	p, ok := s.proofs[string(hash)]
	if !ok {
		return nil, errors.New("proof not held")
	}
	return p, nil
}

type sp222Executed struct {
	header data.HeaderHandler
	hash   []byte
	root   []byte
}

type sp222Node struct {
	t       *testing.T
	self    uint32
	store   *qualNativeStore
	faults  *sp222FaultStore
	imp     *FinalityImport
	src     *sp222Source
	class   *sp222Class
	oracle  *canonicalTestProofVerifier
	mar     marshal.Marshalizer
	tip     data.HeaderHandler
	tipHash []byte
	metaTip *block.MetaBlockV3
	metaHsh []byte
	legacy  []byte
	bases   [][]byte
	// executed own blocks whose result no header carries yet
	uncarried []sp222Executed
	executed  map[string]sp222Executed
}

func newSP222Node(t *testing.T, self uint32, withSystemAccount bool) *sp222Node {
	return newSP222NodeOnBase(t, self, withSystemAccount, 3)
}

// newSP222NodeOnBase starts the metachain with one legacy block followed by
// the given number of V3 blocks.
func newSP222NodeOnBase(t *testing.T, self uint32, withSystemAccount bool, base int) *sp222Node {
	t.Helper()
	n := &sp222Node{t: t, self: self, store: qualContainmentStore(t), mar: &marshal.GogoProtoMarshalizer{},
		src:   &sp222Source{headers: map[string]data.HeaderHandler{}, proofs: map[string]data.HeaderProofHandler{}},
		class: &sp222Class{gas: 7}, oracle: &canonicalTestProofVerifier{}, executed: map[string]sp222Executed{}}
	if withSystemAccount {
		a, err := n.store.LoadAccount(core.SystemAccountAddress)
		require.NoError(t, err)
		require.NoError(t, n.store.SaveAccount(a))
		_, err = n.store.Commit()
		require.NoError(t, err)
	}
	n.faults = &sp222FaultStore{qualNativeStore: n.store}
	n.imp = n.owner()
	n.legacy = n.hold(&block.MetaBlock{Nonce: 29, Round: 39, Epoch: 4, ChainID: []byte("unit-chain"), RandSeed: []byte{29}})
	for i := 0; i < base; i++ {
		n.bases = append(n.bases, n.meta(nil, nil))
	}
	if self != core.MetachainShardId {
		n.tip = &block.HeaderV3{ShardID: self, Nonce: 10, Round: 20, Epoch: 3, ChainID: []byte("unit-chain"), RandSeed: []byte{10}}
		n.tipHash = n.hold(n.tip)
	}
	return n
}

func (n *sp222Node) owner() *FinalityImport {
	exclusions, err := common.NewRoundExclusionHandler(nil)
	require.NoError(n.t, err)
	hasher := blake2b.NewBlake2b()
	imp, err := NewFinalityImport(ArgsFinalityImport{
		Accounts: n.faults, Marshaller: n.mar, Hasher: hasher, SelfShardID: n.self, Source: n.src,
		Validator: &canonicalTestValidator{marshaller: n.mar, hash: hasher.Compute}, Proofs: n.oracle,
		Integrity: &canonicalTestIntegrity{}, Exclusions: exclusions,
		Classes: map[string]FinalityRecordClass{"class/": n.class}, MaxRecordBytes: 4096,
	})
	require.NoError(n.t, err)
	return imp
}

func (n *sp222Node) hash(h data.HeaderHandler) []byte {
	raw, err := n.mar.Marshal(h)
	require.NoError(n.t, err)
	return blake2b.NewBlake2b().Compute(string(raw))
}

// hold makes a header and its proof retrievable on this node.
func (n *sp222Node) hold(h data.HeaderHandler) []byte {
	hash := n.hash(h)
	n.src.headers[string(hash)] = h
	n.src.proofs[string(hash)] = &block.HeaderProof{HeaderHash: hash, HeaderShardId: h.GetShardID(),
		HeaderNonce: h.GetNonce(), HeaderRound: h.GetRound(), HeaderEpoch: h.GetEpoch(),
		IsStartOfEpoch: h.IsStartOfEpochBlock(), AggregatedSignature: []byte("unit proof oracle")}
	return hash
}

// meta appends a metachain block that proposes the given own-shard headers and
// lists the given executed identities. On a metachain node it is not used for
// the own chain (see next).
func (n *sp222Node) meta(proposed []data.HeaderHandler, executed []data.HeaderHandler) []byte {
	m := &block.MetaBlockV3{Nonce: 30, Round: 40, Epoch: 4, ChainID: []byte("unit-chain"), RandSeed: []byte{30},
		PrevHash: n.legacy, PrevRandSeed: []byte{29}}
	if n.metaTip != nil {
		m.Nonce, m.Round = n.metaTip.Nonce+1, n.metaTip.Round+1
		m.PrevHash, m.PrevRandSeed, m.RandSeed = n.metaHsh, n.metaTip.RandSeed, []byte{byte(m.Nonce)}
	}
	for _, h := range proposed {
		m.ShardInfoProposal = append(m.ShardInfoProposal, block.ShardDataProposal{HeaderHash: n.hash(h),
			ShardID: h.GetShardID(), Nonce: h.GetNonce(), Round: h.GetRound(), Epoch: h.GetEpoch()})
	}
	for _, s := range executed {
		m.ShardInfo = append(m.ShardInfo, block.ShardData{HeaderHash: n.hash(s), ShardID: s.GetShardID(),
			Nonce: s.GetNonce(), Round: s.GetRound(), Epoch: s.GetEpoch()})
	}
	n.metaTip, n.metaHsh = m, n.hold(m)
	return n.metaHsh
}

// next builds the next own-chain header. carry adds every uncarried execution
// result; refs are the metachain references of a shard header.
func (n *sp222Node) next(carry bool, refs ...[]byte) data.HeaderHandler {
	var results []*block.BaseExecutionResult
	if carry {
		for _, e := range n.uncarried {
			results = append(results, &block.BaseExecutionResult{HeaderHash: e.hash, HeaderNonce: e.header.GetNonce(),
				HeaderRound: e.header.GetRound(), HeaderEpoch: e.header.GetEpoch(), RootHash: e.root})
		}
		n.uncarried = nil
	}
	if n.self == core.MetachainShardId {
		m := &block.MetaBlockV3{Nonce: n.metaTip.Nonce + 1, Round: n.metaTip.Round + 1, Epoch: 4, ChainID: []byte("unit-chain"),
			PrevHash: n.metaHsh, PrevRandSeed: n.metaTip.RandSeed, RandSeed: []byte{byte(n.metaTip.Nonce + 1)}}
		for _, r := range results {
			m.ExecutionResults = append(m.ExecutionResults, &block.MetaExecutionResult{
				ExecutionResult: &block.BaseMetaExecutionResult{BaseExecutionResult: r}})
		}
		return m
	}
	h := &block.HeaderV3{ShardID: n.self, Nonce: n.tip.GetNonce() + 1, Round: n.tip.GetRound() + 1, Epoch: 3,
		ChainID: []byte("unit-chain"), PrevHash: n.tipHash, PrevRandSeed: n.tip.GetRandSeed(),
		RandSeed: []byte{byte(n.tip.GetNonce() + 1)}, MetaBlockHashes: refs}
	for _, r := range results {
		h.ExecutionResults = append(h.ExecutionResults, &block.ExecutionResult{BaseExecutionResult: r})
	}
	return h
}

// begin runs the import phase of a block; commit ends its execution.
func (n *sp222Node) begin(h data.HeaderHandler) error {
	require.Equal(n.t, 0, n.store.JournalLen())
	return n.imp.BeginBlock(h, n.hash(h))
}

func (n *sp222Node) commit(h data.HeaderHandler) []byte {
	root, err := n.store.Commit()
	require.NoError(n.t, err)
	n.imp.EndBlock(true)
	hash := n.hold(h)
	e := sp222Executed{header: h, hash: hash, root: bytes.Clone(root)}
	n.uncarried = append(n.uncarried, e)
	n.executed[string(hash)] = e
	if n.self == core.MetachainShardId {
		n.metaTip, n.metaHsh = h.(*block.MetaBlockV3), hash
	} else {
		n.tip, n.tipHash = h, hash
	}
	return root
}

func (n *sp222Node) revert() {
	require.NoError(n.t, n.store.RevertToSnapshot(0))
	n.imp.EndBlock(false)
}

// run executes one block with optional staging and returns its header.
func (n *sp222Node) run(h data.HeaderHandler, stage ...string) data.HeaderHandler {
	require.NoError(n.t, n.begin(h))
	for _, key := range stage {
		require.NoError(n.t, n.stage(key, 0, nil, "body of "+key))
	}
	n.commit(h)
	return h
}

func (n *sp222Node) stage(key string, version uint64, predecessor []byte, body string) error {
	return n.imp.Stage([]byte(key), version, predecessor, []byte(body), func(gas uint64) error {
		n.class.charged += gas
		return nil
	})
}

func (n *sp222Node) value(kind string, fields ...[]byte) []byte {
	records, err := newPendingFinalRecords(n.store, &RollbackContainment{stores: []state.AccountsAdapter{n.store}},
		n.mar, blake2b.NewBlake2b(), 4096, &pendingFinalTestHost{})
	require.NoError(n.t, err)
	key, err := records.key(kind, fields...)
	require.NoError(n.t, err)
	v, err := records.read(key)
	require.NoError(n.t, err)
	return v
}

func (n *sp222Node) final(key string) []byte {
	encoded, commitment, err := n.imp.Final([]byte(key))
	require.NoError(n.t, err)
	require.Equal(n.t, len(encoded) != 0, len(commitment) != 0)
	return encoded
}

func (n *sp222Node) root() []byte {
	root, err := n.store.RootHash()
	require.NoError(n.t, err)
	return bytes.Clone(root)
}

// sp222ShardStory stages two records in S, carries the result in H = S+1 and
// has the metachain reference H in block M. It returns S, H and hash(M).
func sp222ShardStory(n *sp222Node) (s, h data.HeaderHandler, m []byte) {
	s = n.run(n.next(false), "class/a", "class/b")
	h = n.run(n.next(true))
	m = n.meta([]data.HeaderHandler{h}, []data.HeaderHandler{s})
	return s, h, m
}

func TestQualSP222ShardLocalPromotionNeedsTwoProofedDescendants(t *testing.T) {
	n := newSP222Node(t, 0, true)
	s, _, m := sp222ShardStory(n)
	sHash := n.hash(s)
	require.NotEmpty(t, n.value("origin", sHash))
	require.Equal(t, n.executed[string(sHash)].root, n.value("seal", sHash), "S+1 sealed the root of S")
	require.Equal(t, uint64(14), n.class.charged, "each write paid its finalization work once")
	require.Equal(t, []int{0, 1}, n.class.positions, "the class prices each item at its position in the block's write set")

	// B references M itself: reference inclusion is not settlement.
	n.run(n.next(false, m))
	require.Empty(t, n.final("class/a"))
	// One proofed descendant in B's ancestry: still not final.
	n.run(n.next(false, n.meta(nil, nil)))
	require.Empty(t, n.final("class/a"))
	require.NotEmpty(t, n.value("pending", []byte("class/a")))
	// Second proofed descendant: the whole manifest is promoted at the import phase.
	b := n.next(false, n.meta(nil, nil))
	require.NoError(t, n.begin(b))
	require.NotEmpty(t, n.final("class/a"))
	require.NotEmpty(t, n.final("class/b"))
	require.Empty(t, n.value("pending", []byte("class/a")))
	require.Empty(t, n.value("origin", sHash))
	require.Empty(t, n.value("seal", sHash))
	require.Empty(t, n.value("open"))
	n.commit(b)
	observations := n.imp.CommittedObservations()
	require.Len(t, observations, 2)
	require.Equal(t, []byte(FinalHeadObservation), observations[0].Logs[0].Identifier)
	require.Equal(t, []byte("class/a"), observations[0].Logs[0].Topics[0])
	require.Equal(t, sHash, observations[0].Logs[0].Topics[3])
	require.Equal(t, uint64(14), n.class.charged, "promotion charges nothing more")
}

func TestQualSP222OneBlockReferencingThreeMetaBlocks(t *testing.T) {
	n := newSP222Node(t, 0, true)
	_, _, m := sp222ShardStory(n)
	m2 := n.meta(nil, nil)
	m3 := n.meta(nil, nil)
	n.src.asked = nil
	n.run(n.next(false, m, m2, m3))
	require.NotEmpty(t, n.final("class/a"))
	// Bounded retrieval (Q04/Q07): k+2 metachain headers and proofs, H with its
	// proof, S. Nothing else is asked from the node.
	require.Len(t, n.src.asked, 2*5+2+1)
}

// Q01 and Q07: two nodes hold the same committed chain; one received every
// header late and in reverse and also holds unrelated proofed siblings.
func TestQualSP222ArrivalOrderDoesNotChangePromotion(t *testing.T) {
	type step struct {
		header data.HeaderHandler
		stage  []string
	}
	first := newSP222Node(t, 0, true)
	var steps []step
	do := func(h data.HeaderHandler, stage ...string) {
		steps = append(steps, step{h, stage})
		first.run(h, stage...)
	}
	do(first.next(false), "class/a", "class/b")
	s := steps[0].header
	do(first.next(true))
	m := first.meta([]data.HeaderHandler{steps[1].header}, []data.HeaderHandler{s})
	do(first.next(false, m), "class/c")
	do(first.next(true, first.meta(nil, nil)))
	do(first.next(false, first.meta(nil, nil)))
	var firstRoots [][]byte
	for _, st := range steps {
		firstRoots = append(firstRoots, first.executed[string(first.hash(st.header))].root)
	}

	second := newSP222Node(t, 0, true)
	sibling := &block.MetaBlockV3{Nonce: 33, Round: 99, Epoch: 4, ChainID: []byte("unit-chain"), RandSeed: []byte{9},
		ShardInfo: []block.ShardData{{HeaderHash: first.hash(s), ShardID: 0, Nonce: s.GetNonce(), Round: s.GetRound(), Epoch: s.GetEpoch()}}}
	second.hold(sibling)
	for i := len(steps) - 1; i >= 0; i-- {
		second.hold(steps[i].header)
	}
	for hash, h := range first.src.headers {
		second.src.headers[hash] = h
		second.src.proofs[hash] = first.src.proofs[hash]
	}
	for i, st := range steps {
		require.NoError(t, second.begin(st.header))
		for _, key := range st.stage {
			require.NoError(t, second.stage(key, 0, nil, "body of "+key))
		}
		require.Equal(t, firstRoots[i], second.commit(st.header), "block %d", i)
	}
	for _, key := range []string{"class/a", "class/b", "class/c"} {
		require.Equal(t, first.final(key), second.final(key), key)
	}
	require.NotEmpty(t, first.final("class/a"))
	require.Empty(t, first.final("class/c"), "the later origin is not yet final on either node")
}

// Q02 and Q06: nothing below is promoted; evidence failures refuse the block.
func TestQualSP222NothingIsPromotedWithoutTheWholePredicate(t *testing.T) {
	t.Run("another shard's identity and an unstaged origin promote nothing", func(t *testing.T) {
		n := newSP222Node(t, 0, true)
		s := n.run(n.next(false), "class/a")
		h := n.run(n.next(true))
		foreign := &block.HeaderV3{ShardID: 1, Nonce: s.GetNonce(), Round: s.GetRound(), Epoch: 3, ChainID: []byte("unit-chain")}
		m := n.meta([]data.HeaderHandler{h}, []data.HeaderHandler{foreign, h})
		n.run(n.next(false, m, n.meta(nil, nil), n.meta(nil, nil)))
		require.Empty(t, n.final("class/a"))
		require.NotEmpty(t, n.value("pending", []byte("class/a")))
	})
	t.Run("S and H swapped between the two lists promote nothing", func(t *testing.T) {
		n := newSP222Node(t, 0, true)
		s := n.run(n.next(false), "class/a")
		h := n.run(n.next(true))
		m := n.meta([]data.HeaderHandler{s}, []data.HeaderHandler{h})
		n.run(n.next(false, m, n.meta(nil, nil), n.meta(nil, nil)))
		require.Empty(t, n.final("class/a"))
	})
	refused := func(name string, spoil func(n *sp222Node, s, h data.HeaderHandler, m []byte), repair func(n *sp222Node)) {
		t.Run(name, func(t *testing.T) {
			n := newSP222Node(t, 0, true)
			s, h, m := sp222ShardStory(n)
			m2, m3 := n.meta(nil, nil), n.meta(nil, nil)
			b := n.next(false, m, m2, m3)
			spoil(n, s, h, m)
			before := n.root()
			require.Error(t, n.begin(b))
			n.revert()
			require.Equal(t, before, n.root())
			require.Empty(t, n.final("class/a"))
			require.Error(t, n.stage("class/z", 0, nil, "late"), "no execution is open after a refused import")
			if repair == nil {
				return
			}
			repair(n)
			require.NoError(t, n.begin(b), "the same block succeeds once the evidence is held")
			require.NotEmpty(t, n.final("class/a"))
		})
	}
	var kept data.HeaderProofHandler
	var keptHeader data.HeaderHandler
	refused("missing proof of a descendant", func(n *sp222Node, _, _ data.HeaderHandler, _ []byte) {
		kept = n.src.proofs[string(n.metaHsh)]
		delete(n.src.proofs, string(n.metaHsh))
	}, func(n *sp222Node) { n.src.proofs[string(n.metaHsh)] = kept })
	refused("missing carrying header", func(n *sp222Node, _, h data.HeaderHandler, _ []byte) {
		keptHeader = h
		delete(n.src.headers, string(n.hash(h)))
	}, func(n *sp222Node) { n.src.headers[string(n.hash(keptHeader))] = keptHeader })
	refused("missing proof of the carrying header", func(n *sp222Node, _, h data.HeaderHandler, _ []byte) {
		keptHeader = h
		kept = n.src.proofs[string(n.hash(h))]
		delete(n.src.proofs, string(n.hash(h)))
	}, func(n *sp222Node) { n.src.proofs[string(n.hash(keptHeader))] = kept })
	refused("missing executed header", func(n *sp222Node, s, _ data.HeaderHandler, _ []byte) {
		keptHeader = s
		delete(n.src.headers, string(n.hash(s)))
	}, func(n *sp222Node) { n.src.headers[string(n.hash(keptHeader))] = keptHeader })
	refused("missing referenced metachain header", func(n *sp222Node, _, _ data.HeaderHandler, m []byte) {
		keptHeader = n.src.headers[string(m)]
		delete(n.src.headers, string(m))
	}, func(n *sp222Node) { n.src.headers[string(n.hash(keptHeader))] = keptHeader })
	refused("proof rejected by the native verifier", func(n *sp222Node, _, _ data.HeaderHandler, _ []byte) {
		n.oracle.failure = errors.New("bad aggregate")
	}, func(n *sp222Node) { n.oracle.failure = nil })
	refused("proof for another header", func(n *sp222Node, _, _ data.HeaderHandler, m []byte) {
		kept = n.src.proofs[string(m)]
		n.src.proofs[string(m)] = n.src.proofs[string(n.metaHsh)]
	}, func(n *sp222Node) {
		n.src.proofs[string(n.hash(n.src.headers[string(kept.GetHeaderHash())]))] = kept
	})
	refused("a different header is returned for a committed hash", func(n *sp222Node, s, h data.HeaderHandler, _ []byte) {
		n.src.headers[string(n.hash(s))] = h
	}, nil)
	refused("the source returns nothing", func(n *sp222Node, _, _ data.HeaderHandler, m []byte) {
		n.src.headers[string(m)] = nil
	}, nil)
	refused("the source returns no proof object", func(n *sp222Node, _, _ data.HeaderHandler, m []byte) {
		n.src.proofs[string(m)] = nil
	}, nil)
	refused("the sealed root is not the root the carrying header commits", func(n *sp222Node, s, _ data.HeaderHandler, _ []byte) {
		// The manifest was committed under another root than H claims for S.
		sealKey := n.sealKey(s)
		a, err := n.store.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, err)
		require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(sealKey, bytes.Repeat([]byte{9}, 32)))
		require.NoError(t, n.store.SaveAccount(a))
		_, err = n.store.Commit()
		require.NoError(t, err)
	}, nil)
}

func (n *sp222Node) sealKey(s data.HeaderHandler) []byte {
	records, err := newPendingFinalRecords(n.store, &RollbackContainment{stores: []state.AccountsAdapter{n.store}},
		n.mar, blake2b.NewBlake2b(), 4096, &pendingFinalTestHost{})
	require.NoError(n.t, err)
	key, err := records.key(finalitySealKind, n.hash(s))
	require.NoError(n.t, err)
	return key
}

// Q02 conflicting result and Q05: the carrying header is opened; identities
// present in the reference without the carrying relation prove nothing.
func TestQualSP222CarryingHeaderRelation(t *testing.T) {
	t.Run("a carrying header with another root for S is refused", func(t *testing.T) {
		n := newSP222Node(t, 0, true)
		s := n.run(n.next(false), "class/a")
		n.uncarried[0].root = bytes.Repeat([]byte{7}, 32)
		h := n.run(n.next(true))
		m := n.meta([]data.HeaderHandler{h}, []data.HeaderHandler{s})
		require.Error(t, n.begin(n.next(false, m, n.meta(nil, nil), n.meta(nil, nil))))
		n.revert()
		require.Empty(t, n.final("class/a"))
	})
	t.Run("a carrying header with other coordinates for S is refused", func(t *testing.T) {
		n := newSP222Node(t, 0, true)
		s := n.run(n.next(false), "class/a")
		h := n.next(true).(*block.HeaderV3)
		h.ExecutionResults[0].BaseExecutionResult.HeaderRound++
		n.run(h)
		m := n.meta([]data.HeaderHandler{h}, []data.HeaderHandler{s})
		require.Error(t, n.begin(n.next(false, m, n.meta(nil, nil), n.meta(nil, nil))))
		n.revert()
	})
	t.Run("S named without any proposed header carrying its result is refused", func(t *testing.T) {
		n := newSP222Node(t, 0, true)
		s := n.run(n.next(false), "class/a")
		n.run(n.next(true))
		other := n.run(n.next(false))
		m := n.meta([]data.HeaderHandler{other}, []data.HeaderHandler{s})
		require.Error(t, n.begin(n.next(false, m, n.meta(nil, nil), n.meta(nil, nil))))
		n.revert()
		require.Empty(t, n.final("class/a"))
	})
	t.Run("two proposed headers carrying a result for S are refused", func(t *testing.T) {
		n := newSP222Node(t, 0, true)
		s := n.run(n.next(false), "class/a")
		kept := n.uncarried
		h := n.run(n.next(true))
		n.uncarried = append(kept, n.uncarried...)
		h2 := n.run(n.next(true))
		m := n.meta([]data.HeaderHandler{h, h2}, []data.HeaderHandler{s})
		require.Error(t, n.begin(n.next(false, m, n.meta(nil, nil), n.meta(nil, nil))))
		n.revert()
	})
	t.Run("S listed twice in the reference is refused", func(t *testing.T) {
		n := newSP222Node(t, 0, true)
		s := n.run(n.next(false), "class/a")
		h := n.run(n.next(true))
		m := n.meta([]data.HeaderHandler{h}, []data.HeaderHandler{s, s})
		require.Error(t, n.begin(n.next(false, m, n.meta(nil, nil), n.meta(nil, nil))))
		n.revert()
	})
	t.Run("S and H as separate valid entries of one reference", func(t *testing.T) {
		// H1 carries S; H2 carries H1. One metachain block proposes H1 and H2
		// and therefore lists both S and H1 as executed identities.
		n := newSP222Node(t, 0, true)
		s := n.run(n.next(false), "class/a")
		h1 := n.run(n.next(true), "class/b")
		h2 := n.run(n.next(true))
		foreign := &block.HeaderV3{ShardID: 1, Nonce: 5, Round: 6, Epoch: 3, ChainID: []byte("unit-chain")}
		m := n.meta([]data.HeaderHandler{foreign, h1, h2}, []data.HeaderHandler{s, h1})
		n.run(n.next(false, m, n.meta(nil, nil), n.meta(nil, nil)))
		require.NotEmpty(t, n.final("class/a"), "S through H1")
		require.NotEmpty(t, n.final("class/b"), "H1, as an executed block, through H2")
		require.Empty(t, n.value("open"))
	})
}

// Q02: one live pending successor, idempotent retry, no second import.
func TestQualSP222SingleSuccessorAndDuplicateImport(t *testing.T) {
	n := newSP222Node(t, 0, true)
	s := n.next(false)
	require.NoError(t, n.begin(s))
	require.NoError(t, n.stage("class/a", 0, nil, "one"))
	require.NoError(t, n.stage("class/a", 0, nil, "one"), "exact retry")
	require.Equal(t, uint64(7), n.class.charged, "the retry is not charged")
	require.Error(t, n.stage("class/a", 0, nil, "two"), "a different second candidate")
	require.Error(t, n.stage("class/a", 1, bytes.Repeat([]byte{1}, 32), "three"), "wrong predecessor")
	n.commit(s)
	h := n.run(n.next(true))
	m := n.meta([]data.HeaderHandler{h}, []data.HeaderHandler{s})
	n.run(n.next(false, m, n.meta(nil, nil), n.meta(nil, nil)))
	head := n.final("class/a")
	require.NotEmpty(t, head)

	// A later reference naming S again finds no manifest: nothing changes.
	again := n.meta([]data.HeaderHandler{h}, []data.HeaderHandler{s})
	before := n.root()
	b := n.next(false, again, n.meta(nil, nil), n.meta(nil, nil))
	require.NoError(t, n.begin(b))
	require.Equal(t, before, n.root())
	// The successor must name the final head; it becomes pending, not final.
	require.Error(t, n.stage("class/a", 1, nil, "next"))
	require.NoError(t, n.stage("class/a", 1, blake2b.NewBlake2b().Compute(string(head)), "next"))
	require.Equal(t, head, n.final("class/a"))
	n.commit(b)
}

// Q03: a replacement block reverts promotion and every dependent effect; a
// restart reproduces the same pending and final heads.
func TestQualSP222ReplacementBlockAndRestart(t *testing.T) {
	n := newSP222Node(t, 0, true)
	_, _, m := sp222ShardStory(n)
	m2, m3 := n.meta(nil, nil), n.meta(nil, nil)
	parentRoot := n.root()

	b := n.next(false, m, m2, m3)
	require.NoError(t, n.begin(b))
	require.NotEmpty(t, n.final("class/a"))
	// A dependent effect of the same block: a successor that names the new head
	// and an ordinary balance change.
	require.NoError(t, n.stage("class/a", 1, blake2b.NewBlake2b().Compute(string(n.final("class/a"))), "dependent"))
	require.NoError(t, qualContainmentBalance(n.store, 55))
	n.revert()
	require.Equal(t, parentRoot, n.root())
	require.Empty(t, n.final("class/a"))
	require.NotEmpty(t, n.value("pending", []byte("class/a")))
	require.Empty(t, n.value("pending", []byte("class/a"))[:0])
	qualAssertContainmentBalance(t, n.store, 100)
	require.Empty(t, n.imp.CommittedObservations())

	// The replacement at the same height does not reference the metachain.
	replacement := n.next(false)
	replacementRoot := n.commitRun(replacement)
	require.Empty(t, n.final("class/a"))
	require.NotEmpty(t, n.value("pending", []byte("class/a")))

	// Restart: a new store over the same database and a new owner.
	restarted := n.restart(replacementRoot)
	require.Empty(t, restarted.final("class/a"))
	require.Equal(t, n.value("pending", []byte("class/a")), restarted.value("pending", []byte("class/a")))
	require.Equal(t, n.value("open"), restarted.value("open"))

	// Both continue with the same next block and reach the same heads and root.
	b2 := n.next(false, m, m2, m3)
	rootA := n.commitRun(b2)
	restarted.tip, restarted.tipHash = replacement, n.hash(replacement)
	rootB := restarted.commitRun(b2)
	require.Equal(t, rootA, rootB)
	require.NotEmpty(t, restarted.final("class/a"))
	require.Equal(t, n.final("class/a"), restarted.final("class/a"))
	require.Equal(t, n.final("class/b"), restarted.final("class/b"))
}

func (n *sp222Node) commitRun(h data.HeaderHandler) []byte {
	require.NoError(n.t, n.begin(h))
	return n.commit(h)
}

func (n *sp222Node) restart(root []byte) *sp222Node {
	args, _ := qualContainmentArgs(n.t, n.store.backing)
	adb, err := state.NewAccountsDB(args)
	require.NoError(n.t, err)
	require.NoError(n.t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	r := &sp222Node{t: n.t, self: n.self, store: &qualNativeStore{AccountsAdapter: adb, backing: n.store.backing},
		mar: n.mar, src: n.src, class: n.class, oracle: n.oracle, executed: n.executed,
		tip: n.tip, tipHash: n.tipHash, metaTip: n.metaTip, metaHsh: n.metaHsh}
	r.faults = &sp222FaultStore{qualNativeStore: r.store}
	r.imp = r.owner()
	return r
}

// Q07: the import needs no old state root and no header older than the walk.
func TestQualSP222PrunedHistoryAndRestartBeforePromotion(t *testing.T) {
	n := newSP222Node(t, 0, true)
	s, h, m := sp222ShardStory(n)
	lastRoot := n.root()
	m2, m3 := n.meta(nil, nil), n.meta(nil, nil)
	needed := map[string]bool{string(n.hash(s)): true, string(n.hash(h)): true, string(m): true, string(m2): true, string(m3): true}
	for i, link := 0, n.src.headers[string(m)].GetPrevHash(); i < 2; i++ {
		needed[string(link)] = true
		link = n.src.headers[string(link)].GetPrevHash()
	}
	for hash := range n.src.headers {
		if !needed[hash] {
			delete(n.src.headers, hash)
			delete(n.src.proofs, hash)
		}
	}
	restarted := n.restart(lastRoot)
	restarted.run(restarted.next(false, m, m2, m3))
	require.NotEmpty(t, restarted.final("class/a"))
	require.NotEmpty(t, restarted.final("class/b"))
}

func TestQualSP222MetachainLocalPromotion(t *testing.T) {
	n := newSP222Node(t, core.MetachainShardId, true)
	s := n.run(n.next(false), "class/a")
	sHash := n.hash(s)
	n.run(n.next(true)) // H carries the result of S
	require.Equal(t, n.executed[string(sHash)].root, n.value("seal", sHash))
	n.run(n.next(false)) // H is the parent: depth 0
	require.Empty(t, n.final("class/a"))
	n.run(n.next(false)) // depth 1
	require.Empty(t, n.final("class/a"))
	b := n.next(false) // H has two proofed descendants below B
	require.NoError(t, n.begin(b))
	require.NotEmpty(t, n.final("class/a"))
	n.revert()
	require.Empty(t, n.final("class/a"), "a replaced metachain block reverts the promotion")

	// A consuming block that does not construct on its parent is refused.
	bad := n.next(false).(*block.MetaBlockV3)
	bad.PrevRandSeed = []byte("other")
	require.Error(t, n.begin(bad))
	n.revert()
	n.run(b)
	require.NotEmpty(t, n.final("class/a"))
	require.Empty(t, n.value("open"))
}

// INV-0: with no finalization item in the state the import phase reads no
// header and no proof and changes nothing, on a shard and on the metachain,
// with and without a system account.
func TestQualSP222NoItemNoWork(t *testing.T) {
	for _, self := range []uint32{0, core.MetachainShardId} {
		for _, withAccount := range []bool{true, false} {
			n := newSP222Node(t, self, withAccount)
			n.src.asked = nil
			before := n.root()
			var h data.HeaderHandler
			if self == core.MetachainShardId {
				h = n.next(false)
			} else {
				h = n.next(false, n.metaHsh)
			}
			require.NoError(t, n.begin(h))
			require.Equal(t, 0, n.store.JournalLen())
			require.NoError(t, qualContainmentBalance(n.store, 30))
			require.Empty(t, n.final("class/a"))
			root := n.commit(h)
			require.Empty(t, n.src.asked)
			require.NotEqual(t, before, root)

			// The same block on a store without the owner gives the same root.
			plain := qualContainmentStore(t)
			if withAccount {
				a, err := plain.LoadAccount(core.SystemAccountAddress)
				require.NoError(t, err)
				require.NoError(t, plain.SaveAccount(a))
				_, err = plain.Commit()
				require.NoError(t, err)
			}
			require.NoError(t, qualContainmentBalance(plain, 30))
			plainRoot, err := plain.Commit()
			require.NoError(t, err)
			require.Equal(t, plainRoot, root)
		}
	}
}

func TestQualSP222StagingIsRefusedOutsideItsContract(t *testing.T) {
	n := newSP222Node(t, 0, true)
	require.Error(t, n.stage("class/a", 0, nil, "x"), "no block in execution")
	s := n.next(false)
	require.NoError(t, n.begin(s))
	root := n.root()
	require.Error(t, n.imp.Stage([]byte("class/a"), 0, nil, []byte("x"), nil), "no payer")
	require.Error(t, n.stage("other/a", 0, nil, "x"), "no installed class")
	require.Error(t, n.stage("class/a", 0, nil, ""), "empty body")
	n.class.admit = errors.New("class refuses")
	require.Error(t, n.stage("class/a", 0, nil, "x"))
	n.class.admit = nil
	n.class.gas = 0
	require.Error(t, n.stage("class/a", 0, nil, "x"), "a class without a finalization charge")
	n.class.gas = 7
	require.Error(t, n.imp.Stage([]byte("class/a"), 0, nil, []byte("x"), func(uint64) error { return errors.New("out of gas") }))
	require.Equal(t, root, n.root(), "a refused write leaves no state")
	require.Empty(t, n.value("open"))
	require.Zero(t, n.class.charged)
	n.commit(s)
	require.Error(t, n.stage("class/a", 0, nil, "x"), "the execution is closed after commit")

	t.Run("no system account: staging cannot create the namespace", func(t *testing.T) {
		bare := newSP222Node(t, 0, false)
		require.NoError(t, bare.begin(bare.next(false)))
		require.Error(t, bare.stage("class/a", 0, nil, "x"))
	})
	t.Run("the work one block can register is bounded", func(t *testing.T) {
		m := newSP222Node(t, 0, true)
		require.NoError(t, m.begin(m.next(false)))
		limit := 4096 / (32 + 2)
		for i := 0; i < limit; i++ {
			require.NoError(t, m.stage("class/"+string(rune('A'+i/26))+string(rune('a'+i%26)), 0, nil, "x"), "item %d", i)
		}
		require.Error(t, m.stage("class/over", 0, nil, "x"))
	})
}

func TestQualSP222BeginBlockGuards(t *testing.T) {
	n := newSP222Node(t, 0, true)
	h := n.next(false)
	require.ErrorIs(t, n.imp.BeginBlock(nil, n.hash(h)), ErrFinalityImport)
	require.ErrorIs(t, n.imp.BeginBlock(h, nil), ErrFinalityImport)
	require.ErrorIs(t, n.imp.BeginBlock(&block.Header{ShardID: 0}, n.hash(h)), ErrFinalityImport)
	require.ErrorIs(t, n.imp.BeginBlock(&block.HeaderV3{ShardID: 1}, n.hash(h)), ErrFinalityImport)
	require.NoError(t, qualContainmentBalance(n.store, 31))
	require.ErrorIs(t, n.imp.BeginBlock(h, n.hash(h)), ErrUncommittedState, "the import phase starts from committed stores")
	require.NoError(t, n.store.RevertToSnapshot(0))

	// With open work the consuming header itself must be the committed one.
	n.run(h, "class/a")
	b := n.next(true)
	require.ErrorIs(t, n.imp.BeginBlock(b, n.hash(h)), ErrFinalityImport)
	n.revert()
	// A shard header with more references than the native maximum.
	many := n.next(false, make([][]byte, 100)...)
	require.ErrorIs(t, n.begin(many), ErrFinalityImport)
	n.revert()
	// References that are not the walked ancestry in order.
	m1 := n.meta(nil, nil)
	m2 := n.meta(nil, nil)
	require.ErrorIs(t, n.begin(n.next(false, m2, m1)), ErrFinalityImport)
	n.revert()
	// A corrupted work counter refuses the block.
	a, err := n.store.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	records, err := newPendingFinalRecords(n.store, &RollbackContainment{stores: []state.AccountsAdapter{n.store}},
		n.mar, blake2b.NewBlake2b(), 4096, &pendingFinalTestHost{})
	require.NoError(t, err)
	openKey, err := records.key(finalityOpenKind)
	require.NoError(t, err)
	require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(openKey, []byte{1}))
	require.NoError(t, n.store.SaveAccount(a))
	_, err = n.store.Commit()
	require.NoError(t, err)
	require.ErrorIs(t, n.begin(n.next(false)), ErrFinalityImport)
	a, err = n.store.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(openKey, binary.BigEndian.AppendUint64(nil, 0)))
	require.NoError(t, n.store.SaveAccount(a))
	_, err = n.store.Commit()
	require.NoError(t, err)
	require.ErrorIs(t, n.begin(n.next(false)), ErrFinalityImport)
}

func TestQualSP222ConstructorAndAccountReadFailures(t *testing.T) {
	n := newSP222Node(t, 0, true)
	good := n.imp.args
	for name, spoil := range map[string]func(*ArgsFinalityImport){
		"accounts":    func(a *ArgsFinalityImport) { a.Accounts = nil },
		"marshaller":  func(a *ArgsFinalityImport) { a.Marshaller = nil },
		"hasher":      func(a *ArgsFinalityImport) { a.Hasher = nil },
		"source":      func(a *ArgsFinalityImport) { a.Source = nil },
		"validator":   func(a *ArgsFinalityImport) { a.Validator = nil },
		"proofs":      func(a *ArgsFinalityImport) { a.Proofs = nil },
		"integrity":   func(a *ArgsFinalityImport) { a.Integrity = nil },
		"exclusions":  func(a *ArgsFinalityImport) { a.Exclusions = nil },
		"record size": func(a *ArgsFinalityImport) { a.MaxRecordBytes = 0 },
		"tiny record": func(a *ArgsFinalityImport) { a.MaxRecordBytes = 8 },
		"class":       func(a *ArgsFinalityImport) { a.Classes = map[string]FinalityRecordClass{"x": nil} },
		"class name":  func(a *ArgsFinalityImport) { a.Classes = map[string]FinalityRecordClass{"": n.class} },
	} {
		args := good
		spoil(&args)
		_, err := NewFinalityImport(args)
		require.Error(t, err, name)
	}
	var none *FinalityImport
	require.True(t, none.IsInterfaceNil())
	require.True(t, (*finalityHost)(nil).IsInterfaceNil())
	require.False(t, n.imp.IsInterfaceNil())

	// A failed account read is not an absence: the block is refused (G15).
	broken := &sp222BrokenStore{qualNativeStore: n.store, failure: errors.New("trie node unavailable")}
	args := good
	args.Accounts = broken
	imp, err := NewFinalityImport(args)
	require.NoError(t, err)
	h := n.next(false)
	require.ErrorContains(t, imp.BeginBlock(h, n.hash(h)), "trie node unavailable")
	_, _, err = imp.Final([]byte("class/a"))
	require.ErrorContains(t, err, "trie node unavailable")
}

type sp222BrokenStore struct {
	*qualNativeStore
	failure error
}

func (s *sp222BrokenStore) GetExistingAccount([]byte) (vmcommon.AccountHandler, error) {
	return nil, s.failure
}

// Longest class prefix wins whatever the map order.
func TestQualSP222ClassSelectionIsDeterministic(t *testing.T) {
	n := newSP222Node(t, 0, true)
	wide, narrow := &sp222Class{gas: 1}, &sp222Class{gas: 100}
	args := n.imp.args
	args.Classes = map[string]FinalityRecordClass{"class/": wide, "class/special/": narrow, "clasz/": wide}
	imp, err := NewFinalityImport(args)
	require.NoError(t, err)
	require.Equal(t, []string{"class/special/", "class/", "clasz/"}, imp.prefixes)
	h := n.next(false)
	require.NoError(t, imp.BeginBlock(h, n.hash(h)))
	var charged uint64
	require.NoError(t, imp.Stage([]byte("class/special/a"), 0, nil, []byte("x"), func(g uint64) error { charged += g; return nil }))
	require.Equal(t, uint64(100), charged)
}

// The promotion host accepts only the evidence of the import phase.
func TestQualSP222HostRefusesPromotionOutsideTheImportPhase(t *testing.T) {
	n := newSP222Node(t, 0, true)
	s := n.run(n.next(false), "class/a")
	b := n.next(true)
	require.NoError(t, n.begin(b))
	encoded := n.value("pending", []byte("class/a"))
	require.NotEmpty(t, encoded)
	candidate := pendingFinalCandidate{key: []byte("class/a"), body: []byte("body of class/a"), origin: n.hash(s)}
	require.Error(t, n.imp.records.promote(candidate, []byte("requester evidence")))
	require.Error(t, n.imp.records.promoteResult([]pendingFinalPromotion{{candidate: candidate, evidence: []byte("x")}},
		[][]byte{blake2b.NewBlake2b().Compute(string(encoded))}, 1, 1024))
	host := (*finalityHost)(n.imp)
	require.Error(t, host.Canonical(encoded, []byte("x")))
	require.Error(t, host.Canonical([]byte("not a record"), []byte("x")))
	_, err := host.Observe([]byte("not a record"))
	require.Error(t, err)
	_, err = host.Initialize([]byte("not a record"))
	require.Error(t, err)
	n.revert()
	require.Error(t, host.Admit(encoded), "no execution open")
	require.Empty(t, n.final("class/a"))
}

// sp222FaultStore fails the n-th account load, value read, value write,
// account save or root read of the owner's store.
type sp222FaultStore struct {
	*qualNativeStore
	kind   string
	at     int
	count  int
	totals map[string]int
}

var errSP222Fault = errors.New("injected state fault")

func (s *sp222FaultStore) hit(kind string) error {
	if s.totals != nil {
		s.totals[kind]++
	}
	if s.kind != kind {
		return nil
	}
	s.count++
	if s.count == s.at {
		return errSP222Fault
	}
	return nil
}

type sp222FaultAccount struct {
	state.UserAccountHandler
	store *sp222FaultStore
}

func (a *sp222FaultAccount) RetrieveValue(key []byte) ([]byte, uint32, error) {
	if err := a.store.hit("read"); err != nil {
		return nil, 0, err
	}
	return a.UserAccountHandler.RetrieveValue(key)
}
func (a *sp222FaultAccount) SaveKeyValue(key, value []byte) error {
	if err := a.store.hit("write"); err != nil {
		return err
	}
	return a.UserAccountHandler.SaveKeyValue(key, value)
}
func (s *sp222FaultStore) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	if err := s.hit("load"); err != nil {
		return nil, err
	}
	a, err := s.qualNativeStore.GetExistingAccount(address)
	if err != nil {
		return nil, err
	}
	return &sp222FaultAccount{UserAccountHandler: a.(state.UserAccountHandler), store: s}, nil
}
func (s *sp222FaultStore) SaveAccount(account vmcommon.AccountHandler) error {
	if a, ok := account.(*sp222FaultAccount); ok {
		account = a.UserAccountHandler
	}
	if err := s.hit("save"); err != nil {
		return err
	}
	return s.qualNativeStore.SaveAccount(account)
}
func (s *sp222FaultStore) RootHash() ([]byte, error) {
	if err := s.hit("root"); err != nil {
		return nil, err
	}
	return s.qualNativeStore.RootHash()
}

// Every state access of staging, sealing and promotion is failed in turn. The
// failure is always reported, the block state reverts to its starting root,
// nothing is partly promoted, and the same step succeeds afterwards.
func TestQualSP222StateFaultsNeverLeaveAPartialResult(t *testing.T) {
	type scenario struct {
		prepare func(n *sp222Node) data.HeaderHandler
		stage   bool
		done    func(n *sp222Node) bool
	}
	steps := map[string]scenario{
		"staging": {
			prepare: func(n *sp222Node) data.HeaderHandler { return n.next(false) },
			stage:   true,
			done: func(n *sp222Node) bool {
				return len(n.value("pending", []byte("class/a"))) != 0 && len(n.value("open")) == 8
			},
		},
		"sealing": {
			prepare: func(n *sp222Node) data.HeaderHandler {
				n.run(n.next(false), "class/a", "class/b")
				return n.next(true)
			},
			done: func(n *sp222Node) bool { return len(n.value("seal", n.tipHash)) != 0 },
		},
		"promotion": {
			prepare: func(n *sp222Node) data.HeaderHandler {
				_, _, m := sp222ShardStory(n)
				return n.next(false, m, n.meta(nil, nil), n.meta(nil, nil))
			},
			done: func(n *sp222Node) bool {
				return len(n.final("class/a")) != 0 && len(n.final("class/b")) != 0 && len(n.value("open")) == 0
			},
		},
		"metachain promotion": {
			prepare: func(n *sp222Node) data.HeaderHandler {
				n.run(n.next(false), "class/a", "class/b")
				n.run(n.next(true))
				n.run(n.next(false))
				n.run(n.next(false))
				return n.next(false)
			},
			done: func(n *sp222Node) bool { return len(n.final("class/a")) != 0 && len(n.value("open")) == 0 },
		},
	}
	for name, step := range steps {
		for _, kind := range []string{"load", "read", "write", "save", "root"} {
			injected := 0
			for at := 1; at < 400; at++ {
				self := uint32(0)
				if name == "metachain promotion" {
					self = core.MetachainShardId
				}
				n := newSP222Node(t, self, true)
				h := step.prepare(n)
				before := n.root()
				n.faults.kind, n.faults.at, n.faults.count = kind, at, 0
				err := n.begin(h)
				if err == nil && step.stage {
					err = n.stage("class/a", 0, nil, "body")
				}
				reached := n.faults.count >= at
				n.faults.kind = ""
				if !reached {
					require.NoError(t, err, "%s %s %d", name, kind, at)
					break
				}
				injected++
				require.ErrorIs(t, err, errSP222Fault, "%s: %s fault %d must be reported", name, kind, at)
				n.revert()
				require.Equal(t, before, n.root(), "%s %s %d", name, kind, at)
				require.Empty(t, n.final("class/a"))
				require.NoError(t, n.begin(h), "%s %s %d: retry", name, kind, at)
				if step.stage {
					require.NoError(t, n.stage("class/a", 0, nil, "body"))
				}
				require.True(t, step.done(n), "%s %s %d: retry result", name, kind, at)
			}
			if kind != "root" || name == "sealing" {
				require.NotZero(t, injected, "%s: no %s access was exercised", name, kind)
			}
		}
	}
}

// The walk ends at the first metachain header that is not V3: nothing below it
// is examined and no error is raised.
func TestQualSP222WalkEndsBelowTheFirstV3MetaBlock(t *testing.T) {
	n := newSP222Node(t, 0, true)
	n.run(n.next(false), "class/a")
	n.run(n.next(true))
	n.src.asked = nil
	n.run(n.next(false, n.bases[0]))
	require.Empty(t, n.final("class/a"))
	require.NotEmpty(t, n.value("pending", []byte("class/a")))

	meta := newSP222NodeOnBase(t, core.MetachainShardId, true, 1)
	meta.run(meta.next(false), "class/a")
	meta.run(meta.next(true))
	require.Empty(t, meta.final("class/a"))
	// A missing ancestor is an error, not an end of the walk.
	delete(meta.src.headers, string(meta.bases[0]))
	require.Error(t, meta.begin(meta.next(false)))
}

// Damaged finalization state refuses the block; it is never worked around.
func TestQualSP222DamagedFinalizationStateRefusesTheBlock(t *testing.T) {
	damage := func(name string, change func(n *sp222Node, s data.HeaderHandler, records *pendingFinalRecords, account state.UserAccountHandler)) {
		t.Run(name, func(t *testing.T) {
			n := newSP222Node(t, 0, true)
			s := n.run(n.next(false), "class/a", "class/b")
			h := n.next(true)
			records, err := newPendingFinalRecords(n.store, &RollbackContainment{stores: []state.AccountsAdapter{n.store}},
				n.mar, blake2b.NewBlake2b(), 4096, &pendingFinalTestHost{})
			require.NoError(t, err)
			if name != "the parent is already sealed" {
				n.run(h)
				h = n.next(false, n.meta([]data.HeaderHandler{h}, []data.HeaderHandler{s}), n.meta(nil, nil), n.meta(nil, nil))
			}
			a, err := n.store.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			change(n, s, records, a.(state.UserAccountHandler))
			require.NoError(t, n.store.SaveAccount(a))
			_, err = n.store.Commit()
			require.NoError(t, err)
			before := n.root()
			require.Error(t, n.begin(h))
			n.revert()
			require.Equal(t, before, n.root())
			require.Empty(t, n.final("class/a"))
			require.Empty(t, n.final("class/b"))
		})
	}
	set := func(t *testing.T, records *pendingFinalRecords, account state.UserAccountHandler, value []byte, kind string, fields ...[]byte) {
		key, err := records.key(kind, fields...)
		require.NoError(t, err)
		require.NoError(t, account.SaveKeyValue(key, value))
	}
	digestOf := func(n *sp222Node, key string) []byte {
		return blake2b.NewBlake2b().Compute(string(n.value("pending", []byte(key))))
	}
	damage("the parent is already sealed", func(n *sp222Node, s data.HeaderHandler, r *pendingFinalRecords, a state.UserAccountHandler) {
		set(t, r, a, []byte("earlier seal"), finalitySealKind, n.hash(s))
	})
	damage("a work entry is missing", func(n *sp222Node, s data.HeaderHandler, r *pendingFinalRecords, a state.UserAccountHandler) {
		set(t, r, a, nil, finalityWorkKind, n.hash(s), digestOf(n, "class/a"))
	})
	damage("a work entry names another record", func(n *sp222Node, s data.HeaderHandler, r *pendingFinalRecords, a state.UserAccountHandler) {
		set(t, r, a, []byte("class/b"), finalityWorkKind, n.hash(s), digestOf(n, "class/a"))
	})
	damage("a pending record is not a record", func(n *sp222Node, s data.HeaderHandler, r *pendingFinalRecords, a state.UserAccountHandler) {
		set(t, r, a, []byte{0xff, 0xff}, "pending", []byte("class/a"))
	})
	damage("a pending record is filed under another origin", func(n *sp222Node, s data.HeaderHandler, r *pendingFinalRecords, a state.UserAccountHandler) {
		moved, err := r.codec.frame([]byte("class/a"), binary.BigEndian.AppendUint64(nil, 0), nil, []byte("body of class/a"), bytes.Repeat([]byte{4}, 32))
		require.NoError(t, err)
		set(t, r, a, moved, "pending", []byte("class/a"))
	})
}

// A reference chain in which two metachain blocks both name the same H and S
// cannot be attributed to the selected depth and is refused.
func TestQualSP222OriginNamedByTwoReferencesIsRefused(t *testing.T) {
	n := newSP222Node(t, 0, true)
	s, h, m := sp222ShardStory(n)
	again := n.meta([]data.HeaderHandler{h}, []data.HeaderHandler{s})
	m3, m4 := n.meta(nil, nil), n.meta(nil, nil)
	_ = m
	require.ErrorIs(t, n.begin(n.next(false, again, m3, m4)), ErrFinalityImport)
	n.revert()
	require.Empty(t, n.final("class/a"))
}

func TestQualSP222HostAndCounterGuards(t *testing.T) {
	n := newSP222Node(t, 0, true)
	s := n.next(false)
	require.NoError(t, n.begin(s))
	require.ErrorIs(t, n.imp.adjustOpen(-1), ErrFinalityImport, "nothing is open")
	require.NoError(t, n.imp.put(bytes.Repeat([]byte{0xff}, 8), finalityOpenKind))
	require.ErrorIs(t, n.imp.adjustOpen(1), ErrFinalityImport, "counter overflow")
	oversized := bytes.Repeat([]byte{1}, 5000)
	_, err := n.imp.get(finalityWorkKind, oversized)
	require.Error(t, err, "a key beyond the record limit")
	require.Error(t, n.imp.put(nil, finalityWorkKind, oversized))
	n.revert()

	require.NoError(t, n.begin(s))
	host := (*finalityHost)(n.imp)
	frame := func(fields ...[]byte) []byte {
		raw, err := n.imp.records.codec.frame(fields...)
		require.NoError(t, err)
		return raw
	}
	version := binary.BigEndian.AppendUint64(nil, 0)
	foreign := frame([]byte("class/a"), version, nil, []byte("body"), bytes.Repeat([]byte{8}, 32))
	require.ErrorIs(t, host.Admit(foreign), ErrFinalityImport, "a record filed under another block")
	short := frame([]byte("class/a"), []byte{1}, nil, []byte("body"), n.hash(s))
	require.ErrorIs(t, host.Admit(short), ErrFinalityImport, "a malformed version")
	_, err = host.Observe(foreign)
	require.ErrorIs(t, err, ErrFinalityImport, "no manifest for that origin")
	n.revert()

	// The first header of a chain has no parent to seal.
	n.run(s, "class/a")
	orphan := &block.HeaderV3{ShardID: 0, Nonce: 99, Round: 199, Epoch: 3, ChainID: []byte("unit-chain")}
	require.NoError(t, n.begin(orphan))
	n.revert()
}

// The import owner's context reader holds no proof trie: it cannot be used to
// read an account witness.
func TestQualSP222ContextReaderRefusesAccountWitnessReads(t *testing.T) {
	n := newSP222Node(t, 0, true)
	_, err := n.imp.reader.accounts.readAccountItem(bytes.Repeat([]byte{1}, 32), core.SystemAccountAddress,
		[]byte("key"), AccountItemWitness{AccountProof: [][]byte{{1}}, DataProof: [][]byte{{1}}})
	require.ErrorIs(t, err, ErrInvalidAccountWitness)
}

// Q04 and the tariff input (owner ruling of 26 November): the state work of
// staging, sealing and promotion, counted on the owner's store. Staging and
// promotion writes are a fixed amount per item; promotion reads grow with the
// position of the item in its origin. Nothing else in the state adds work.
func TestQualSP222FinalizationWorkMeasurement(t *testing.T) {
	measure := func(items int, unrelated int) (stage, seal, promote map[string]int) {
		n := newSP222Node(t, 0, true)
		// Unrelated open work of an earlier block that is not yet final.
		if unrelated > 0 {
			var keys []string
			for i := 0; i < unrelated; i++ {
				keys = append(keys, "class/unrelated-"+string(rune('a'+i)))
			}
			n.run(n.next(false), keys...)
			n.uncarried = nil
		}
		s := n.next(false)
		require.NoError(t, n.begin(s))
		n.faults.totals = map[string]int{}
		for i := 0; i < items; i++ {
			require.NoError(t, n.stage("class/item-"+string(rune('a'+i)), 0, nil, "body"))
		}
		stage = n.faults.totals
		n.faults.totals = nil
		n.commit(s)
		h := n.next(true)
		n.faults.totals = map[string]int{}
		require.NoError(t, n.begin(h))
		seal = n.faults.totals
		n.faults.totals = nil
		n.commit(h)
		b := n.next(false, n.meta([]data.HeaderHandler{h}, []data.HeaderHandler{s}), n.meta(nil, nil), n.meta(nil, nil))
		n.faults.totals = map[string]int{}
		require.NoError(t, n.begin(b))
		promote = n.faults.totals
		n.faults.totals = nil
		require.NotEmpty(t, n.final("class/item-a"))
		return stage, seal, promote
	}
	stage1, seal1, promote1 := measure(1, 0)
	stage2, seal2, promote2 := measure(2, 0)
	stage3, _, promote3 := measure(3, 0)
	stage4, _, promote4 := measure(4, 0)
	_, sealBusy, promoteBusy := measure(2, 5)
	t.Logf("staging: 1 item %v, 2 items %v, 3 items %v, 4 items %v", stage1, stage2, stage3, stage4)
	t.Logf("sealing: %v", seal1)
	t.Logf("promotion: 1 item %v, 2 items %v, 3 items %v, 4 items %v", promote1, promote2, promote3, promote4)
	for _, kind := range []string{"load", "read", "write", "save"} {
		require.Equal(t, stage2[kind]-stage1[kind], stage3[kind]-stage2[kind], "staging %s per item", kind)
		require.Equal(t, stage3[kind]-stage2[kind], stage4[kind]-stage3[kind], "staging %s per item", kind)
		require.Equal(t, promote2[kind], promoteBusy[kind], "unrelated open work adds no promotion %s", kind)
	}
	// Writes and saves of promotion are a fixed amount per item.
	for _, kind := range []string{"write", "save"} {
		require.Equal(t, promote2[kind]-promote1[kind], promote3[kind]-promote2[kind], "promotion %s per item", kind)
		require.Equal(t, promote3[kind]-promote2[kind], promote4[kind]-promote3[kind], "promotion %s per item", kind)
	}
	// Reads of promotion: the k-th item costs a fixed amount more than the
	// (k-1)-th, because the heads of every item of the origin are compared
	// around each item's promotion. This is what FinalizationGas is given the
	// item's position for.
	for _, kind := range []string{"load", "read"} {
		step2, step3, step4 := promote2[kind]-promote1[kind], promote3[kind]-promote2[kind], promote4[kind]-promote3[kind]
		require.Equal(t, step3-step2, step4-step3, "promotion %s grows by a fixed amount per position", kind)
		require.Positive(t, step3-step2)
	}
	require.Equal(t, seal1, seal2, "sealing does not depend on the number of items")
	require.Equal(t, seal1, sealBusy)
	require.Equal(t, 1, seal1["write"])
	require.Equal(t, 5, promote2["write"]-promote1["write"], "writes per promoted item: pending, item, final, manifest, work entry")
	require.Equal(t, 4, stage2["write"]-stage1["write"], "writes per staged item: pending, item, manifest, work entry")
}
