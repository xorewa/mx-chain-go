package drwa

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/batch"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/stretchr/testify/require"
)

// Unit proof oracle ONLY. Native cryptographic/roster admission is a separate
// required integration boundary; these bytes do not constitute signed proofs.
type canonicalTestProofVerifier struct {
	process.InterceptedHeaderSigVerifier
	failure error
	calls   int
}

func (p *canonicalTestProofVerifier) IsInterfaceNil() bool { return p == nil }
func (p *canonicalTestProofVerifier) VerifyHeaderProof(proof data.HeaderProofHandler) error {
	p.calls++
	if p.failure != nil {
		return p.failure
	}
	if !bytes.Equal(proof.GetAggregatedSignature(), []byte("unit proof oracle")) {
		return errors.New("proof rejected")
	}
	return nil
}

// Explicit unit oracles. External integration tests replace these with the
// concrete native validators without creating a lower-layer import cycle.
type canonicalTestValidator struct {
	marshaller marshal.Marshalizer
	hash       func(string) []byte
}

func (v *canonicalTestValidator) IsInterfaceNil() bool { return v == nil }
func (v *canonicalTestValidator) IsHeaderConstructionValid(next, previous data.HeaderHandler) error {
	raw, err := v.marshaller.Marshal(previous)
	if err != nil {
		return err
	}
	if next.GetNonce() != previous.GetNonce()+1 || next.GetRound() <= previous.GetRound() || !bytes.Equal(next.GetPrevHash(), v.hash(string(raw))) || !bytes.Equal(next.GetPrevRandSeed(), previous.GetRandSeed()) {
		return errors.New("unit ancestry oracle rejected")
	}
	return nil
}

type canonicalTestIntegrity struct{}

func (v *canonicalTestIntegrity) IsInterfaceNil() bool             { return v == nil }
func (v *canonicalTestIntegrity) GetVersion(uint32, uint64) string { return "unit" }
func (v *canonicalTestIntegrity) Verify(h data.HeaderHandler) error {
	if !bytes.Equal(h.GetChainID(), []byte("unit-chain")) || len(h.GetReserved()) != 0 {
		return errors.New("unit integrity oracle rejected")
	}
	return nil
}

type canonicalTestFixture struct {
	*pendingFinalTestFixture
	reader                     *canonicalResultReader
	oracle                     *canonicalTestProofVerifier
	w                          canonicalResultWitness
	metas                      []*block.MetaBlockV3
	producer, consumer         uint32
	bHash, originKey, expected []byte
	limit                      int
}

func (f *canonicalTestFixture) encode(t *testing.T, value interface{}) []byte {
	t.Helper()
	raw, err := f.r.codec.marshaller.Marshal(value)
	require.NoError(t, err)
	return raw
}
func (f *canonicalTestFixture) hash(raw []byte) []byte { return f.r.codec.hasher.Compute(string(raw)) }
func (f *canonicalTestFixture) proof(t *testing.T, h data.HeaderHandler, raw []byte) []byte {
	return f.encode(t, &block.HeaderProof{HeaderHash: f.hash(raw), HeaderShardId: h.GetShardID(), HeaderNonce: h.GetNonce(), HeaderRound: h.GetRound(), HeaderEpoch: h.GetEpoch(), IsStartOfEpoch: h.IsStartOfEpochBlock(), AggregatedSignature: []byte("unit proof oracle")})
}
func (f *canonicalTestFixture) rechain(t *testing.T) {
	t.Helper()
	f.w.MetaHeaders = nil
	f.w.MetaProofs = nil
	for i, m := range f.metas {
		if i > 0 {
			m.PrevHash = f.hash(f.w.MetaHeaders[i-1])
			m.PrevRandSeed = bytes.Clone(f.metas[i-1].RandSeed)
			m.Nonce = f.metas[i-1].Nonce + 1
			m.Round = f.metas[i-1].Round + 1
		}
		raw := f.encode(t, m)
		f.w.MetaHeaders = append(f.w.MetaHeaders, raw)
		f.w.MetaProofs = append(f.w.MetaProofs, f.proof(t, m, raw))
	}
	tip := f.metas[len(f.metas)-1]
	tipHash := f.hash(f.w.MetaHeaders[len(f.w.MetaHeaders)-1])
	if f.consumer == core.MetachainShardId {
		f.w.Consumer = f.encode(t, &block.MetaBlockV3{Nonce: tip.Nonce + 1, Round: tip.Round + 1, Epoch: tip.Epoch, ChainID: []byte("unit-chain"), PrevHash: tipHash, PrevRandSeed: bytes.Clone(tip.RandSeed)})
	} else {
		f.w.Consumer = f.encode(t, &block.HeaderV3{ShardID: f.consumer, Nonce: 100, Round: 200, Epoch: 4, ChainID: []byte("unit-chain"), MetaBlockHashes: [][]byte{tipHash}})
	}
	f.bHash = f.hash(f.w.Consumer)
	f.rebudget()
}
func (f *canonicalTestFixture) rebudget() {
	f.limit = 0
	for _, raw := range [][]byte{f.w.Consumer, f.w.Account.Header, f.w.Account.ExecutedHeader, f.w.HeaderProof} {
		f.limit += len(raw)
	}
	for _, list := range [][][]byte{f.w.MetaHeaders, f.w.MetaProofs, f.w.Account.AccountProof, f.w.Account.DataProof} {
		for _, raw := range list {
			f.limit += len(raw)
		}
	}
	f.limit += f.budget
}
func newCanonicalTestFixture(t *testing.T, producer, consumer uint32) *canonicalTestFixture {
	t.Helper()
	mar := &marshal.GogoProtoMarshalizer{}
	var s data.HeaderHandler = &block.HeaderV3{Nonce: 11, Round: 21, Epoch: 3, ShardID: producer, ChainID: []byte("unit-chain")}
	if producer == core.MetachainShardId {
		s = &block.MetaBlockV3{Nonce: 11, Round: 21, Epoch: 3, ChainID: []byte("unit-chain")}
	}
	sRaw, err := mar.Marshal(s)
	require.NoError(t, err)
	// S is a native proposal identity available before its execution root.
	tmpArgs, _ := qualContainmentArgs(t)
	origin := tmpArgs.Hasher.Compute(string(sRaw))
	f := &canonicalTestFixture{pendingFinalTestFixture: newPendingFinalTestFixture(t, 2, origin, origin), producer: producer, consumer: consumer, oracle: &canonicalTestProofVerifier{}}
	f.w.Account.ExecutedHeader = sRaw
	root, err := f.s.RootHash()
	require.NoError(t, err)
	result := &block.BaseExecutionResult{HeaderHash: origin, HeaderNonce: 11, HeaderRound: 21, HeaderEpoch: 3, RootHash: root}
	var h data.HeaderHandler = &block.HeaderV3{Nonce: 15, Round: 25, Epoch: 4, ShardID: producer, ChainID: []byte("unit-chain"), ExecutionResults: []*block.ExecutionResult{{BaseExecutionResult: result}}}
	if producer == core.MetachainShardId {
		h = &block.MetaBlockV3{Nonce: 15, Round: 25, Epoch: 4, ChainID: []byte("unit-chain"), ExecutionResults: []*block.MetaExecutionResult{{ExecutionResult: &block.BaseMetaExecutionResult{BaseExecutionResult: result}}}}
	}
	f.w.Account.Header = f.encode(t, h)
	first := &block.MetaBlockV3{Nonce: 30, Round: 40, Epoch: 4, ChainID: []byte("unit-chain"), ShardInfoProposal: []block.ShardDataProposal{{HeaderHash: f.hash(f.w.Account.Header), ShardID: producer, Nonce: 15, Round: 25, Epoch: 4}}, ShardInfo: []block.ShardData{{HeaderHash: origin, ShardID: producer, Nonce: 11, Round: 21, Epoch: 3}}}
	if producer == core.MetachainShardId {
		first = h.(*block.MetaBlockV3)
	} else {
		f.w.HeaderProof = f.proof(t, h, f.w.Account.Header)
	}
	f.metas = []*block.MetaBlockV3{first, {Epoch: 4, ChainID: []byte("unit-chain")}, {Epoch: 4, ChainID: []byte("unit-chain")}}
	f.originKey = append([]byte(pendingFinalPrefix+"origin@"), f.encode(t, batch.New(origin))...)
	f.expected = f.encode(t, batch.New(f.commitments...))
	args, _ := qualContainmentArgs(t, f.s.backing)
	main, err := args.Trie.Recreate(holders.NewDefaultRootHashesHolder(root))
	require.NoError(t, err)
	f.w.Account.AccountProof, _, err = main.GetProof(core.SystemAccountAddress)
	require.NoError(t, err)
	a, err := f.s.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	f.w.Account.DataProof, _, err = a.(state.UserAccountHandler).DataTrie().(common.Trie).GetProof(f.originKey)
	require.NoError(t, err)
	cache := testscommon.NewMemDbMock()
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	accounts, err := NewResultAccountReader(ArgsResultAccountReader{StorageManager: &storageManager.StorageManagerStub{GetCalled: cache.Get, GetFromCurrentEpochCalled: cache.Get, PutCalled: cache.Put, GetIdentifierCalled: cache.GetIdentifier, GetStateStatsHandlerCalled: cache.GetStateStatsHandler}, Marshaller: mar, Hasher: args.Hasher, EnableEpochsHandler: flags, MaxTrieLevelInMemory: 5})
	require.NoError(t, err)
	validator := &canonicalTestValidator{marshaller: mar, hash: args.Hasher.Compute}
	integrity := &canonicalTestIntegrity{}
	exclusions, err := common.NewRoundExclusionHandler(nil)
	require.NoError(t, err)
	f.reader, err = newCanonicalResultReader(accounts, validator, f.oracle, integrity, exclusions)
	require.NoError(t, err)
	f.rechain(t)
	return f
}

// Test-only exports follow this repository's export_test.go pattern. They do
// not install production seams and permit actual native upper-layer validators
// to be exercised by external-package integration tests.
func NewCanonicalResultTestFixture(t *testing.T, producer, consumer uint32) *canonicalTestFixture {
	return newCanonicalTestFixture(t, producer, consumer)
}
func (f *canonicalTestFixture) ReaderArgs() ArgsResultAccountReader { return f.reader.accounts.args }
func (f *canonicalTestFixture) SetNativeValidators(v process.HeaderConstructionValidator, i process.HeaderIntegrityVerifier) {
	f.reader.validator = v
	f.reader.integrity = i
}
func (f *canonicalTestFixture) ImportCanonical() error         { return f.promoteCanonical() }
func (f *canonicalTestFixture) ReadCanonical() ([]byte, error) { return f.read() }

func (f *canonicalTestFixture) InstallNativeProofVerifier(t *testing.T, v process.InterceptedHeaderSigVerifier, sign func(*block.HeaderProof) error) {
	t.Helper()
	f.reader.proofs = v
	install := func(raw []byte) []byte {
		p := &block.HeaderProof{}
		require.NoError(t, f.r.codec.marshaller.Unmarshal(p, raw))
		require.NoError(t, sign(p))
		return f.encode(t, p)
	}
	if len(f.w.HeaderProof) != 0 {
		f.w.HeaderProof = install(f.w.HeaderProof)
	}
	for i := range f.w.MetaProofs {
		f.w.MetaProofs[i] = install(f.w.MetaProofs[i])
	}
	f.rebudget()
}
func (f *canonicalTestFixture) CorruptProofSignature(t *testing.T) {
	p := &block.HeaderProof{}
	require.NoError(t, f.r.codec.marshaller.Unmarshal(p, f.w.MetaProofs[0]))
	p.AggregatedSignature[0] ^= 1
	f.w.MetaProofs[0] = f.encode(t, p)
}
func (f *canonicalTestFixture) P13Snapshot(t *testing.T) [][]byte { return f.snapshot(t) }
func (f *canonicalTestFixture) ExportWitness(t *testing.T) []byte {
	raw, err := json.Marshal(f.w)
	require.NoError(t, err)
	return raw
}
func (f *canonicalTestFixture) ImportWitness(t *testing.T, raw []byte) {
	require.NoError(t, json.Unmarshal(raw, &f.w))
	f.rebudget()
}

func (f *canonicalTestFixture) read() ([]byte, error) {
	return f.reader.read(f.bHash, f.consumer, f.producer, f.items[0].candidate.origin, f.originKey, f.w, f.limit-f.budget)
}
func (f *canonicalTestFixture) promoteCanonical() error {
	return f.r.promoteCanonicalResult(f.reader, f.bHash, f.consumer, f.producer, f.items, f.w, 2, f.limit)
}

func TestCanonicalResultReader_Read(t *testing.T) {
	for _, producer := range []uint32{0, 1, core.MetachainShardId} {
		for _, consumer := range []uint32{0, 2, core.MetachainShardId} {
			t.Run(fmt.Sprintf("origin %d consumer %d should bind native result ancestry and complete items", producer, consumer), func(t *testing.T) {
				f := newCanonicalTestFixture(t, producer, consumer)
				before := f.snapshot(t)
				value, err := f.read()
				require.NoError(t, err)
				require.Equal(t, f.expected, value)
				require.Equal(t, before, f.snapshot(t))
				require.NoError(t, f.promoteCanonical())
				after := f.snapshot(t)
				for _, order := range [][]int{{2, 0, 1}, {1, 2, 0}, {1, 0, 2}, {0, 2, 1}, {2, 1, 0}} {
					headers, proofs := f.w.MetaHeaders, f.w.MetaProofs
					f.w.MetaHeaders = [][]byte{headers[order[0]], headers[order[1]], headers[order[2]]}
					f.w.MetaProofs = [][]byte{proofs[order[0]], proofs[order[1]], proofs[order[2]]}
					require.NoError(t, f.promoteCanonical())
					require.Equal(t, after, f.snapshot(t))
					require.Equal(t, 2, f.host.observed)
					f.w.MetaHeaders, f.w.MetaProofs = headers, proofs
				}
			})
		}
	}
}

func TestCanonicalResultReader_Rejection(t *testing.T) {
	for _, name := range []string{"missing ancestry", "mismatched proof list", "byte budget", "wrong B", "wrong S", "wrong H shard", "wrong H encoding", "wrong B encoding", "missing H proof", "wrong H proof", "wrong proof coordinates", "bad signature", "missing ancestor", "wrong ancestry", "duplicate header", "wrong proposal", "wrong executed projection", "duplicate proposal", "duplicate projection", "missing account proof", "corrupt data proof", "missing item", "reordered items", "too many items", "missing native owner", "empty item set", "empty budget", "malformed candidate"} {
		t.Run(name+" should leave P13 state byte identical", func(t *testing.T) {
			f := newCanonicalTestFixture(t, 1, 2)
			before := f.snapshot(t)
			max := 2
			native := f.reader
			switch name {
			case "missing ancestry":
				f.w.MetaHeaders = nil
				f.w.MetaProofs = nil
			case "mismatched proof list":
				f.w.MetaProofs = f.w.MetaProofs[:2]
			case "byte budget":
				f.limit--
			case "wrong B":
				f.bHash = []byte("other B")
			case "wrong S":
				f.w.Account.ExecutedHeader = append(f.w.Account.ExecutedHeader, 0)
			case "wrong H shard":
				h := &block.HeaderV3{}
				require.NoError(t, f.r.codec.marshaller.Unmarshal(h, f.w.Account.Header))
				h.ShardID = 0
				f.w.Account.Header = f.encode(t, h)
			case "wrong H encoding":
				f.w.Account.Header = []byte{0xff}
			case "wrong B encoding":
				f.w.Consumer = []byte{0xff}
				f.bHash = f.hash(f.w.Consumer)
			case "missing H proof":
				f.w.HeaderProof = nil
			case "wrong H proof":
				f.w.HeaderProof = []byte{0xff}
			case "wrong proof coordinates":
				p := &block.HeaderProof{}
				require.NoError(t, f.r.codec.marshaller.Unmarshal(p, f.w.MetaProofs[1]))
				p.HeaderEpoch++
				f.w.MetaProofs[1] = f.encode(t, p)
			case "bad signature":
				f.oracle.failure = errors.New("native proof verification failed")
			case "missing ancestor":
				f.w.MetaHeaders = f.w.MetaHeaders[1:]
				f.w.MetaProofs = f.w.MetaProofs[1:]
			case "wrong ancestry":
				f.metas[1].PrevRandSeed = []byte("wrong committed seed")
				f.w.MetaHeaders[1] = f.encode(t, f.metas[1])
				f.w.MetaProofs[1] = f.proof(t, f.metas[1], f.w.MetaHeaders[1])
				f.metas[2].PrevHash = f.hash(f.w.MetaHeaders[1])
				f.w.MetaHeaders[2] = f.encode(t, f.metas[2])
				f.w.MetaProofs[2] = f.proof(t, f.metas[2], f.w.MetaHeaders[2])
				b := &block.HeaderV3{}
				require.NoError(t, f.r.codec.marshaller.Unmarshal(b, f.w.Consumer))
				b.MetaBlockHashes = [][]byte{f.hash(f.w.MetaHeaders[2])}
				f.w.Consumer = f.encode(t, b)
				f.bHash = f.hash(f.w.Consumer)
			case "duplicate header":
				f.w.MetaHeaders[0] = f.w.MetaHeaders[1]
			case "wrong proposal":
				f.metas[0].ShardInfoProposal[0].HeaderHash = f.items[0].candidate.origin
				f.rechain(t)
			case "wrong executed projection":
				f.metas[0].ShardInfo[0].Nonce++
				f.rechain(t)
			case "duplicate proposal":
				f.metas[0].ShardInfoProposal = append(f.metas[0].ShardInfoProposal, f.metas[0].ShardInfoProposal[0])
				f.rechain(t)
			case "duplicate projection":
				f.metas[0].ShardInfo = append(f.metas[0].ShardInfo, f.metas[0].ShardInfo[0])
				f.rechain(t)
			case "missing account proof":
				f.w.Account.AccountProof = nil
			case "corrupt data proof":
				f.w.Account.DataProof[0] = []byte{0xff}
			case "missing item":
				f.items = f.items[:1]
			case "reordered items":
				f.items[0], f.items[1] = f.items[1], f.items[0]
			case "too many items":
				max = 1
			case "missing native owner":
				native = nil
			case "empty item set":
				f.items = nil
			case "empty budget":
				f.limit = 0
			case "malformed candidate":
				f.items[0].candidate.key = nil
			}
			if name != "byte budget" && name != "empty budget" {
				f.rebudget()
			}
			require.Error(t, f.r.promoteCanonicalResult(native, f.bHash, f.consumer, f.producer, f.items, f.w, max, f.limit))
			require.Equal(t, before, f.snapshot(t))
			require.Empty(t, f.owner.outputs)
		})
	}
}

func TestCanonicalResultReader_PositiveReconciliation(t *testing.T) {
	t.Run("one child should remain pending until native positive reconciliation is available", func(t *testing.T) {
		f := newCanonicalTestFixture(t, 1, 2)
		before := f.snapshot(t)
		last := f.metas[2]
		f.metas = f.metas[:2]
		f.rechain(t)
		require.Error(t, f.promoteCanonical())
		require.Equal(t, before, f.snapshot(t))
		require.Zero(t, f.host.observed)
		// Supplying an extra positive proof does not advance B's committed
		// anchor. Its presence in this bag cannot authorize early promotion.
		raw := f.encode(t, last)
		f.w.MetaHeaders = append(f.w.MetaHeaders, raw)
		f.w.MetaProofs = append(f.w.MetaProofs, f.proof(t, last, raw))
		f.rebudget()
		require.Error(t, f.promoteCanonical())
		require.Equal(t, before, f.snapshot(t))
		require.Zero(t, f.host.observed)
		f.metas = append(f.metas, last)
		f.rechain(t)
		require.NoError(t, f.promoteCanonical())
		require.Equal(t, 2, f.host.observed)
	})
	t.Run("unrelated local sibling evidence should not select a different promotion set", func(t *testing.T) {
		f := newCanonicalTestFixture(t, 1, 2)
		sibling := *f.metas[0]
		sibling.Round++
		raw := f.encode(t, &sibling)
		f.w.MetaHeaders = append(f.w.MetaHeaders, raw)
		f.w.MetaProofs = append(f.w.MetaProofs, f.proof(t, &sibling, raw))
		f.rebudget()
		require.NoError(t, f.promoteCanonical())
		require.Equal(t, 2, f.host.observed)
	})
}

func TestNewCanonicalResultReader(t *testing.T) {
	f := newCanonicalTestFixture(t, 1, 2)
	for i := 0; i < 5; i++ {
		t.Run(fmt.Sprintf("nil dependency %d should reject", i), func(t *testing.T) {
			a, v, p, h, e := f.reader.accounts, f.reader.validator, f.reader.proofs, f.reader.integrity, f.reader.exclusions
			switch i {
			case 0:
				a = nil
			case 1:
				v = nil
			case 2:
				p = nil
			case 3:
				h = nil
			case 4:
				e = nil
			}
			_, err := newCanonicalResultReader(a, v, p, h, e)
			require.Error(t, err)
		})
	}
}

func FuzzCanonicalResultReader_Read(f *testing.F) {
	f.Add([]byte{0xff}, uint8(0))
	f.Add([]byte{}, uint8(1))
	f.Add([]byte{0x0a, 0x01, 0xff}, uint8(2))
	f.Fuzz(func(t *testing.T, raw []byte, field uint8) {
		if len(raw) > 4096 {
			t.Skip()
		}
		x := newCanonicalTestFixture(t, 1, 2)
		before := x.snapshot(t)
		origin := x.items[0].candidate.origin
		switch field % 4 {
		case 0:
			x.w.Consumer = raw
			x.bHash = x.hash(raw)
		case 1:
			x.w.Account.Header = raw
		case 2:
			x.w.HeaderProof = raw
		case 3:
			x.w.Account.ExecutedHeader = raw
			origin = x.hash(raw)
		}
		x.rebudget()
		_, _ = x.reader.read(x.bHash, x.consumer, x.producer, origin, x.originKey, x.w, x.limit)
		require.Equal(t, before, x.snapshot(t))
	})
}

func TestCanonicalResultReader_ContextGuards(t *testing.T) {
	for _, name := range []string{"integrity", "malformed S", "missing B references", "malformed meta", "missing meta proof", "meta B ancestry", "meta H extra proof", "witness byte charge", "item evidence charge", "empty proof node"} {
		t.Run(name+" should retain P13 bytes", func(t *testing.T) {
			producer, consumer := uint32(1), uint32(2)
			if name == "meta B ancestry" {
				consumer = core.MetachainShardId
			}
			if name == "meta H extra proof" {
				producer = core.MetachainShardId
			}
			f := newCanonicalTestFixture(t, producer, consumer)
			before := f.snapshot(t)
			switch name {
			case "integrity":
				h := &block.HeaderV3{}
				require.NoError(t, f.r.codec.marshaller.Unmarshal(h, f.w.Account.Header))
				h.ChainID = []byte("other chain")
				f.w.Account.Header = f.encode(t, h)
				f.rebudget()
			case "malformed S":
				f.w.Account.ExecutedHeader = []byte{0xff}
				_, err := f.reader.read(f.bHash, consumer, producer, f.hash(f.w.Account.ExecutedHeader), f.originKey, f.w, f.limit)
				require.Error(t, err)
				require.Equal(t, before, f.snapshot(t))
				return
			case "missing B references":
				b := &block.HeaderV3{}
				require.NoError(t, f.r.codec.marshaller.Unmarshal(b, f.w.Consumer))
				b.MetaBlockHashes = nil
				f.w.Consumer = f.encode(t, b)
				f.bHash = f.hash(f.w.Consumer)
			case "malformed meta":
				f.w.MetaHeaders[2] = []byte{0xff}
				b := &block.HeaderV3{}
				require.NoError(t, f.r.codec.marshaller.Unmarshal(b, f.w.Consumer))
				b.MetaBlockHashes = [][]byte{f.hash(f.w.MetaHeaders[2])}
				f.w.Consumer = f.encode(t, b)
				f.bHash = f.hash(f.w.Consumer)
			case "missing meta proof":
				f.w.MetaProofs[2] = nil
			case "meta B ancestry":
				b := &block.MetaBlockV3{}
				require.NoError(t, f.r.codec.marshaller.Unmarshal(b, f.w.Consumer))
				b.PrevRandSeed = []byte("unrelated seed")
				f.w.Consumer = f.encode(t, b)
				f.bHash = f.hash(f.w.Consumer)
			case "meta H extra proof":
				f.w.HeaderProof = []byte("unexpected")
			case "witness byte charge":
				f.limit = f.budget + len(f.w.Consumer) - 1
			case "item evidence charge":
				f.limit = len(f.encoded[0])
			case "empty proof node":
				f.w.Account.AccountProof = append([][]byte{nil}, f.w.Account.AccountProof...)
			}
			require.Error(t, f.promoteCanonical())
			require.Equal(t, before, f.snapshot(t))
			require.Empty(t, f.owner.outputs)
		})
	}
}
