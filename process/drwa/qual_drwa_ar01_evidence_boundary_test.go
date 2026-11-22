package drwa

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/dataRetriever/dataPool/headersCache"
	proofscache "github.com/multiversx/mx-chain-go/dataRetriever/dataPool/proofsCache"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/track"
	"github.com/stretchr/testify/require"
)

// Non-normative feasibility experiment, not a G3 consumer or promotion oracle.
// Architecture 6.1 AR-01/Q01/Q05/Q07 requires committed-input finality in
// addition to authenticated result membership. The native subjective view and
// account reader intentionally have different input contracts. These tests
// retain their actual answers; they do not turn their conjunction into an
// admission rule. In particular the inserted HeaderProofs are unsigned fixture
// objects, not cryptographic admission evidence. No B executes, no final head
// changes, and no durable replay, canonical recovery or pruning is claimed.
// All coordinates/capacities/layouts are experimental (R7 register T43 rows).
type qualAR01Evidence struct {
	f         *qualReaderFixture
	m, child  *block.MetaBlockV3
	b         *block.HeaderV3
	mHash     []byte
	childHash []byte
}

func qualAR01NativeEvidence(t *testing.T, auto bool, shard uint32) *qualAR01Evidence {
	t.Helper()
	f := qualNativeReaderFixture(t, auto, shard)
	s, h := &block.HeaderV3{}, &block.HeaderV3{}
	require.NoError(t, f.args.Marshaller.Unmarshal(s, f.w.ExecutedHeader))
	require.NoError(t, f.args.Marshaller.Unmarshal(h, f.w.Header))
	require.NotEqual(t, f.w.ExecutedHeader, f.w.Header)
	x := &qualAR01Evidence{f: f}
	x.m = &block.MetaBlockV3{Nonce: h.Nonce + 1, Round: h.Round + 1, Epoch: h.Epoch,
		ShardInfoProposal: []block.ShardDataProposal{{HeaderHash: bytes.Clone(f.anchor),
			ShardID: shard, Nonce: h.Nonce, Round: h.Round, Epoch: h.Epoch}},
		ShardInfo: []block.ShardData{{HeaderHash: f.args.Hasher.Compute(string(f.w.ExecutedHeader)),
			ShardID: shard, Nonce: s.Nonce, Round: s.Round, Epoch: s.Epoch}}}
	x.mHash = qualAR01Hash(t, f, x.m)
	x.child = &block.MetaBlockV3{Nonce: x.m.Nonce + 1, Round: x.m.Round + 1,
		Epoch: x.m.Epoch, PrevHash: bytes.Clone(x.mHash)}
	x.childHash = qualAR01Hash(t, f, x.child)
	x.b = &block.HeaderV3{Nonce: h.Nonce + 1, Round: h.Round + 1, Epoch: h.Epoch,
		ShardID: shard, MetaBlockHashes: [][]byte{bytes.Clone(x.mHash)}}
	return x
}

func qualAR01Hash(t *testing.T, f *qualReaderFixture, object interface{}) []byte {
	t.Helper()
	raw, err := f.args.Marshaller.Marshal(object)
	require.NoError(t, err)
	return f.args.Hasher.Compute(string(raw))
}

func qualAR01View(t *testing.T) (dataRetriever.HeadersPool, dataRetriever.ProofsPool, process.MetaFinalityView) {
	t.Helper()
	headers, err := headersCache.NewHeadersPool(config.HeadersPoolConfig{
		MaxHeadersPerShard: 1000, NumElementsToRemoveOnEviction: 100})
	require.NoError(t, err)
	proofs := proofscache.NewProofsPool(3, 100)
	view, err := track.NewMetaFinalityView(track.ArgsMetaFinalityView{HeadersPool: headers, ProofsPool: proofs})
	require.NoError(t, err)
	return headers, proofs, view
}

func qualAR01Proof(h *block.MetaBlockV3, hash []byte) *block.HeaderProof {
	return &block.HeaderProof{HeaderHash: bytes.Clone(hash), HeaderNonce: h.Nonce,
		HeaderRound: h.Round, HeaderShardId: core.MetachainShardId}
}

func TestQualDRWAAR01LocalEvidenceBoundary(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for shard := uint32(0); shard < 3; shard++ {
			t.Run(fmt.Sprintf("auto_%t/shard_%d", auto, shard), func(t *testing.T) {
				x := qualAR01NativeEvidence(t, auto, shard)
				f := x.f
				reader, err := NewResultAccountReader(qualReaderArgs(auto))
				require.NoError(t, err)
				headers, proofs, view := qualAR01View(t)
				// Snapshot S/H bytes and M/B hashes, not just coordinates. Pool arrival,
				// eviction and reconstruction below never change these inputs.
				beforeS, beforeH := bytes.Clone(f.w.ExecutedHeader), bytes.Clone(f.w.Header)
				beforeM, beforeB := qualAR01Hash(t, f, x.m), qualAR01Hash(t, f, x.b)
				check := func(settlement bool) {
					v, readErr := reader.Read(f.anchor, shard, f.address, f.key, f.w, f.budget)
					require.NoError(t, readErr)
					require.Equal(t, f.expected, v)
					require.True(t, view.IsShardHeaderIncluded(x.m, shard, f.anchor, 15))
					require.Equal(t, settlement, view.IsMetaHeaderSettlementReady(x.m, x.mHash))
					require.Equal(t, beforeS, f.w.ExecutedHeader)
					require.Equal(t, beforeH, f.w.Header)
					require.Equal(t, beforeM, qualAR01Hash(t, f, x.m))
					require.Equal(t, beforeB, qualAR01Hash(t, f, x.b))
					require.Zero(t, f.adb.JournalLen())
				}
				check(false)
				require.True(t, proofs.AddProof(qualAR01Proof(x.m, x.mHash)))
				check(false)
				headers.AddHeader(x.childHash, x.child)
				check(false)
				require.True(t, proofs.AddProof(qualAR01Proof(x.child, x.childHash)))
				check(true)
				headers.RemoveHeaderByHash(x.childHash)
				check(false)
				headers.AddHeader(x.childHash, x.child)
				check(true)
				// A fresh local view has no authority merely because another
				// view previously answered true. Replay in the opposite order.
				headers, proofs, view = qualAR01View(t)
				check(false)
				require.True(t, proofs.AddProof(qualAR01Proof(x.child, x.childHash)))
				headers.AddHeader(x.childHash, x.child)
				check(false)
				require.True(t, proofs.AddProof(qualAR01Proof(x.m, x.mHash)))
				check(true)
				require.False(t, proofs.AddProof(qualAR01Proof(x.m, x.mHash)))
				check(true)
			})
		}
	}
}

func TestQualDRWAAR01ProjectionBoundary(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, name := range []string{"missing_executed_projection", "H_substituted_for_S", "missing_B_reference", "wrong_B_reference"} {
			t.Run(fmt.Sprintf("auto_%t/%s", auto, name), func(t *testing.T) {
				x := qualAR01NativeEvidence(t, auto, 1)
				f := x.f
				switch name {
				case "missing_executed_projection":
					x.m.ShardInfo = nil
					require.Empty(t, x.m.ShardInfo)
				case "H_substituted_for_S":
					x.m.ShardInfo[0].HeaderHash = bytes.Clone(f.anchor)
					require.NotEqual(t, f.args.Hasher.Compute(string(f.w.ExecutedHeader)), x.m.ShardInfo[0].HeaderHash)
				case "missing_B_reference":
					x.b.MetaBlockHashes = nil
					require.Empty(t, x.b.MetaBlockHashes)
				case "wrong_B_reference":
					x.b.MetaBlockHashes = [][]byte{bytes.Clone(f.anchor)}
					require.NotEqual(t, x.mHash, x.b.MetaBlockHashes[0])
				}
				// Rebind the fixture M and child after the deliberate projection
				// change. A stale M hash must not explain the observation.
				x.mHash = qualAR01Hash(t, f, x.m)
				x.child.PrevHash = bytes.Clone(x.mHash)
				x.childHash = qualAR01Hash(t, f, x.child)
				if name == "missing_executed_projection" || name == "H_substituted_for_S" {
					x.b.MetaBlockHashes = [][]byte{bytes.Clone(x.mHash)}
				}
				headers, proofs, view := qualAR01View(t)
				headers.AddHeader(x.childHash, x.child)
				require.True(t, proofs.AddProof(qualAR01Proof(x.m, x.mHash)))
				require.True(t, proofs.AddProof(qualAR01Proof(x.child, x.childHash)))
				reader, err := NewResultAccountReader(qualReaderArgs(auto))
				require.NoError(t, err)
				v, err := reader.Read(f.anchor, 1, f.address, f.key, f.w, f.budget)
				require.NoError(t, err)
				require.Equal(t, f.expected, v)
				require.True(t, view.IsShardHeaderIncluded(x.m, 1, f.anchor, 15))
				require.True(t, view.IsMetaHeaderSettlementReady(x.m, x.mHash))
				// These true answers are deliberately NOT an assertion that
				// the malformed AR-01 witness may promote or B may consume it.
				require.Zero(t, f.adb.JournalLen())
			})
		}
	}
}
