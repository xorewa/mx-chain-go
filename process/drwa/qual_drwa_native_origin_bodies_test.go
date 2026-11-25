package drwa

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/process"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Native serialization/account proofs are reused. Header admission/proof doubles
// retain the canonical fixture's original limitation; these are not native
// first-eligibility, class, tariff or integration qualifications.
type qualOriginBodiesFixture struct {
	*qualNativeCarrierFixture
	mbs, txs [][]byte
	limit    int
}

func newQualOriginBodiesFixture(t *testing.T) *qualOriginBodiesFixture {
	t.Helper()
	f := &qualOriginBodiesFixture{qualNativeCarrierFixture: newQualNativeCarrierFixture(t)}
	var headers []data.MiniBlockHeaderHandler
	for group := 0; group < 2; group++ {
		mb := &block.MiniBlock{Type: block.SmartContractResultBlock, SenderShardID: f.producer, ReceiverShardID: f.consumer}
		for item := 0; item < 2; item++ {
			scr := &smartContractResult.SmartContractResult{}
			require.NoError(t, f.r.codec.marshaller.Unmarshal(scr, f.scrRaw))
			scr.Nonce = uint64(group*2 + item + 1)
			raw := f.encode(t, scr)
			f.txs = append(f.txs, raw)
			mb.TxHashes = append(mb.TxHashes, f.hash(raw))
		}
		raw := f.encode(t, mb)
		f.mbs = append(f.mbs, raw)
		h := &block.MiniBlockHeader{Hash: f.hash(raw), Type: block.SmartContractResultBlock,
			SenderShardID: f.producer, ReceiverShardID: f.consumer, TxCount: 2}
		require.NoError(t, h.SetIndexOfFirstTxProcessed(0))
		require.NoError(t, h.SetIndexOfLastTxProcessed(1))
		require.NoError(t, h.SetConstructionState(int32(block.Final)))
		headers = append(headers, h)
	}
	require.NoError(t, f.h.ExecutionResults[0].SetMiniBlockHeadersHandlers(headers))
	first := *headers[0].(*block.MiniBlockHeader)
	first.Reserved = bytes.Clone(first.Reserved)
	require.NoError(t, first.SetConstructionState(int32(block.Proposed)))
	f.proposalReferences = []data.MiniBlockHeaderHandler{&first}
	f.seal(t)
	return f
}

func (f *qualOriginBodiesFixture) seal(t *testing.T) {
	t.Helper()
	f.reseal(t)
	f.limit = f.canonicalTestFixture.limit
	for _, raws := range [][][]byte{f.mbs, f.txs} {
		for _, raw := range raws {
			f.limit += len(raw)
		}
	}
}

func (f *qualOriginBodiesFixture) readBodies() ([]byte, *block.Body, []*smartContractResult.SmartContractResult, error) {
	return f.r.nativeOriginSCRBodies(f.reader, f.bHash, f.consumer, f.producer,
		f.items[0].candidate.origin, f.w, f.mbs, f.txs, f.limit)
}

func (f *qualOriginBodiesFixture) replaceMB(t *testing.T, index int, raw []byte) {
	t.Helper()
	f.mbs[index] = raw
	headers := f.h.ExecutionResults[0].GetMiniBlockHeadersHandlers()
	headers[index].(*block.MiniBlockHeader).Hash = f.hash(raw)
	require.NoError(t, f.h.ExecutionResults[0].SetMiniBlockHeadersHandlers(headers))
	require.Equal(t, f.hash(raw), f.h.ExecutionResults[0].GetMiniBlockHeadersHandlers()[index].GetHash())
	f.seal(t)
}

type qualOriginDecode struct {
	kind string
	hash string
}

type qualOriginDecodeObserver struct {
	marshal.Marshalizer
	t     *testing.T
	hash  func([]byte) []byte
	seen  map[qualOriginDecode]struct{}
	order []qualOriginDecode
}

func (o *qualOriginDecodeObserver) Unmarshal(target interface{}, raw []byte) error {
	o.t.Helper()
	var kind string
	switch target.(type) {
	case *block.MiniBlock:
		kind = "miniblock"
	case *smartContractResult.SmartContractResult:
		kind = "SCR"
	default:
		return o.Marshalizer.Unmarshal(target, raw)
	}
	visit := qualOriginDecode{kind: kind, hash: string(o.hash(raw))}
	require.NotContains(o.t, o.seen, visit, "a selected native identity reached the decoder twice")
	o.seen[visit] = struct{}{}
	o.order = append(o.order, visit)
	return o.Marshalizer.Unmarshal(target, raw)
}

func TestQualDRWANativeOriginBodies_Complete(t *testing.T) {
	t.Run("source order is independent of supplied order and current B subset", func(t *testing.T) {
		f := newQualOriginBodiesFixture(t)
		root, err := f.s.RootHash()
		require.NoError(t, err)
		// The fixture's two complete native fragments define the expected
		// decode order before either supplied payload list is rearranged.
		wantDecodes := []qualOriginDecode{
			{kind: "miniblock", hash: string(f.hash(f.mbs[0]))},
			{kind: "SCR", hash: string(f.hash(f.txs[0]))},
			{kind: "SCR", hash: string(f.hash(f.txs[1]))},
			{kind: "miniblock", hash: string(f.hash(f.mbs[1]))},
			{kind: "SCR", hash: string(f.hash(f.txs[2]))},
			{kind: "SCR", hash: string(f.hash(f.txs[3]))},
		}
		f.mbs[0], f.mbs[1] = f.mbs[1], f.mbs[0]
		f.txs[0], f.txs[3] = f.txs[3], f.txs[0]
		original := f.reader.accounts.args.Marshaller
		decodes := &qualOriginDecodeObserver{
			Marshalizer: original, t: t, hash: f.hash, seen: make(map[qualOriginDecode]struct{}),
		}
		f.reader.accounts.args.Marshaller = decodes
		value, body, scrs, err := f.readBodies()
		f.reader.accounts.args.Marshaller = original
		require.NoError(t, err)
		require.Equal(t, wantDecodes, decodes.order)
		require.Equal(t, f.expected, value)
		require.Len(t, body.MiniBlocks, 2)
		require.Len(t, scrs, 4)
		for i, scr := range scrs {
			require.Equal(t, uint64(i+1), scr.Nonce)
		}
		after, err := f.s.RootHash()
		require.NoError(t, err)
		require.Equal(t, root, after)
		// Mutating a returned decoded body cannot change retained source inputs.
		body.MiniBlocks[0].TxHashes[0][0] ^= 1
		scrs[0].Nonce = 99
		_, again, txs, err := f.readBodies()
		require.NoError(t, err)
		require.Equal(t, uint64(1), txs[0].Nonce)
		require.Equal(t, f.hash(f.encode(t, txs[0])), again.MiniBlocks[0].TxHashes[0])
	})
	t.Run("same B missing later fragment then restored never publishes a prefix", func(t *testing.T) {
		f := newQualOriginBodiesFixture(t)
		b := bytes.Clone(f.bHash)
		all := f.mbs
		f.mbs = f.mbs[:1]
		value, body, scrs, err := f.readBodies()
		require.ErrorIs(t, err, process.ErrMissingMiniBlock)
		require.Nil(t, value)
		require.Nil(t, body)
		require.Nil(t, scrs)
		f.mbs = all
		value, body, scrs, err = f.readBodies()
		require.NoError(t, err)
		require.Equal(t, b, f.bHash)
		require.Equal(t, f.expected, value)
		require.Len(t, body.MiniBlocks, 2)
		require.Len(t, scrs, 4)
	})
	t.Run("same B missing later transaction then restored", func(t *testing.T) {
		f := newQualOriginBodiesFixture(t)
		b := bytes.Clone(f.bHash)
		all := f.txs
		f.txs = f.txs[:3]
		value, body, scrs, err := f.readBodies()
		require.ErrorIs(t, err, process.ErrMissingTransaction)
		require.Nil(t, value)
		require.Nil(t, body)
		require.Nil(t, scrs)
		f.txs = all
		_, body, scrs, err = f.readBodies()
		require.NoError(t, err)
		require.Equal(t, b, f.bHash)
		require.Len(t, body.MiniBlocks, 2)
		require.Len(t, scrs, 4)
	})
	t.Run("empty B references do not remove source bodies", func(t *testing.T) {
		f := newQualOriginBodiesFixture(t)
		f.proposalReferences = nil
		f.seal(t)
		value, body, scrs, err := f.readBodies()
		require.NoError(t, err)
		require.Equal(t, f.expected, value)
		require.Len(t, body.MiniBlocks, 2)
		require.Len(t, scrs, 4)
	})
	t.Run("partial metadata does not select a transaction prefix", func(t *testing.T) {
		f := newQualOriginBodiesFixture(t)
		h := f.proposalReferences[0].(*block.MiniBlockHeader)
		require.NoError(t, h.SetConstructionState(int32(block.PartialExecuted)))
		require.NoError(t, h.SetIndexOfLastTxProcessed(0))
		f.seal(t)
		_, body, scrs, err := f.readBodies()
		require.NoError(t, err)
		require.Len(t, body.MiniBlocks, 2)
		require.Len(t, scrs, 4)
	})
	t.Run("empty references retain nonempty origin value without no-work", func(t *testing.T) {
		f := newQualOriginBodiesFixture(t)
		require.NoError(t, f.h.ExecutionResults[0].SetMiniBlockHeadersHandlers(nil))
		f.proposalReferences = nil
		f.mbs = nil
		f.txs = nil
		f.seal(t)
		value, body, scrs, err := f.readBodies()
		require.NoError(t, err)
		require.NotEmpty(t, value)
		require.Equal(t, f.expected, value)
		require.Empty(t, body.MiniBlocks)
		require.Empty(t, scrs)
	})
	t.Run("zero transaction fragment is still a retained native fragment", func(t *testing.T) {
		f := newQualOriginBodiesFixture(t)
		mb := &block.MiniBlock{Type: block.SmartContractResultBlock, SenderShardID: f.producer, ReceiverShardID: f.consumer}
		raw := f.encode(t, mb)
		h := &block.MiniBlockHeader{Hash: f.hash(raw), Type: block.SmartContractResultBlock, SenderShardID: f.producer, ReceiverShardID: f.consumer}
		require.NoError(t, f.h.ExecutionResults[0].SetMiniBlockHeadersHandlers([]data.MiniBlockHeaderHandler{h}))
		f.proposalReferences = nil
		f.mbs = [][]byte{raw}
		f.txs = nil
		f.seal(t)
		value, body, scrs, err := f.readBodies()
		require.NoError(t, err)
		require.Equal(t, f.expected, value)
		require.Len(t, body.MiniBlocks, 1)
		require.Empty(t, scrs)
	})
	t.Run("unavailable proof restored under unchanged B", func(t *testing.T) {
		f := newQualOriginBodiesFixture(t)
		b := bytes.Clone(f.bHash)
		proof := f.w.HeaderProof
		f.w.HeaderProof = nil
		value, body, scrs, err := f.readBodies()
		require.Error(t, err)
		require.Nil(t, value)
		require.Nil(t, body)
		require.Nil(t, scrs)
		f.w.HeaderProof = proof
		value, body, scrs, err = f.readBodies()
		require.NoError(t, err)
		require.Equal(t, b, f.bHash)
		require.Equal(t, f.expected, value)
		require.Len(t, body.MiniBlocks, 2)
		require.Len(t, scrs, 4)
	})
}

func TestQualDRWANativeOriginBodies_Refusal(t *testing.T) {
	cases := []struct {
		name   string
		change func(*testing.T, *qualOriginBodiesFixture)
	}{
		{"duplicate input fragment", func(t *testing.T, f *qualOriginBodiesFixture) { f.mbs = append(f.mbs, f.mbs[0]); f.seal(t) }},
		{"duplicate input SCR", func(t *testing.T, f *qualOriginBodiesFixture) { f.txs = append(f.txs, f.txs[0]); f.seal(t) }},
		{"extraneous SCR", func(t *testing.T, f *qualOriginBodiesFixture) {
			tx := &smartContractResult.SmartContractResult{Nonce: 99}
			f.txs = append(f.txs, f.encode(t, tx))
			f.seal(t)
		}},
		{"extraneous fragment", func(t *testing.T, f *qualOriginBodiesFixture) {
			mb := &block.MiniBlock{Type: block.SmartContractResultBlock, SenderShardID: 9}
			f.mbs = append(f.mbs, f.encode(t, mb))
			f.seal(t)
		}},
		{"duplicate source fragment", func(t *testing.T, f *qualOriginBodiesFixture) {
			hs := f.h.ExecutionResults[0].GetMiniBlockHeadersHandlers()
			hs = append(hs, hs[0])
			require.NoError(t, f.h.ExecutionResults[0].SetMiniBlockHeadersHandlers(hs))
			f.seal(t)
		}},
		{"wrong count", func(t *testing.T, f *qualOriginBodiesFixture) {
			headers := f.h.ExecutionResults[0].GetMiniBlockHeadersHandlers()
			headers[1].(*block.MiniBlockHeader).TxCount = 3
			require.NoError(t, f.h.ExecutionResults[0].SetMiniBlockHeadersHandlers(headers))
			require.Equal(t, uint32(3), f.h.ExecutionResults[0].GetMiniBlockHeadersHandlers()[1].GetTxCount())
			f.seal(t)
		}},
		{"wrong routing", func(t *testing.T, f *qualOriginBodiesFixture) {
			mb := &block.MiniBlock{}
			require.NoError(t, f.r.codec.marshaller.Unmarshal(mb, f.mbs[1]))
			mb.SenderShardID = 9
			f.replaceMB(t, 1, f.encode(t, mb))
		}},
		{"wrong type", func(t *testing.T, f *qualOriginBodiesFixture) {
			mb := &block.MiniBlock{}
			require.NoError(t, f.r.codec.marshaller.Unmarshal(mb, f.mbs[1]))
			mb.Type = block.TxBlock
			f.replaceMB(t, 1, f.encode(t, mb))
		}},
		{"malformed committed fragment", func(t *testing.T, f *qualOriginBodiesFixture) { f.replaceMB(t, 1, []byte{255}) }},
		{"malformed committed SCR", func(t *testing.T, f *qualOriginBodiesFixture) {
			f.txs[3] = []byte{255}
			mb := &block.MiniBlock{}
			require.NoError(t, f.r.codec.marshaller.Unmarshal(mb, f.mbs[1]))
			mb.TxHashes[1] = f.hash(f.txs[3])
			f.replaceMB(t, 1, f.encode(t, mb))
		}},
		{"transaction repeated across fragments", func(t *testing.T, f *qualOriginBodiesFixture) {
			mb := &block.MiniBlock{}
			require.NoError(t, f.r.codec.marshaller.Unmarshal(mb, f.mbs[1]))
			mb.TxHashes[0] = f.hash(f.txs[0])
			f.replaceMB(t, 1, f.encode(t, mb))
		}},
		{"budget includes payload and proof together", func(t *testing.T, f *qualOriginBodiesFixture) {
			f.limit = 0
			for _, raw := range f.mbs {
				f.limit += len(raw)
			}
			for _, raw := range f.txs {
				f.limit += len(raw)
			}
		}},
		{"empty supplied bytes", func(t *testing.T, f *qualOriginBodiesFixture) { f.mbs[1] = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newQualOriginBodiesFixture(t)
			tc.change(t, f)
			root, err := f.s.RootHash()
			require.NoError(t, err)
			var wantDecodes []qualOriginDecode
			switch tc.name {
			case "transaction repeated across fragments", "duplicate source fragment":
				// Both fixtures first visit the two members of the first fragment,
				// then the second fragment. A repeated member stops here.
				wantDecodes = []qualOriginDecode{
					{kind: "miniblock", hash: string(f.hash(f.mbs[0]))},
					{kind: "SCR", hash: string(f.hash(f.txs[0]))},
					{kind: "SCR", hash: string(f.hash(f.txs[1]))},
					{kind: "miniblock", hash: string(f.hash(f.mbs[1]))},
				}
			}
			if tc.name == "duplicate source fragment" {
				// Both fragments finish before the repeated reference.
				wantDecodes = append(wantDecodes,
					qualOriginDecode{kind: "SCR", hash: string(f.hash(f.txs[2]))},
					qualOriginDecode{kind: "SCR", hash: string(f.hash(f.txs[3]))},
				)
			}
			original := f.reader.accounts.args.Marshaller
			var decodes *qualOriginDecodeObserver
			if len(wantDecodes) != 0 {
				decodes = &qualOriginDecodeObserver{
					Marshalizer: original, t: t, hash: f.hash, seen: make(map[qualOriginDecode]struct{}),
				}
				f.reader.accounts.args.Marshaller = decodes
			}
			value, body, scrs, err := f.readBodies()
			f.reader.accounts.args.Marshaller = original
			require.ErrorIs(t, err, ErrInvalidAccountWitness)
			require.Nil(t, value)
			require.Nil(t, body)
			require.Nil(t, scrs)
			if decodes != nil {
				require.Equal(t, wantDecodes, decodes.order)
			}
			after, err := f.s.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
		})
	}
}

// A refusing host cannot confer native permission. It confirms that the read-only
// group does not call class hooks, and the original application seam still does.
type qualOriginBodiesRefusingHost struct{ calls int }

func (h *qualOriginBodiesRefusingHost) Admit([]byte) error { h.calls++; return errPendingFinal }
func (h *qualOriginBodiesRefusingHost) Initialize([]byte) (*vmcommon.VMOutput, error) {
	h.calls++
	return nil, errPendingFinal
}
func (h *qualOriginBodiesRefusingHost) Canonical([]byte, []byte) error {
	h.calls++
	return errPendingFinal
}
func (h *qualOriginBodiesRefusingHost) Observe([]byte) (*vmcommon.VMOutput, error) {
	h.calls++
	return nil, errPendingFinal
}
func (h *qualOriginBodiesRefusingHost) IsInterfaceNil() bool { return h == nil }

func TestQualDRWANativeOriginBodies_ExistingClassGate(t *testing.T) {
	f := newQualOriginBodiesFixture(t)
	host := &qualOriginBodiesRefusingHost{}
	f.r.host = host
	root, err := f.s.RootHash()
	require.NoError(t, err)
	_, body, scrs, err := f.readBodies()
	require.NoError(t, err)
	require.Len(t, body.MiniBlocks, 2)
	require.Len(t, scrs, 4)
	require.Zero(t, host.calls)
	require.Error(t, f.promoteCanonical())
	require.Equal(t, 1, host.calls)
	after, err := f.s.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
}
