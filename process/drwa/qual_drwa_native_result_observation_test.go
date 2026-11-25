package drwa

import (
	"bytes"
	"math/big"
	"slices"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/stretchr/testify/require"
)

// AM-012/G15: protobuf decoding and carrier inclusion do not establish a valid
// native result, execution success, settlement, gas refund or source completion.
// The reused fixture has real account proofs and limited header/proof doubles;
// it does not supply native B admission or production finality authority.
func TestQualDRWANativeResultObservation_Integrity(t *testing.T) {
	cases := []struct {
		name        string
		change      func(*smartContractResult.SmartContractResult)
		nativeError error
	}{
		{"missing-receiver", func(s *smartContractResult.SmartContractResult) { s.RcvAddr = nil }, data.ErrNilRcvAddr},
		{"missing-sender", func(s *smartContractResult.SmartContractResult) { s.SndAddr = nil }, data.ErrNilSndAddr},
		{"negative-value", func(s *smartContractResult.SmartContractResult) { s.Value = big.NewInt(-1) }, data.ErrNegativeValue},
		{"missing-previous-transaction", func(s *smartContractResult.SmartContractResult) { s.PrevTxHash = nil }, data.ErrNilTxHash},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newQualNativeCarrierFixture(t)
			native := &smartContractResult.SmartContractResult{}
			require.NoError(t, f.r.codec.marshaller.Unmarshal(native, f.scrRaw))
			native.Data = []byte("@6f6b")
			c.change(native)
			f.scrRaw = f.encode(t, native)
			decoded := &smartContractResult.SmartContractResult{}
			require.NoError(t, f.r.codec.marshaller.Unmarshal(decoded, f.scrRaw), "the wire representation is decodable")
			require.ErrorIs(t, decoded.CheckIntegrity(), c.nativeError, "same rule as InterceptedUnsignedTransaction.CheckValidity")
			f.miniBlock.TxHashes = [][]byte{f.hash(f.scrRaw)}
			f.commitCarrier(t)

			value, result, err := f.readCarrier(f.carrierLimit())
			require.ErrorIs(t, err, ErrInvalidAccountWitness)
			require.Nil(t, value)
			require.Nil(t, result, "do not publish a decoded but invalid native result")
		})
	}
}

func TestQualDRWANativeResultObservation_MissingCorrupt(t *testing.T) {
	for _, name := range []string{"missing", "unreadable", "source-hash-mismatch"} {
		t.Run(name, func(t *testing.T) {
			f := newQualNativeCarrierFixture(t)
			switch name {
			case "missing":
				f.scrRaw = nil
			case "unreadable":
				f.scrRaw = []byte{0x0a, 0x80}
				f.miniBlock.TxHashes = [][]byte{f.hash(f.scrRaw)}
				f.commitCarrier(t)
			case "source-hash-mismatch":
				f.scrRaw = append(bytes.Clone(f.scrRaw), 0)
			}
			value, result, err := f.readCarrier(f.carrierLimit())
			require.ErrorIs(t, err, ErrInvalidAccountWitness)
			require.Nil(t, value)
			require.Nil(t, result)
		})
	}
}

func TestQualDRWANativeResultObservation_UnavailableRestored(t *testing.T) {
	f := newQualNativeCarrierFixture(t)
	proof := bytes.Clone(f.w.HeaderProof)
	f.w.HeaderProof = nil
	value, result, err := f.readCarrier(f.carrierLimit())
	require.Error(t, err)
	require.Nil(t, value)
	require.Nil(t, result, "unavailable evidence is not an authenticated empty outcome")

	f.w.HeaderProof = proof
	value, result, err = f.readCarrier(f.carrierLimit())
	require.NoError(t, err)
	require.NotEmpty(t, value)
	require.NoError(t, result.CheckIntegrity())
	require.Equal(t, f.scrRaw, f.encode(t, result), "restoration preserves the native carrier bytes")
}

func TestQualDRWANativeResultObservation_WholeOriginInvalidTail(t *testing.T) {
	f := newQualOriginBodiesFixture(t)
	scr := &smartContractResult.SmartContractResult{}
	require.NoError(t, f.r.codec.marshaller.Unmarshal(scr, f.txs[3]))
	scr.Value = big.NewInt(-1)
	f.txs[3] = f.encode(t, scr)
	require.ErrorIs(t, scr.CheckIntegrity(), data.ErrNegativeValue)
	mb := &block.MiniBlock{}
	require.NoError(t, f.r.codec.marshaller.Unmarshal(mb, f.mbs[1]))
	mb.TxHashes[1] = f.hash(f.txs[3])
	f.replaceMB(t, 1, f.encode(t, mb))

	value, body, results, err := f.readBodies()
	require.ErrorIs(t, err, ErrInvalidAccountWitness)
	require.Nil(t, value)
	require.Nil(t, body)
	require.Nil(t, results, "a valid earlier fragment is not a complete valid origin")
}

func TestQualDRWANativeResultObservation_MissingNativeReader(t *testing.T) {
	for _, name := range []string{"pointwise", "references", "bodies"} {
		t.Run(name, func(t *testing.T) {
			f := newQualNativeCarrierFixture(t)
			var err error
			var value []byte
			var result *smartContractResult.SmartContractResult
			var references []data.MiniBlockHeaderHandler
			var body *block.Body
			var results []*smartContractResult.SmartContractResult
			require.NotPanics(t, func() {
				switch name {
				case "pointwise":
					value, result, err = f.r.readNativeSCR(nil, f.bHash, f.consumer, f.producer,
						f.items[0].candidate.origin, f.w, f.miniBlockRaw, f.scrRaw, f.carrierLimit())
				case "references":
					value, references, err = f.r.nativeOriginSCRReferences(nil, f.bHash, f.consumer, f.producer,
						f.items[0].candidate.origin, f.w, f.carrierLimit())
				case "bodies":
					value, body, results, err = f.r.nativeOriginSCRBodies(nil, f.bHash, f.consumer, f.producer,
						f.items[0].candidate.origin, f.w, [][]byte{f.miniBlockRaw}, [][]byte{f.scrRaw}, f.carrierLimit())
				}
			}, "an unavailable native reader must not become an observation or crash")
			require.ErrorIs(t, err, ErrInvalidAccountWitness)
			require.Nil(t, value)
			require.Nil(t, result)
			require.Nil(t, references)
			require.Nil(t, body)
			require.Nil(t, results)
		})
	}
}

func qualReadNativeCarrierObservation(f *qualNativeCarrierFixture) (*nativeSCRCarrierObservation, error) {
	return f.r.readNativeSCRObservation(f.reader, f.bHash, f.consumer, f.producer,
		f.items[0].candidate.origin, f.w, f.miniBlockRaw, f.scrRaw, f.carrierLimit())
}

// Use the existing unit sibling fixture pattern without changing B's anchor.
func qualAppendUnrelatedMetaSibling(t *testing.T, f *canonicalTestFixture) int {
	t.Helper()
	tip := len(f.metas) - 1
	sibling := *f.metas[tip]
	sibling.Round++
	require.NoError(t, f.reader.validator.IsHeaderConstructionValid(&sibling, f.metas[tip-1]))
	raw := f.encode(t, &sibling)
	require.NotEqual(t, f.hash(f.encode(t, f.metas[tip])), f.hash(raw))
	proof := f.proof(t, &sibling, raw)
	f.w.MetaHeaders = append(f.w.MetaHeaders, raw)
	f.w.MetaProofs = append(f.w.MetaProofs, proof)
	f.rebudget()
	return len(raw) + len(proof)
}

func TestQualDRWANativeResultObservation_Provenance(t *testing.T) {
	f := newQualNativeCarrierFixture(t)
	native := &smartContractResult.SmartContractResult{}
	require.NoError(t, f.r.codec.marshaller.Unmarshal(native, f.scrRaw))
	native.Data = []byte("@6f6b")
	f.scrRaw = f.encode(t, native)
	f.miniBlock.TxHashes = [][]byte{f.hash(f.scrRaw)}
	f.commitCarrier(t)

	// The projection starts after a normal earlier block. Providing the
	// earlier proof as window context must not extend the visited path.
	predecessor := &block.MetaBlockV3{Nonce: f.metas[0].Nonce - 1, Round: f.metas[0].Round - 1,
		Epoch: f.metas[0].Epoch, ChainID: bytes.Clone(f.metas[0].ChainID), RandSeed: []byte("earlier meta seed")}
	predecessorBytes := f.encode(t, predecessor)
	f.metas[0].PrevHash = f.hash(predecessorBytes)
	f.metas[0].PrevRandSeed = bytes.Clone(predecessor.RandSeed)
	f.reseal(t)
	wantPath := make([][]byte, len(f.w.MetaHeaders))
	for i, header := range f.w.MetaHeaders {
		wantPath[len(wantPath)-1-i] = f.hash(header)
	}
	f.w.MetaHeaders = append(f.w.MetaHeaders, predecessorBytes)
	f.w.MetaProofs = append(f.w.MetaProofs, f.proof(t, predecessor, predecessorBytes))
	consumer := &block.HeaderV3{}
	require.NoError(t, f.r.codec.marshaller.Unmarshal(consumer, f.w.Consumer))
	consumer.Epoch = f.h.Epoch + 1
	f.w.Consumer = f.encode(t, consumer)
	f.bHash = f.hash(f.w.Consumer)
	f.rebudget()

	observed, err := qualReadNativeCarrierObservation(f)
	require.NoError(t, err)
	require.NotNil(t, observed.result)
	require.Equal(t, f.expected, observed.originCommitment)
	require.Equal(t, f.hash(f.scrRaw), observed.resultHash, "subject is the actual committed carrier, not its reported original/previous transaction")
	require.NotEqual(t, observed.result.OriginalTxHash, observed.resultHash)
	require.Equal(t, f.hash(f.miniBlockRaw), observed.miniBlockHash)
	require.Equal(t, f.items[0].candidate.origin, observed.originHash)
	require.Equal(t, f.hash(f.w.Account.Header), observed.carryingHeaderHash)
	require.Equal(t, f.bHash, observed.consumerHeaderHash)
	require.Equal(t, f.producer, observed.producer)
	require.Equal(t, f.consumer, observed.consumer)
	require.Equal(t, wantPath, observed.metaHeaderHashes)
	slices.Reverse(f.w.MetaHeaders)
	slices.Reverse(f.w.MetaProofs)
	reordered, err := qualReadNativeCarrierObservation(f)
	require.NoError(t, err)
	require.Equal(t, observed, reordered, "witness transport order cannot change ancestry provenance")
	require.Equal(t, consumer.GetNonce(), observed.asOfNonce)
	require.Equal(t, consumer.GetRound(), observed.asOfRound)
	require.Equal(t, consumer.GetEpoch(), observed.asOfEpoch)
	require.Equal(t, []byte("@6f6b"), observed.result.Data, "native marker remains carrier data, not a DRWA outcome")

	qualAppendUnrelatedMetaSibling(t, f.canonicalTestFixture)
	withSibling, err := qualReadNativeCarrierObservation(f)
	require.NoError(t, err)
	require.Equal(t, observed, withSibling)

	slices.Reverse(f.w.MetaHeaders)
	slices.Reverse(f.w.MetaProofs)
	withSiblingReordered, err := qualReadNativeCarrierObservation(f)
	require.NoError(t, err)
	require.Equal(t, observed, withSiblingReordered)
}

// Returned coordinates own their bytes: later cache reuse must not relabel an
// observation with another subject, source, result or as-of block.
func TestQualDRWANativeResultObservation_ReceiptOwnership(t *testing.T) {
	f := newQualNativeCarrierFixture(t)
	origin := bytes.Clone(f.items[0].candidate.origin)
	header := f.hash(f.w.Account.Header)
	consumer := bytes.Clone(f.bHash)
	miniBlock := f.hash(f.miniBlockRaw)
	result := f.hash(f.scrRaw)
	commitment := bytes.Clone(f.expected)
	native := &smartContractResult.SmartContractResult{}
	require.NoError(t, f.r.codec.marshaller.Unmarshal(native, f.scrRaw))
	metas := make([][]byte, len(f.w.MetaHeaders))
	for i, raw := range f.w.MetaHeaders {
		metas[len(metas)-1-i] = f.hash(raw)
	}
	called := false
	f.reader.proofs = &qualMetaProofMutator{f.reader.proofs, func() {
		if called {
			return
		}
		called = true
		// Simulate the owning input buffers being returned for reuse when
		// the downstream proof service starts.
		for _, raw := range [][]byte{f.items[0].candidate.origin, f.bHash,
			f.w.Account.Header, f.w.Consumer, f.miniBlockRaw, f.scrRaw} {
			clear(raw)
		}
	}}
	observed, err := qualReadNativeCarrierObservation(f)
	require.NoError(t, err)
	require.True(t, called)

	for _, raw := range [][]byte{f.items[0].candidate.origin, f.bHash,
		f.w.Account.Header, f.w.Consumer, f.miniBlockRaw, f.scrRaw, f.expected} {
		clear(raw)
	}
	for _, raw := range f.w.MetaHeaders {
		clear(raw)
	}
	require.Equal(t, origin, observed.originHash)
	require.Equal(t, header, observed.carryingHeaderHash)
	require.Equal(t, consumer, observed.consumerHeaderHash)
	require.Equal(t, miniBlock, observed.miniBlockHash)
	require.Equal(t, result, observed.resultHash)
	require.Equal(t, commitment, observed.originCommitment)
	require.Equal(t, native, observed.result)
	require.Equal(t, metas, observed.metaHeaderHashes)
}

func TestQualDRWANativeResultObservation_ReceiptRefusalRestoration(t *testing.T) {
	cases := []struct {
		name   string
		change func(*qualNativeCarrierFixture) func()
	}{
		{"stale expected B", func(f *qualNativeCarrierFixture) func() {
			original := bytes.Clone(f.bHash)
			f.bHash[0] ^= 1
			return func() { f.bHash = original }
		}},
		{"unavailable header evidence", func(f *qualNativeCarrierFixture) func() {
			original := f.w.HeaderProof
			f.w.HeaderProof = nil
			return func() { f.w.HeaderProof = original }
		}},
		{"corrupt native result", func(f *qualNativeCarrierFixture) func() {
			original := f.scrRaw
			f.scrRaw = []byte{0xff}
			return func() { f.scrRaw = original }
		}},
		{"missing native reader", func(f *qualNativeCarrierFixture) func() {
			original := f.reader
			f.reader = nil
			return func() { f.reader = original }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newQualNativeCarrierFixture(t)
			before, err := qualReadNativeCarrierObservation(f)
			require.NoError(t, err)
			restore := tc.change(f)
			observed, err := qualReadNativeCarrierObservation(f)
			require.Error(t, err)
			require.Nil(t, observed, "refusal cannot publish partial provenance or authenticated no-work")
			restore()
			restored, err := qualReadNativeCarrierObservation(f)
			require.NoError(t, err)
			require.Equal(t, before, restored, "same admitted bytes give the same receipt on restoration/replay")
		})
	}
}
