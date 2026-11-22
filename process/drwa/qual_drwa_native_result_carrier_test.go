package drwa

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/stretchr/testify/require"
)

// Reuse the existing canonical component fixture: real account/data trie proofs,
// explicitly limited header/proof doubles. These cases exercise native committed
// carrier bytes, not live B admission, a protected class host or funded service.
type qualNativeCarrierFixture struct {
	*canonicalTestFixture
	h                        *block.HeaderV3
	miniBlock                *block.MiniBlock
	miniBlockRaw, scrRaw     []byte
	proposalReferences       []data.MiniBlockHeaderHandler
	consumerExecutionResults []*block.ExecutionResult
}

func newQualNativeCarrierFixture(t *testing.T) *qualNativeCarrierFixture {
	t.Helper()
	f := &qualNativeCarrierFixture{canonicalTestFixture: newCanonicalTestFixture(t, 0, 1)}
	f.h = &block.HeaderV3{}
	require.NoError(t, f.r.codec.marshaller.Unmarshal(f.h, f.w.Account.Header))
	scr := &smartContractResult.SmartContractResult{
		Value: big.NewInt(0), SndAddr: []byte("source"), RcvAddr: []byte("destination"),
		Data:       []byte("ESDTTransfer@544f4b454e2d616263646566@01"),
		PrevTxHash: []byte("source-native-tx"), OriginalTxHash: []byte("original-native-tx"),
		OriginalSender: []byte("original-native-sender"),
		GasLimit:       67, GasPrice: 31, // diagnostic carrier values, not an admitted tariff
	}
	f.scrRaw = f.encode(t, scr)
	f.miniBlock = &block.MiniBlock{Type: block.SmartContractResultBlock,
		SenderShardID: 0, ReceiverShardID: 1, TxHashes: [][]byte{f.hash(f.scrRaw)}}
	f.commitCarrier(t)
	return f
}

func (f *qualNativeCarrierFixture) commitCarrier(t *testing.T) {
	t.Helper()
	f.miniBlockRaw = f.encode(t, f.miniBlock)
	header := &block.MiniBlockHeader{Hash: f.hash(f.miniBlockRaw),
		SenderShardID: f.miniBlock.SenderShardID, ReceiverShardID: f.miniBlock.ReceiverShardID,
		Type: f.miniBlock.Type, TxCount: uint32(len(f.miniBlock.TxHashes))}
	require.NoError(t, f.h.ExecutionResults[0].SetMiniBlockHeadersHandlers([]data.MiniBlockHeaderHandler{header}))
	f.proposalReferences = []data.MiniBlockHeaderHandler{header}
	f.reseal(t)
}

func (f *qualNativeCarrierFixture) reseal(t *testing.T) {
	t.Helper()
	f.w.Account.Header = f.encode(t, f.h)
	f.w.HeaderProof = f.proof(t, f.h, f.w.Account.Header)
	f.metas[0].ShardInfoProposal[0].HeaderHash = f.hash(f.w.Account.Header)
	f.rechain(t)
	b := &block.HeaderV3{}
	require.NoError(t, f.r.codec.marshaller.Unmarshal(b, f.w.Consumer))
	require.NoError(t, b.SetMiniBlockHeaderHandlers(f.proposalReferences))
	b.ExecutionResults = f.consumerExecutionResults
	f.w.Consumer = f.encode(t, b)
	f.bHash = f.hash(f.w.Consumer)
	f.rebudget()
}

func (f *qualNativeCarrierFixture) readCarrier(limit int) ([]byte, *smartContractResult.SmartContractResult, error) {
	return f.r.readNativeSCR(f.reader, f.bHash, f.consumer, f.producer, f.items[0].candidate.origin,
		f.w, f.miniBlockRaw, f.scrRaw, limit)
}

func (f *qualNativeCarrierFixture) carrierLimit() int {
	return f.limit - f.budget + len(f.miniBlockRaw) + len(f.scrRaw)
}

func TestQualDRWANativeShardSCRRejectsMetaBeforeOriginKey(t *testing.T) {
	f, _, _, miniRaw, scrRaw, limit := qualNativeMetaSCRFixture(t, nil)
	origin := f.hash(f.w.Account.ExecutedHeader)
	codec := &pendingFinalTestMarshalizer{Marshalizer: f.r.codec.marshaller}
	f.r.codec.marshaller = codec

	_, err := f.r.readNativeSCRObservation(f.reader, f.bHash, f.consumer, core.MetachainShardId,
		origin, f.w, miniRaw, scrRaw, limit)
	require.Error(t, err)
	require.Zero(t, codec.calls, "shard SCR observation rejects the route before building an origin key")

	_, _, err = f.r.nativeOriginSCRReferences(f.reader, f.bHash, f.consumer, core.MetachainShardId,
		origin, f.w, limit)
	require.Error(t, err)
	require.Zero(t, codec.calls, "shard SCR reference reader rejects the same route before building an origin key")
}

func TestQualDRWANativeResultCarrier_HeaderBinding(t *testing.T) {
	f := newQualNativeCarrierFixture(t)
	carrierHash := f.hash(f.miniBlockRaw)
	header := *f.proposalReferences[0].(*block.MiniBlockHeader)
	require.True(t, nativeSCRHeaderMatches(&header, carrierHash, f.miniBlock))

	t.Run("different_header_type", func(t *testing.T) {
		other := header
		other.Type = block.TxBlock
		require.False(t, nativeSCRHeaderMatches(&other, carrierHash, f.miniBlock))
	})
	t.Run("different_header_identity", func(t *testing.T) {
		other := header
		other.Hash = f.hash([]byte("another ordinary fixture carrier"))
		require.False(t, nativeSCRHeaderMatches(&other, carrierHash, f.miniBlock))
	})
}

func TestQualDRWANativeResultCarrier_Read(t *testing.T) {
	t.Run("exact_origin_carrier_and_source_allocation", func(t *testing.T) {
		f := newQualNativeCarrierFixture(t)
		before, err := f.s.RootHash()
		require.NoError(t, err)
		value, scr, err := f.readCarrier(f.carrierLimit())
		require.NoError(t, err)
		require.Equal(t, f.expected, value)
		require.Equal(t, uint64(67), scr.GasLimit)
		require.Equal(t, uint64(31), scr.GasPrice)
		require.Equal(t, []byte("original-native-tx"), scr.OriginalTxHash)
		require.Equal(t, []byte("original-native-sender"), scr.OriginalSender)
		require.Equal(t, []byte("ESDTTransfer@544f4b454e2d616263646566@01"), scr.Data)
		after, err := f.s.RootHash()
		require.NoError(t, err)
		require.Equal(t, before, after)
		again, replay, err := f.readCarrier(f.carrierLimit())
		require.NoError(t, err)
		require.Equal(t, value, again)
		require.Equal(t, scr, replay)
		require.Equal(t, uint64(15), f.h.Nonce) // carrying H is not S+1
		require.Equal(t, uint32(4), f.h.Epoch)
		require.Equal(t, uint32(3), f.h.ExecutionResults[0].BaseExecutionResult.HeaderEpoch)
	})

	for _, tc := range []struct {
		name   string
		change func(*testing.T, *qualNativeCarrierFixture)
	}{
		{"different_source_origin", func(t *testing.T, f *qualNativeCarrierFixture) {
			base := *f.h.ExecutionResults[0].BaseExecutionResult
			base.HeaderHash = f.hash(f.encode(t, &block.HeaderV3{Nonce: 12, Round: 22, Epoch: 3, ShardID: f.producer, ChainID: []byte("unit-chain")}))
			base.HeaderNonce, base.HeaderRound = 12, 22
			other := &block.ExecutionResult{BaseExecutionResult: &base}
			require.NoError(t, other.SetMiniBlockHeadersHandlers(f.h.ExecutionResults[0].GetMiniBlockHeadersHandlers()))
			require.NoError(t, f.h.ExecutionResults[0].SetMiniBlockHeadersHandlers(nil))
			f.h.ExecutionResults = append(f.h.ExecutionResults, other)
			f.reseal(t)
			require.NotNil(t, process.GetMiniBlockHeaderWithHash(f.h, f.hash(f.miniBlockRaw)))
		}},
		{"consumer_execution_result_is_not_proposal_reference", func(t *testing.T, f *qualNativeCarrierFixture) {
			base := *f.h.ExecutionResults[0].BaseExecutionResult
			base.HeaderHash = f.hash(f.encode(t, &block.HeaderV3{Nonce: 11, Round: 21, Epoch: 3, ShardID: f.consumer, ChainID: []byte("unit-chain")}))
			past := &block.ExecutionResult{BaseExecutionResult: &base}
			require.NoError(t, past.SetMiniBlockHeadersHandlers(f.h.ExecutionResults[0].GetMiniBlockHeadersHandlers()))
			f.consumerExecutionResults = []*block.ExecutionResult{past}
			f.proposalReferences = nil
			f.reseal(t)
			b := &block.HeaderV3{}
			require.NoError(t, f.r.codec.marshaller.Unmarshal(b, f.w.Consumer))
			require.NotNil(t, process.GetMiniBlockHeaderWithHash(b, f.hash(f.miniBlockRaw)))
		}},
		{"missing_consumer_reference", func(t *testing.T, f *qualNativeCarrierFixture) {
			f.proposalReferences = nil
			f.reseal(t)
		}},
		{"wrong_miniblock_type", func(t *testing.T, f *qualNativeCarrierFixture) {
			f.miniBlock.Type = block.TxBlock
			f.commitCarrier(t)
		}},
		{"wrong_destination", func(t *testing.T, f *qualNativeCarrierFixture) {
			f.miniBlock.ReceiverShardID = 2
			f.commitCarrier(t)
		}},
		{"wrong_source", func(t *testing.T, f *qualNativeCarrierFixture) {
			f.miniBlock.SenderShardID = 2
			f.commitCarrier(t)
		}},
		{"changed_miniblock_bytes", func(t *testing.T, f *qualNativeCarrierFixture) {
			f.miniBlockRaw = f.encode(t, &block.MiniBlock{Type: block.SmartContractResultBlock,
				SenderShardID: 0, ReceiverShardID: 1, TxHashes: [][]byte{[]byte("foreign-tx")}})
		}},
		{"foreign_scr", func(t *testing.T, f *qualNativeCarrierFixture) {
			f.miniBlock.TxHashes = [][]byte{[]byte("foreign-tx")}
			f.commitCarrier(t)
		}},
		{"changed_scr_bytes", func(t *testing.T, f *qualNativeCarrierFixture) {
			f.scrRaw = f.encode(t, &smartContractResult.SmartContractResult{Value: big.NewInt(0), GasLimit: 68})
		}},
		{"duplicate_scr_membership", func(t *testing.T, f *qualNativeCarrierFixture) {
			f.miniBlock.TxHashes = append(f.miniBlock.TxHashes, bytes.Clone(f.miniBlock.TxHashes[0]))
			f.commitCarrier(t)
		}},
		{"malformed_miniblock", func(t *testing.T, f *qualNativeCarrierFixture) { f.miniBlockRaw = []byte{0xff} }},
		{"malformed_scr", func(t *testing.T, f *qualNativeCarrierFixture) { f.scrRaw = []byte{0xff} }},
		{"missing_scr", func(t *testing.T, f *qualNativeCarrierFixture) { f.scrRaw = nil }},
		{"canonical_proof_refusal", func(t *testing.T, f *qualNativeCarrierFixture) {
			f.w.Account.DataProof[0] = []byte("unavailable-or-invalid-proof")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newQualNativeCarrierFixture(t)
			before, err := f.s.RootHash()
			require.NoError(t, err)
			tc.change(t, f)
			if tc.name != "canonical_proof_refusal" {
				control, controlErr := f.canonicalTestFixture.read()
				require.NoError(t, controlErr)
				require.Equal(t, f.expected, control)
			}
			value, scr, err := f.readCarrier(f.carrierLimit())
			require.Error(t, err)
			require.Nil(t, value)
			require.Nil(t, scr)
			after, rootErr := f.s.RootHash()
			require.NoError(t, rootErr)
			require.Equal(t, before, after)
		})
	}

	t.Run("missing_then_restored", func(t *testing.T) {
		f := newQualNativeCarrierFixture(t)
		original := bytes.Clone(f.miniBlockRaw)
		f.miniBlockRaw = nil
		value, scr, err := f.readCarrier(f.carrierLimit())
		require.Error(t, err)
		require.Nil(t, value)
		require.Nil(t, scr)
		f.miniBlockRaw = original
		value, scr, err = f.readCarrier(f.carrierLimit())
		require.NoError(t, err)
		require.Equal(t, f.expected, value)
		require.Equal(t, uint64(67), scr.GasLimit)
	})

	t.Run("combined_bound", func(t *testing.T) {
		f := newQualNativeCarrierFixture(t)
		value, scr, err := f.readCarrier(f.carrierLimit() - 1)
		require.Error(t, err)
		require.Nil(t, value)
		require.Nil(t, scr)
	})

	t.Run("zero_native_allocation_is_not_funding", func(t *testing.T) {
		f := newQualNativeCarrierFixture(t)
		scr := &smartContractResult.SmartContractResult{}
		require.NoError(t, f.r.codec.marshaller.Unmarshal(scr, f.scrRaw))
		scr.GasLimit, scr.GasPrice = 0, 0
		f.scrRaw = f.encode(t, scr)
		f.miniBlock.TxHashes = [][]byte{f.hash(f.scrRaw)}
		f.commitCarrier(t)
		value, got, err := f.readCarrier(f.carrierLimit())
		require.NoError(t, err)
		require.Equal(t, f.expected, value)
		require.Zero(t, got.GasLimit)
		require.Zero(t, got.GasPrice)
	})
}
