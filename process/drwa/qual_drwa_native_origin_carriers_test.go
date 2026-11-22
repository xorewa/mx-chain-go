package drwa

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/stretchr/testify/require"
)

// Same explicitly limited canonical component fixture as A38; these are
// native-reference discovery/getter cases, not native B/signature admission.
func newQualOriginReferencesFixture(t *testing.T) (*qualNativeCarrierFixture, []data.MiniBlockHeaderHandler) {
	t.Helper()
	f := newQualNativeCarrierFixture(t)
	var selected []data.MiniBlockHeaderHandler
	nonce := uint64(0)
	makeHeader := func(count int, kind block.Type, sender, receiver uint32) *block.MiniBlockHeader {
		mb := &block.MiniBlock{Type: kind, SenderShardID: sender, ReceiverShardID: receiver}
		for i := 0; i < count; i++ {
			scr := &smartContractResult.SmartContractResult{}
			require.NoError(t, f.r.codec.marshaller.Unmarshal(scr, f.scrRaw))
			scr.Nonce = nonce
			nonce++
			mb.TxHashes = append(mb.TxHashes, f.hash(f.encode(t, scr)))
		}
		h := &block.MiniBlockHeader{Hash: f.hash(f.encode(t, mb)), SenderShardID: sender,
			ReceiverShardID: receiver, Type: kind, TxCount: uint32(count)}
		// Native execution-result header normalization, not canonical finality.
		require.NoError(t, h.SetIndexOfFirstTxProcessed(0))
		require.NoError(t, h.SetIndexOfLastTxProcessed(int32(count)-1))
		require.NoError(t, h.SetProcessingType(int32(block.Normal)))
		require.NoError(t, h.SetConstructionState(int32(block.Final)))
		return h
	}
	a := makeHeader(3, block.SmartContractResultBlock, 0, 1)
	b := makeHeader(1, block.SmartContractResultBlock, 0, 1)
	c := makeHeader(2, block.SmartContractResultBlock, 0, 1)
	selected = []data.MiniBlockHeaderHandler{a, b, c}
	all := []data.MiniBlockHeaderHandler{a, makeHeader(1, block.SmartContractResultBlock, 0, 2),
		b, makeHeader(1, block.TxBlock, 0, 1), c, makeHeader(1, block.SmartContractResultBlock, 2, 0)}
	require.NoError(t, f.h.ExecutionResults[0].SetMiniBlockHeadersHandlers(all))
	proposed := &block.MiniBlockHeader{Hash: bytes.Clone(a.Hash), SenderShardID: 0,
		ReceiverShardID: 1, Type: block.SmartContractResultBlock, TxCount: a.TxCount}
	require.NoError(t, proposed.SetProcessingType(int32(block.Normal)))
	require.NoError(t, proposed.SetConstructionState(int32(block.Proposed)))
	f.proposalReferences = []data.MiniBlockHeaderHandler{proposed}
	f.reseal(t)
	return f, selected
}

func readQualOriginReferences(f *qualNativeCarrierFixture, limit int) ([]byte, []data.MiniBlockHeaderHandler, error) {
	return f.r.nativeOriginSCRReferences(f.reader, f.bHash, f.consumer, f.producer,
		f.items[0].candidate.origin, f.w, limit)
}

func requireQualReferenceList(t *testing.T, expected, actual []data.MiniBlockHeaderHandler) {
	t.Helper()
	require.Len(t, actual, len(expected))
	for i := range expected {
		require.Equal(t, expected[i].GetHash(), actual[i].GetHash())
		require.Equal(t, expected[i].GetTxCount(), actual[i].GetTxCount())
		require.True(t, bytes.Equal(expected[i].(*block.MiniBlockHeader).Reserved, actual[i].(*block.MiniBlockHeader).Reserved))
		require.Equal(t, expected[i].GetSenderShardID(), actual[i].GetSenderShardID())
		require.Equal(t, expected[i].GetReceiverShardID(), actual[i].GetReceiverShardID())
		require.Equal(t, expected[i].GetTypeInt32(), actual[i].GetTypeInt32())
	}
}

func TestQualDRWANativeOriginCarriers_Discovery(t *testing.T) {
	t.Run("whole_source_order_with_subset_proposal", func(t *testing.T) {
		f, expected := newQualOriginReferencesFixture(t)
		root, err := f.s.RootHash()
		require.NoError(t, err)
		value, refs, err := readQualOriginReferences(f, f.limit-f.budget)
		require.NoError(t, err)
		require.Equal(t, f.expected, value)
		requireQualReferenceList(t, expected, refs)
		after, err := f.s.RootHash()
		require.NoError(t, err)
		require.Equal(t, root, after)
		require.Len(t, f.proposalReferences, 1)
	})

	t.Run("empty_receiving_references_keep_tail", func(t *testing.T) {
		f, expected := newQualOriginReferencesFixture(t)
		f.proposalReferences = nil
		f.reseal(t)
		value, refs, err := readQualOriginReferences(f, f.limit-f.budget)
		require.NoError(t, err)
		require.Equal(t, f.expected, value)
		requireQualReferenceList(t, expected, refs)
	})

	t.Run("later_fragment_reference_does_not_trim_source", func(t *testing.T) {
		f, expected := newQualOriginReferencesFixture(t)
		last := expected[2].(*block.MiniBlockHeader)
		proposed := &block.MiniBlockHeader{Hash: bytes.Clone(last.Hash), SenderShardID: 0,
			ReceiverShardID: 1, Type: last.Type, TxCount: last.TxCount}
		require.NoError(t, proposed.SetConstructionState(int32(block.Proposed)))
		f.proposalReferences = []data.MiniBlockHeaderHandler{proposed}
		f.reseal(t)
		value, refs, err := readQualOriginReferences(f, f.limit-f.budget)
		require.NoError(t, err)
		require.Equal(t, f.expected, value)
		requireQualReferenceList(t, expected, refs)
	})

	t.Run("local_partial_and_full_metadata_cannot_change_next_read", func(t *testing.T) {
		f, expected := newQualOriginReferencesFixture(t)
		_, refs, err := readQualOriginReferences(f, f.limit-f.budget)
		require.NoError(t, err)
		first := refs[0].(*block.MiniBlockHeader)
		require.NoError(t, first.SetConstructionState(int32(block.PartialExecuted)))
		require.NoError(t, first.SetIndexOfLastTxProcessed(0))
		require.Equal(t, int32(0), first.GetIndexOfLastTxProcessed())
		require.True(t, refs[1].(*block.MiniBlockHeader).IsFinal())
		value, again, err := readQualOriginReferences(f, f.limit-f.budget)
		require.NoError(t, err)
		require.Equal(t, f.expected, value)
		requireQualReferenceList(t, expected, again)
	})

	t.Run("authenticated_empty_carriers_is_not_empty_class_list", func(t *testing.T) {
		f, _ := newQualOriginReferencesFixture(t)
		require.NoError(t, f.h.ExecutionResults[0].SetMiniBlockHeadersHandlers(nil))
		f.reseal(t)
		value, refs, err := readQualOriginReferences(f, f.limit-f.budget)
		require.NoError(t, err)
		require.Equal(t, f.expected, value)
		require.NotEmpty(t, value)
		require.Empty(t, refs)
	})

	t.Run("other_origin_headers_are_not_in_group", func(t *testing.T) {
		f, expected := newQualOriginReferencesFixture(t)
		base := *f.h.ExecutionResults[0].BaseExecutionResult
		base.HeaderHash = f.hash(f.encode(t, &block.HeaderV3{Nonce: 12, Round: 22, Epoch: 3,
			ShardID: f.producer, ChainID: []byte("unit-chain")}))
		base.HeaderNonce, base.HeaderRound = 12, 22
		other := &block.ExecutionResult{BaseExecutionResult: &base}
		require.NoError(t, other.SetMiniBlockHeadersHandlers([]data.MiniBlockHeaderHandler{
			&block.MiniBlockHeader{Hash: []byte("foreign-reference"), SenderShardID: 0,
				ReceiverShardID: 1, Type: block.SmartContractResultBlock, TxCount: 1},
		}))
		f.h.ExecutionResults = append(f.h.ExecutionResults, other)
		f.reseal(t)
		value, refs, err := readQualOriginReferences(f, f.limit-f.budget)
		require.NoError(t, err)
		require.Equal(t, f.expected, value)
		requireQualReferenceList(t, expected, refs)
	})

	t.Run("unavailable_finality_proof_then_restored", func(t *testing.T) {
		f, expected := newQualOriginReferencesFixture(t)
		proof := bytes.Clone(f.w.HeaderProof)
		f.w.HeaderProof = nil
		f.rebudget()
		value, refs, err := readQualOriginReferences(f, f.limit-f.budget)
		require.Error(t, err)
		require.Nil(t, value)
		require.Nil(t, refs)
		f.w.HeaderProof = proof
		f.rebudget()
		value, refs, err = readQualOriginReferences(f, f.limit-f.budget)
		require.NoError(t, err)
		require.Equal(t, f.expected, value)
		requireQualReferenceList(t, expected, refs)
	})

	t.Run("same_B_different_sibling_H_refused", func(t *testing.T) {
		f, _ := newQualOriginReferencesFixture(t)
		beforeB := bytes.Clone(f.bHash)
		headers := f.h.ExecutionResults[0].GetMiniBlockHeadersHandlers()
		headers[0], headers[1] = headers[1], headers[0]
		require.NoError(t, f.h.ExecutionResults[0].SetMiniBlockHeadersHandlers(headers))
		f.w.Account.Header = f.encode(t, f.h)
		f.w.HeaderProof = f.proof(t, f.h, f.w.Account.Header)
		// Deliberately retain B and its selected meta ancestry.
		f.rebudget()
		value, refs, err := readQualOriginReferences(f, f.limit-f.budget)
		require.Error(t, err)
		require.Nil(t, value)
		require.Nil(t, refs)
		require.Equal(t, beforeB, f.bHash)
	})

	t.Run("whole_witness_bound_never_returns_prefix", func(t *testing.T) {
		f, _ := newQualOriginReferencesFixture(t)
		value, refs, err := readQualOriginReferences(f, f.limit-f.budget-1)
		require.Error(t, err)
		require.Nil(t, value)
		require.Nil(t, refs)
	})

	t.Run("hashless_selected_reference_refused", func(t *testing.T) {
		f, _ := newQualOriginReferencesFixture(t)
		headers := f.h.ExecutionResults[0].GetMiniBlockHeadersHandlers()
		headers[4].(*block.MiniBlockHeader).Hash = nil
		require.NoError(t, f.h.ExecutionResults[0].SetMiniBlockHeadersHandlers(headers))
		f.reseal(t)
		value, refs, err := readQualOriginReferences(f, f.limit-f.budget)
		require.Error(t, err)
		require.Nil(t, value)
		require.Nil(t, refs)
	})

	t.Run("ambiguous_origin_refused", func(t *testing.T) {
		f, _ := newQualOriginReferencesFixture(t)
		f.h.ExecutionResults = append(f.h.ExecutionResults, f.h.ExecutionResults[0])
		f.reseal(t)
		value, refs, err := readQualOriginReferences(f, f.limit-f.budget)
		require.Error(t, err)
		require.Nil(t, value)
		require.Nil(t, refs)
	})

	t.Run("zero_count_reference_is_not_dropped_as_no_work", func(t *testing.T) {
		f, _ := newQualOriginReferencesFixture(t)
		empty := &block.MiniBlock{Type: block.SmartContractResultBlock, SenderShardID: 0, ReceiverShardID: 1}
		header := &block.MiniBlockHeader{Hash: f.hash(f.encode(t, empty)), Type: empty.Type,
			SenderShardID: 0, ReceiverShardID: 1, TxCount: 0}
		require.NoError(t, f.h.ExecutionResults[0].SetMiniBlockHeadersHandlers([]data.MiniBlockHeaderHandler{header}))
		f.reseal(t)
		value, refs, err := readQualOriginReferences(f, f.limit-f.budget)
		require.NoError(t, err)
		require.Equal(t, f.expected, value)
		require.Len(t, refs, 1)
		require.Zero(t, refs[0].GetTxCount())
	})
}

func TestQualDRWANativeOriginCarriers_PrefixEvidence(t *testing.T) {
	t.Run("proposed_full_range_is_not_canonical_finality", func(t *testing.T) {
		header := &block.MiniBlockHeader{TxCount: 3}
		require.NoError(t, header.SetProcessingType(int32(block.Normal)))
		require.NoError(t, header.SetConstructionState(int32(block.Proposed)))
		require.Equal(t, int32(0), header.GetIndexOfFirstTxProcessed())
		require.Equal(t, int32(2), header.GetIndexOfLastTxProcessed())
		require.False(t, header.IsFinal())
	})

	t.Run("legacy_partial_zero_index_is_not_unset_final_index", func(t *testing.T) {
		header := &block.MiniBlockHeader{TxCount: 3}
		require.NoError(t, header.SetConstructionState(int32(block.PartialExecuted)))
		require.NoError(t, header.SetIndexOfFirstTxProcessed(0))
		require.NoError(t, header.SetIndexOfLastTxProcessed(0))
		require.Equal(t, int32(0), header.GetIndexOfLastTxProcessed())
		require.NoError(t, header.SetConstructionState(int32(block.Final)))
		require.Equal(t, int32(2), header.GetIndexOfLastTxProcessed())
	})

	t.Run("malformed_reserved_fallback_is_not_authority", func(t *testing.T) {
		header := &block.MiniBlockHeader{TxCount: 3, Reserved: []byte{0xff}}
		require.True(t, header.IsFinal())
		require.Equal(t, int32(0), header.GetIndexOfFirstTxProcessed())
		require.Equal(t, int32(2), header.GetIndexOfLastTxProcessed())
	})

	t.Run("zero_count_range_is_not_no_work_proof", func(t *testing.T) {
		header := &block.MiniBlockHeader{TxCount: 0}
		require.Equal(t, int32(0), header.GetIndexOfFirstTxProcessed())
		require.Equal(t, int32(-1), header.GetIndexOfLastTxProcessed())
	})
}
