package drwa

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// SP2-22, audit finding TA-SP2-22-S133156C-1: guards of the supplied-origin
// projection whose removal no earlier case noticed. Each case gives the reader
// a context that is complete and valid for the refused route, so only the
// guard under test can refuse it.

func TestQualSP222NativeProjectionRouteGuardsRefuseBeforeAnyProof(t *testing.T) {
	for _, tc := range []struct {
		name               string
		producer, consumer uint32
	}{
		{"same_shard_with_a_valid_same_shard_context", 1, 1},
		{"metachain_source_with_a_valid_metachain_context", core.MetachainShardId, 0},
		{"metachain_destination_with_a_valid_metachain_consumer", 1, core.MetachainShardId},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCanonicalTestFixture(t, tc.producer, tc.consumer)
			// The context itself is admitted by the canonical reader.
			_, err := f.read()
			require.NoError(t, err)
			origin := f.hash(f.w.Account.ExecutedHeader)
			root, err := f.s.RootHash()
			require.NoError(t, err)
			identity := f.hash([]byte("some native identity"))
			calls := f.oracle.calls
			mini, tx, err := f.reader.readProducerNativeTransactionProjection(&qualSCRPayloadStorage{},
				&testscommon.ShardsCoordinatorMock{NoShards: 3, CurrentShard: tc.producer},
				f.bHash, origin, root, identity, identity, tc.producer, tc.consumer, 0, 0, f.w, 1<<20)
			require.ErrorIs(t, err, ErrInvalidAccountWitness)
			require.Nil(t, mini)
			require.Nil(t, tx)
			require.Equal(t, calls, f.oracle.calls, "the route is refused before the context is read")
		})
	}
}

// A descriptor that is wrong in the same way in the carrying header and in the
// metachain projection is still refused by the source-side checks.
func TestQualSP222NativeProjectionSourceDescriptorGuards(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*block.MiniBlockHeader)
	}{
		{"both_sides_not_a_transaction_block", func(h *block.MiniBlockHeader) { h.Type = block.SmartContractResultBlock }},
		{"both_sides_another_sender", func(h *block.MiniBlockHeader) { h.SenderShardID = 2 }},
		{"both_sides_another_receiver", func(h *block.MiniBlockHeader) { h.ReceiverShardID = 2 }},
		{"both_sides_another_hash", func(h *block.MiniBlockHeader) { h.Hash = bytes.Repeat([]byte{3}, 32) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCanonicalTestFixture(t, 1, 0)
			origin := f.hash(f.w.Account.ExecutedHeader)
			descriptor := block.MiniBlockHeader{Type: block.TxBlock, SenderShardID: f.producer, ReceiverShardID: f.consumer,
				Hash: f.hash([]byte("ordinary descriptor")), TxCount: 2}
			wanted := bytes.Clone(descriptor.Hash)
			build := func(d block.MiniBlockHeader) *canonicalResultProjection {
				return &canonicalResultProjection{
					carryingHeader: &block.HeaderV3{ExecutionResults: []*block.ExecutionResult{{
						BaseExecutionResult: &block.BaseExecutionResult{HeaderHash: origin},
						MiniBlockHeaders:    []block.MiniBlockHeader{d}}}},
					meta: &block.MetaBlockV3{ShardInfo: []block.ShardData{{ShardID: f.producer, HeaderHash: origin,
						ShardMiniBlockHeaders: []block.MiniBlockHeader{d}}}},
				}
			}
			count, err := projectedNativeTransactionCount(build(descriptor), origin, wanted, f.producer, f.consumer, 0)
			require.NoError(t, err)
			require.Equal(t, uint32(2), count)

			tc.change(&descriptor)
			count, err = projectedNativeTransactionCount(build(descriptor), origin, wanted, f.producer, f.consumer, 0)
			require.ErrorIs(t, err, ErrInvalidAccountWitness)
			require.Zero(t, count)
		})
	}
}
