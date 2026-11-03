package block_test

import (
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	processBlock "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/process/block/processedMb"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/stretchr/testify/require"
	"testing"
)

type qualG25Header struct {
	*block.Header
	reads int
}

func (h *qualG25Header) GetMiniBlockHeaderHandlers() []data.MiniBlockHeaderHandler {
	h.reads++
	return h.Header.GetMiniBlockHeaderHandlers()
}

// Observe both actual consumers of the new cached header traversal, with
// independent miniblock fields and a tracker spy. No cross-shard transport.
func TestQualPartialsG25MiniBlockHeaderConsumers(t *testing.T) {
	headers := []block.MiniBlockHeader{{Hash: []byte("to-me"), SenderShardID: 1, ReceiverShardID: 0, TxCount: 2, Type: block.TxBlock}, {Hash: []byte("to-other"), SenderShardID: 1, ReceiverShardID: 2, TxCount: 3, Type: block.SmartContractResultBlock}}
	t.Run("meta", func(t *testing.T) {
		core, dataC, boot, status := createMockComponentHolders()
		core.EnableEpochsHandlerField = enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
		args := createMockMetaArguments(core, dataC, boot, status)
		mp, err := processBlock.NewMetaProcessor(args)
		require.NoError(t, err)
		header := &qualG25Header{Header: &block.Header{MiniBlockHeaders: headers}}
		output := mp.BuildShardDataFromHeader(header, []byte("shard-header"))
		require.Equal(t, headers, output.ShardMiniBlockHeaders)
		require.Equal(t, 1, header.reads)
	})
	t.Run("shard", func(t *testing.T) {
		args := CreateMockArgumentsMultiShard(createMockComponentHolders())
		metaHash := []byte("meta-header")
		recorded := [][]byte{}
		args.ProcessedMiniBlocksTracker = &testscommon.ProcessedMiniBlocksTrackerStub{SetProcessedMiniBlockInfoCalled: func(meta, mini []byte, _ *processedMb.ProcessedMiniBlockInfo) {
			require.Equal(t, metaHash, meta)
			recorded = append(recorded, mini)
		}}
		sp, err := processBlock.NewShardProcessor(args)
		require.NoError(t, err)
		meta := &block.MetaBlock{ShardInfo: []block.ShardData{{ShardID: 1, ShardMiniBlockHeaders: headers}}}
		args.HeadersForBlock.AddHeaderUsedInBlock(string(metaHash), meta)
		header := &qualG25Header{Header: &block.Header{MiniBlockHeaders: headers, MetaBlockHashes: [][]byte{metaHash}}}
		require.NoError(t, sp.AddProcessedCrossMiniBlocksFromHeader(header))
		require.Equal(t, [][]byte{[]byte("to-me")}, recorded)
		require.Equal(t, 2, header.reads, "one traversal plus one native matching-header lookup")
	})
}
