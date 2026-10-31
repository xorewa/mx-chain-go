package block_test

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	processBlock "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/process/block/processedMb"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

func TestQualG31ShardInterfaceMiniblocks(t *testing.T) {
	coreC, dataC, bootstrapC, statusC := createComponentHolderMocks()
	args := CreateMockArguments(coreC, dataC, bootstrapC, statusC)
	metaHash, miniHash := []byte("meta"), []byte("mini")
	meta := createDummyMetaBlock(0, 1, miniHash)
	calls := 0
	args.ProcessedMiniBlocksTracker = &testscommon.ProcessedMiniBlocksTrackerStub{
		SetProcessedMiniBlockInfoCalled: func(mh, bh []byte, info *processedMb.ProcessedMiniBlockInfo) {
			calls++
			require.Equal(t, metaHash, mh)
			require.Equal(t, miniHash, bh)
			require.True(t, info.FullyProcessed)
		},
	}
	sp, err := processBlock.NewShardProcessor(args)
	require.NoError(t, err)
	args.HeadersForBlock.AddHeaderUsedInBlock(string(metaHash), meta)
	mini := &block.MiniBlockHeader{Hash: miniHash, SenderShardID: 1, ReceiverShardID: 0, TxCount: 1}
	require.NoError(t, mini.SetConstructionState(int32(block.Final)))
	header := &qualG31ShardHeader{Header: &block.Header{MetaBlockHashes: [][]byte{metaHash}}, minis: []data.MiniBlockHeaderHandler{mini}}
	require.NoError(t, sp.AddProcessedCrossMiniBlocksFromHeader(header))
	require.Equal(t, 1, calls)
	header.minis = nil
	require.NoError(t, sp.AddProcessedCrossMiniBlocksFromHeader(header))
	require.Equal(t, 1, calls)
}
