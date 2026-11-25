package receipts_test

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/batch"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/process/receipts"
	"github.com/multiversx/mx-chain-go/testscommon/genericMocks"
	"github.com/stretchr/testify/require"
)

// Ordinary local receipt serialization and storage reuse across repository
// instances. The execution-result DTOs are inert, not authenticated inputs.
func TestQualSP222OrdinaryReceiptRoundTrip(t *testing.T) {
	const epoch = uint32(7)
	marshaller := &marshal.GogoProtoMarshalizer{}
	hasher := blake2b.NewBlake2b()
	miniBlocks := []*block.MiniBlock{
		{Type: block.SmartContractResultBlock, SenderShardID: 1, ReceiverShardID: 1, TxHashes: [][]byte{hasher.Compute("ordinary output 1"), hasher.Compute("ordinary output 2")}},
		{Type: block.ReceiptBlock, SenderShardID: 1, ReceiverShardID: 1, TxHashes: [][]byte{hasher.Compute("ordinary fee receipt")}},
	}
	var contents, hashes [][]byte
	for _, mb := range miniBlocks {
		raw, err := marshaller.Marshal(mb)
		require.NoError(t, err)
		contents = append(contents, raw)
		hashes = append(hashes, hasher.Compute(string(raw)))
	}
	expectedBytes, err := marshaller.Marshal(&batch.Batch{Data: contents})
	require.NoError(t, err)
	receiptHash, err := core.CalculateHash(marshaller, hasher, &batch.Batch{Data: hashes})
	require.NoError(t, err)
	headerHash := hasher.Compute("ordinary header fixture")
	require.NotEqual(t, headerHash, receiptHash)
	header := &block.Header{Epoch: epoch, Nonce: 3, ReceiptsHash: receiptHash}
	base := &block.BaseExecutionResult{HeaderHash: headerHash, HeaderEpoch: epoch, HeaderNonce: 3}
	holdersInput := holders.NewReceiptsHolder(miniBlocks)

	for _, tc := range []struct {
		name   string
		result data.BaseExecutionResultHandler
	}{
		{name: "header"},
		{name: "shard_result", result: &block.ExecutionResult{BaseExecutionResult: base, ReceiptsHash: receiptHash}},
		{name: "meta_result", result: &block.MetaExecutionResult{ExecutionResult: &block.BaseMetaExecutionResult{BaseExecutionResult: base}, ReceiptsHash: receiptHash}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := genericMocks.NewChainStorerMock(epoch)
			args := receipts.ArgsNewReceiptsRepository{Marshaller: marshaller, Hasher: hasher, Store: store}
			writer, err := receipts.NewReceiptsRepository(args)
			require.NoError(t, err)
			if tc.result == nil {
				require.NoError(t, writer.SaveReceipts(holdersInput, header, headerHash))
			} else {
				require.NoError(t, writer.SaveReceiptsForExecResult(holdersInput, tc.result))
			}
			storer, err := store.GetStorer(dataRetriever.ReceiptsUnit)
			require.NoError(t, err)
			actualBytes, err := storer.GetFromEpoch(receiptHash, epoch)
			require.NoError(t, err)
			require.Equal(t, expectedBytes, actualBytes)

			reader, err := receipts.NewReceiptsRepository(args)
			require.NoError(t, err)
			got, err := reader.LoadReceipts(receiptHash, header, headerHash)
			require.NoError(t, err)
			require.Equal(t, miniBlocks, got.GetMiniblocks())
		})
	}
}
