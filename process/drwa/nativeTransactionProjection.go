package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/sharding"
)

// readProducerNativeTransactionProjection checks one supplied original carrier
// position in the admitted S/H/M/B context. The caller must bind producerStore
// and producerCoordinator to the producing node; StorageService has no shard
// identity. B identifies the consuming header, not the storage owner.
//
// The source node's saveExecutedData requests H's epoch for its executed outbound
// miniblock. Its saveBody requests S's epoch for the original transaction in S.
// These are native lookup arguments; the storer owns cache, persister and history
// selection. This point read grants no coverage or application permission.
func (r *canonicalResultReader) readProducerNativeTransactionProjection(
	producerStore dataRetriever.StorageService, producerCoordinator sharding.Coordinator,
	committedB, origin, expectedRoot, miniBlockHash, transactionHash []byte,
	producer, consumer uint32, miniBlockIndex, transactionIndex int32, w canonicalResultWitness, byteLimit int,
) (*block.MiniBlock, *transaction.Transaction, error) {
	if r == nil || r.accounts == nil || producer == consumer || producer == core.MetachainShardId ||
		consumer == core.MetachainShardId || miniBlockIndex < 0 {
		return nil, nil, ErrInvalidAccountWitness
	}
	remaining := byteLimit
	for _, id := range [][]byte{committedB, origin, expectedRoot} {
		if len(id) == 0 || len(id) > remaining {
			return nil, nil, ErrInvalidAccountWitness
		}
		remaining -= len(id)
	}
	payloadLimit, err := canonicalWitnessRemaining(w, remaining)
	if err != nil {
		return nil, nil, err
	}

	// Leave the lookup keys in the payload budget, where the native reader
	// and decoder both count them. Check that budget before copying any input.
	if len(miniBlockHash) == 0 || len(miniBlockHash) > payloadLimit ||
		len(transactionHash) == 0 || len(transactionHash) > payloadLimit-len(miniBlockHash) {
		return nil, nil, ErrInvalidAccountWitness
	}
	committedB, origin, expectedRoot = bytes.Clone(committedB), bytes.Clone(origin), bytes.Clone(expectedRoot)
	miniBlockHash, transactionHash = bytes.Clone(miniBlockHash), bytes.Clone(transactionHash)
	w = cloneCanonicalResultWitness(w)

	hasher := r.accounts.args.Hasher
	if check.IfNil(hasher) || check.IfNil(r.accounts.args.Marshaller) || check.IfNil(producerCoordinator) ||
		producerCoordinator.SelfId() != producer {
		return nil, nil, ErrInvalidAccountWitness
	}
	size := hasher.Size()
	for _, id := range [][]byte{committedB, origin, expectedRoot, miniBlockHash, transactionHash} {
		if len(id) != size {
			return nil, nil, ErrInvalidAccountWitness
		}
	}
	projection, err := r.readBoundedContext(committedB, consumer, producer, origin, w)
	if err != nil {
		return nil, nil, err
	}
	root, err := r.accounts.executionRoot(producer, w.Account)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(root, expectedRoot) {
		return nil, nil, ErrInvalidAccountWitness
	}
	count, err := projectedNativeTransactionCount(projection, origin, miniBlockHash, producer, consumer, miniBlockIndex)
	if err != nil {
		return nil, nil, err
	}
	miniRaw, transactionRaw, err := r.accounts.readNativeTransactionPayloadsAtEpochs(producerStore,
		projection.carryingHeader.GetEpoch(), projection.executedHeader.GetEpoch(), miniBlockHash, transactionHash, payloadLimit)
	if err != nil {
		return nil, nil, err
	}
	mini, tx, err := r.accounts.decodeNativeTransactionMember(producerCoordinator, miniBlockHash, transactionHash,
		miniRaw, transactionRaw, producer, consumer, transactionIndex, payloadLimit)
	if err != nil {
		return nil, nil, err
	}
	if uint64(len(mini.TxHashes)) != uint64(count) {
		return nil, nil, ErrInvalidAccountWitness
	}

	return mini, tx, nil
}

// ShardInfoCreateData copies these five descriptor fields from the executed
// result in order. MiniBlockHeader.Reserved is not part of that projection.
// Check only this point; neither loop certifies the whole origin or all carriers.
func projectedNativeTransactionCount(projection *canonicalResultProjection, origin, miniBlockHash []byte,
	producer, consumer uint32, index int32,
) (uint32, error) {
	var fromResult []block.MiniBlockHeader
	for _, result := range projection.carryingHeader.(*block.HeaderV3).ExecutionResults {
		// executionRoot has verified that every result is present and that
		// exactly one of them carries this origin.
		if bytes.Equal(result.GetHeaderHash(), origin) {
			fromResult = result.MiniBlockHeaders
			break
		}
	}
	if int(index) >= len(fromResult) {
		return 0, ErrInvalidAccountWitness
	}
	header := fromResult[index]
	if header.Type != block.TxBlock || header.SenderShardID != producer ||
		header.ReceiverShardID != consumer || !bytes.Equal(header.Hash, miniBlockHash) {
		return 0, ErrInvalidAccountWitness
	}
	for _, shard := range projection.meta.ShardInfo {
		if shard.ShardID != producer || !bytes.Equal(shard.HeaderHash, origin) {
			continue
		}
		if int(index) >= len(shard.ShardMiniBlockHeaders) {
			break
		}
		atMeta := shard.ShardMiniBlockHeaders[index]
		if atMeta.Type == header.Type && atMeta.SenderShardID == header.SenderShardID &&
			atMeta.ReceiverShardID == header.ReceiverShardID && atMeta.TxCount == header.TxCount &&
			bytes.Equal(atMeta.Hash, header.Hash) {
			return header.TxCount, nil
		}
		break
	}
	return 0, ErrInvalidAccountWitness
}
