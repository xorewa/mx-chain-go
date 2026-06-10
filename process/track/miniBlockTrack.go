package track

import (
	"sync"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/storage"
)

type confirmedMiniBlockInfo struct {
	cacheID string
	mbType  block.Type
	nonce   uint64
}

type miniBlockTrack struct {
	blockTransactionsPool    dataRetriever.ShardedDataCacherNotifier
	rewardTransactionsPool   dataRetriever.ShardedDataCacherNotifier
	unsignedTransactionsPool dataRetriever.ShardedDataCacherNotifier
	miniBlocksPool           storage.Cacher
	shardCoordinator         sharding.Coordinator
	whitelistHandler         process.WhiteListHandler
	requireConfirmation      bool
	mutConfirmedMiniBlocks   sync.RWMutex
	confirmedMiniBlocks      map[string]confirmedMiniBlockInfo
}

// NewMiniBlockTrack creates an object for tracking the received mini blocks
func NewMiniBlockTrack(
	dataPool dataRetriever.PoolsHolder,
	shardCoordinator sharding.Coordinator,
	whitelistHandler process.WhiteListHandler,
) (*miniBlockTrack, error) {
	return newMiniBlockTrack(dataPool, nil, shardCoordinator, whitelistHandler)
}

// NewMiniBlockTrackWithBlockTracker creates an object for tracking received mini blocks and confirmation headers.
func NewMiniBlockTrackWithBlockTracker(
	dataPool dataRetriever.PoolsHolder,
	blockTracker process.BlockTracker,
	shardCoordinator sharding.Coordinator,
	whitelistHandler process.WhiteListHandler,
) (*miniBlockTrack, error) {
	return newMiniBlockTrack(dataPool, blockTracker, shardCoordinator, whitelistHandler)
}

func newMiniBlockTrack(
	dataPool dataRetriever.PoolsHolder,
	blockTracker process.BlockTracker,
	shardCoordinator sharding.Coordinator,
	whitelistHandler process.WhiteListHandler,
) (*miniBlockTrack, error) {
	if check.IfNil(dataPool) {
		return nil, process.ErrNilPoolsHolder
	}
	if check.IfNil(dataPool.Transactions()) {
		return nil, process.ErrNilTransactionPool
	}
	if check.IfNil(dataPool.RewardTransactions()) {
		return nil, process.ErrNilRewardTxDataPool
	}
	if check.IfNil(dataPool.UnsignedTransactions()) {
		return nil, process.ErrNilUnsignedTxDataPool
	}
	if check.IfNil(dataPool.MiniBlocks()) {
		return nil, process.ErrNilMiniBlockPool
	}
	if check.IfNil(shardCoordinator) {
		return nil, process.ErrNilShardCoordinator
	}
	if check.IfNil(whitelistHandler) {
		return nil, process.ErrNilWhiteListHandler
	}

	mbt := miniBlockTrack{
		blockTransactionsPool:    dataPool.Transactions(),
		rewardTransactionsPool:   dataPool.RewardTransactions(),
		unsignedTransactionsPool: dataPool.UnsignedTransactions(),
		miniBlocksPool:           dataPool.MiniBlocks(),
		shardCoordinator:         shardCoordinator,
		whitelistHandler:         whitelistHandler,
		requireConfirmation:      !check.IfNil(blockTracker),
		confirmedMiniBlocks:      make(map[string]confirmedMiniBlockInfo),
	}
	handlerID, err := core.UniqueIdentifierWithError()
	if err != nil {
		return nil, err
	}

	mbt.miniBlocksPool.RegisterHandler(mbt.receivedMiniBlock, handlerID)
	mbt.registerBlockTrackerHandlers(blockTracker)

	return &mbt, nil
}

func (mbt *miniBlockTrack) receivedMiniBlock(key []byte, value interface{}) {
	if key == nil {
		return
	}

	miniBlock, ok := value.(*block.MiniBlock)
	if !ok {
		log.Warn("miniBlockTrack.receivedMiniBlock", "error", process.ErrWrongTypeAssertion)
		return
	}

	log.Debug("received miniblock from network in block tracker",
		"hash", key,
		"sender", miniBlock.SenderShardID,
		"receiver", miniBlock.ReceiverShardID,
		"type", miniBlock.Type,
		"num txs", len(miniBlock.TxHashes))

	if miniBlock.SenderShardID == mbt.shardCoordinator.SelfId() {
		return
	}

	mbt.immunizeMiniBlock(key, miniBlock)
}

func (mbt *miniBlockTrack) getTransactionPool(mbType block.Type) dataRetriever.ShardedDataCacherNotifier {
	switch mbType {
	case block.TxBlock:
		return mbt.blockTransactionsPool
	case block.RewardsBlock:
		return mbt.rewardTransactionsPool
	case block.SmartContractResultBlock:
		return mbt.unsignedTransactionsPool
	}

	return nil
}

func (mbt *miniBlockTrack) registerBlockTrackerHandlers(blockTracker process.BlockTracker) {
	if check.IfNil(blockTracker) {
		return
	}

	if mbt.shardCoordinator.SelfId() == core.MetachainShardId {
		blockTracker.RegisterCrossNotarizedHeadersHandler(func(_ uint32, headers []data.HeaderHandler, _ [][]byte) {
			mbt.registerConfirmedMiniBlocks(headers)
		})
		return
	}

	blockTracker.RegisterFinalMetachainHeadersHandler(func(_ uint32, headers []data.HeaderHandler, _ [][]byte) {
		mbt.registerConfirmedMiniBlocks(headers)
	})
}

func (mbt *miniBlockTrack) registerConfirmedMiniBlocks(headers []data.HeaderHandler) {
	for _, header := range headers {
		mbt.registerConfirmedMiniBlocksForHeader(header)
	}
}

func (mbt *miniBlockTrack) registerConfirmedMiniBlocksForHeader(header data.HeaderHandler) {
	if check.IfNil(header) {
		return
	}

	switch typedHeader := header.(type) {
	case data.MetaHeaderHandler:
		mbt.registerFromMiniBlockHeaders(typedHeader.GetNonce(), core.MetachainShardId, typedHeader.GetMiniBlockHeaderHandlers())
		for _, shardInfo := range typedHeader.GetShardInfoHandlers() {
			mbt.registerFromMiniBlockHeaders(typedHeader.GetNonce(), shardInfo.GetShardID(), shardInfo.GetShardMiniBlockHeaderHandlers())
		}
	case data.ShardHeaderHandler:
		mbt.registerFromMiniBlockHeaders(typedHeader.GetNonce(), typedHeader.GetShardID(), typedHeader.GetMiniBlockHeaderHandlers())
	}
}

func (mbt *miniBlockTrack) registerFromMiniBlockHeaders(
	nonce uint64,
	processingShard uint32,
	miniBlockHeaders []data.MiniBlockHeaderHandler,
) {
	selfShardID := mbt.shardCoordinator.SelfId()
	for _, miniBlockHeader := range miniBlockHeaders {
		receiverShard := miniBlockHeader.GetReceiverShardID()
		receiverIsAllShardsMiniBlockFromMetaHeader := receiverShard == core.AllShardId && processingShard == core.MetachainShardId
		receiverIsRelevantForCurrentShard := receiverShard == selfShardID || receiverIsAllShardsMiniBlockFromMetaHeader
		senderShard := miniBlockHeader.GetSenderShardID()
		senderIsSelfShard := senderShard == selfShardID
		if !receiverIsRelevantForCurrentShard || senderIsSelfShard {
			continue
		}

		cacheID := process.ShardCacherIdentifier(senderShard, receiverShard)
		mbInfo := confirmedMiniBlockInfo{
			cacheID: cacheID,
			mbType:  block.Type(miniBlockHeader.GetTypeInt32()),
			nonce:   nonce,
		}

		transactionPool := mbt.getTransactionPool(mbInfo.mbType)
		if check.IfNil(transactionPool) {
			continue
		}

		mbt.storeConfirmedMiniBlockInfo(miniBlockHeader.GetHash(), mbInfo)
		mbt.tryProcessStoredMiniBlock(miniBlockHeader.GetHash())
	}
}

func (mbt *miniBlockTrack) tryProcessStoredMiniBlock(miniBlockHash []byte) {
	value, ok := mbt.miniBlocksPool.Peek(miniBlockHash)
	if !ok {
		return
	}

	miniBlock, ok := value.(*block.MiniBlock)
	if !ok {
		return
	}

	mbt.immunizeMiniBlock(miniBlockHash, miniBlock)
}

func (mbt *miniBlockTrack) immunizeMiniBlock(miniBlockHash []byte, miniBlock *block.MiniBlock) {
	transactionPool := mbt.getTransactionPool(miniBlock.Type)
	if check.IfNil(transactionPool) {
		return
	}

	confirmationInfo, ok := mbt.getConfirmedMiniBlockInfo(miniBlockHash)
	if !ok {
		if mbt.requireConfirmation {
			return
		}

		confirmationInfo = confirmedMiniBlockInfo{
			cacheID: process.ShardCacherIdentifier(miniBlock.SenderShardID, miniBlock.ReceiverShardID),
			mbType:  miniBlock.Type,
			nonce:   0,
		}
	}

	mbt.whitelistHandler.Add(miniBlock.TxHashes)
	transactionPool.ImmunizeSetOfDataAgainstEviction(miniBlock.TxHashes, confirmationInfo.cacheID, confirmationInfo.nonce)
	mbt.removeConfirmedMiniBlockInfo(miniBlockHash, confirmationInfo.nonce)
}

func (mbt *miniBlockTrack) storeConfirmedMiniBlockInfo(miniBlockHash []byte, info confirmedMiniBlockInfo) {
	mbt.mutConfirmedMiniBlocks.Lock()
	defer mbt.mutConfirmedMiniBlocks.Unlock()

	key := string(miniBlockHash)
	existingInfo, exists := mbt.confirmedMiniBlocks[key]
	if exists && existingInfo.nonce >= info.nonce {
		return
	}

	mbt.confirmedMiniBlocks[key] = info
}

func (mbt *miniBlockTrack) getConfirmedMiniBlockInfo(miniBlockHash []byte) (confirmedMiniBlockInfo, bool) {
	mbt.mutConfirmedMiniBlocks.RLock()
	defer mbt.mutConfirmedMiniBlocks.RUnlock()

	info, ok := mbt.confirmedMiniBlocks[string(miniBlockHash)]
	return info, ok
}

func (mbt *miniBlockTrack) removeConfirmedMiniBlockInfo(miniBlockHash []byte, nonce uint64) {
	mbt.mutConfirmedMiniBlocks.Lock()
	defer mbt.mutConfirmedMiniBlocks.Unlock()

	key := string(miniBlockHash)
	info, ok := mbt.confirmedMiniBlocks[key]
	if !ok {
		return
	}
	if info.nonce > nonce {
		return
	}

	delete(mbt.confirmedMiniBlocks, key)
}

// CleanupConfirmedMiniBlocksBelow drops every tracked confirmation whose nonce is strictly below threshold.
func (mbt *miniBlockTrack) CleanupConfirmedMiniBlocksBelow(threshold uint64) {
	mbt.mutConfirmedMiniBlocks.Lock()
	defer mbt.mutConfirmedMiniBlocks.Unlock()

	for key, info := range mbt.confirmedMiniBlocks {
		if info.nonce >= threshold {
			continue
		}

		delete(mbt.confirmedMiniBlocks, key)
	}
}

// CleanupConfirmedMiniBlocksBelowForCacheID drops every tracked confirmation whose cacheID matches and nonce is strictly below threshold.
func (mbt *miniBlockTrack) CleanupConfirmedMiniBlocksBelowForCacheID(cacheID string, threshold uint64) {
	mbt.mutConfirmedMiniBlocks.Lock()
	defer mbt.mutConfirmedMiniBlocks.Unlock()

	for key, info := range mbt.confirmedMiniBlocks {
		if info.cacheID != cacheID || info.nonce >= threshold {
			continue
		}

		delete(mbt.confirmedMiniBlocks, key)
	}
}

// ReleaseImmunityForCommittedMetaBlocks advances the immunity threshold across all pools.
func (mbt *miniBlockTrack) ReleaseImmunityForCommittedMetaBlocks(threshold uint64) {
	if !check.IfNil(mbt.blockTransactionsPool) {
		mbt.blockTransactionsPool.SetOldestImmuneNonceForAllCaches(threshold)
	}
	if !check.IfNil(mbt.rewardTransactionsPool) {
		mbt.rewardTransactionsPool.SetOldestImmuneNonceForAllCaches(threshold)
	}
	if !check.IfNil(mbt.unsignedTransactionsPool) {
		mbt.unsignedTransactionsPool.SetOldestImmuneNonceForAllCaches(threshold)
	}
	mbt.CleanupConfirmedMiniBlocksBelow(threshold)
}

// ReleaseImmunityForCommittedShardBlocks advances the immunity threshold for metachain-bound caches from senderShard.
func (mbt *miniBlockTrack) ReleaseImmunityForCommittedShardBlocks(senderShard uint32, threshold uint64) {
	cacheID := process.ShardCacherIdentifier(senderShard, core.MetachainShardId)
	if !check.IfNil(mbt.blockTransactionsPool) {
		mbt.blockTransactionsPool.SetOldestImmuneNonce(cacheID, threshold)
	}
	if !check.IfNil(mbt.rewardTransactionsPool) {
		mbt.rewardTransactionsPool.SetOldestImmuneNonce(cacheID, threshold)
	}
	if !check.IfNil(mbt.unsignedTransactionsPool) {
		mbt.unsignedTransactionsPool.SetOldestImmuneNonce(cacheID, threshold)
	}
	mbt.CleanupConfirmedMiniBlocksBelowForCacheID(cacheID, threshold)
}

// IsInterfaceNil returns true if the receiver is a nil interface
func (mbt *miniBlockTrack) IsInterfaceNil() bool {
	return mbt == nil
}
