package txcache

import (
	"time"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-storage-go/immunitycache"
	"github.com/multiversx/mx-chain-storage-go/types"

	"github.com/multiversx/mx-chain-go/common"
)

var _ types.Cacher = (*CrossTxCache)(nil)

// CrossTxCache holds cross-shard transactions (where destination == me)
type CrossTxCache struct {
	*immunitycache.ImmunityCache
	config ConfigDestinationMe
}

// NewCrossTxCache creates a new transactions cache
func NewCrossTxCache(config ConfigDestinationMe) (*CrossTxCache, error) {
	log.Debug("NewCrossTxCache", "config", config.String())

	err := config.verify()
	if err != nil {
		return nil, err
	}

	immunityCacheConfig := immunitycache.CacheConfig{
		Name:                        config.Name,
		NumChunks:                   config.NumChunks,
		MaxNumBytes:                 config.MaxNumBytes,
		MaxNumItems:                 config.MaxNumItems,
		NumItemsToPreemptivelyEvict: config.NumItemsToPreemptivelyEvict,
	}

	immunityCache, err := immunitycache.NewImmunityCache(immunityCacheConfig)
	if err != nil {
		return nil, err
	}

	cache := CrossTxCache{
		ImmunityCache: immunityCache,
		config:        config,
	}

	return &cache, nil
}

// ImmunizeTxsAgainstEviction marks items as non-evictable for the provided confirmation nonce
func (cache *CrossTxCache) ImmunizeTxsAgainstEviction(keys [][]byte, nonce uint64) {
	numNow, numFuture := cache.ImmunityCache.ImmunizeKeys(keys, nonce)
	log.Trace("CrossTxCache.ImmunizeTxsAgainstEviction",
		"name", cache.config.Name,
		"len(keys)", len(keys),
		"numNow", numNow,
		"numFuture", numFuture,
		"nonce", nonce,
	)
	cache.Diagnose(false)
}

// SetOldestImmuneNonce deactivates immunity below the provided nonce
func (cache *CrossTxCache) SetOldestImmuneNonce(nonce uint64) {
	cache.ImmunityCache.SetOldestImmuneNonce(nonce)
}

// AddTx adds a transaction in the cache
func (cache *CrossTxCache) AddTx(tx *WrappedTransaction) (has, added bool) {
	return cache.AddTxWithValidationReceipt(tx, nil)
}

// AddTxWithValidationReceipt adds a transaction and its optional opaque observation.
func (cache *CrossTxCache) AddTxWithValidationReceipt(tx *WrappedTransaction, receipt interface{}) (has, added bool) {
	log.Trace("CrossTxCache.AddTx", "name", cache.config.Name, "txHash", tx.TxHash)
	return cache.HasOrAdd(tx.TxHash, cachedTransactionValue(tx, receipt), int(tx.Size))
}

// GetByTxHash gets the transaction by hash
func (cache *CrossTxCache) GetByTxHash(txHash []byte) (*WrappedTransaction, bool) {
	tx, _, ok := cache.GetByTxHashWithValidationReceipt(txHash)
	return tx, ok
}

// GetByTxHashWithValidationReceipt reads the native entry and receipt together.
func (cache *CrossTxCache) GetByTxHashWithValidationReceipt(txHash []byte) (*WrappedTransaction, interface{}, bool) {
	item, ok := cache.ImmunityCache.Get(txHash)
	if !ok {
		return nil, nil, false
	}

	return unwrapCachedTransaction(item)
}

// Get returns the unwrapped payload of a TransactionWrapper
// Implemented for compatibility reasons (see txPoolsCleaner.go).
func (cache *CrossTxCache) Get(key []byte) (value interface{}, ok bool) {
	wrapped, ok := cache.GetByTxHash(key)
	if !ok {
		return nil, false
	}

	return wrapped.Tx, true
}

// Peek returns the unwrapped payload of a TransactionWrapper
// Implemented for compatibility reasons (see transactions.go, common.go).
func (cache *CrossTxCache) Peek(key []byte) (value interface{}, ok bool) {
	return cache.Get(key)
}

// RemoveTxByHash removes tx by hash
func (cache *CrossTxCache) RemoveTxByHash(txHash []byte) bool {
	log.Trace("CrossTxCache.RemoveTxByHash", "name", cache.config.Name, "txHash", txHash)
	return cache.RemoveWithResult(txHash)
}

// ForEachTransaction iterates over the transactions in the cache
func (cache *CrossTxCache) ForEachTransaction(function ForEachTransaction) {
	cache.ForEachTransactionWithValidationReceipt(func(key []byte, tx *WrappedTransaction, _ interface{}) {
		function(key, tx)
	})
}

// ForEachItem preserves the native item representation in ordinary iteration.
func (cache *CrossTxCache) ForEachItem(function types.ForEachItem) {
	cache.ImmunityCache.ForEachItem(func(key []byte, item interface{}) {
		if tx, _, ok := unwrapCachedTransaction(item); ok {
			item = tx
		}
		function(key, item)
	})
}

// ForEachTransactionWithValidationReceipt iterates over native entries with their receipts.
func (cache *CrossTxCache) ForEachTransactionWithValidationReceipt(function ForEachTransactionWithValidationReceipt) {
	cache.ImmunityCache.ForEachItem(func(key []byte, item interface{}) {
		tx, receipt, ok := unwrapCachedTransaction(item)
		if ok {
			function(key, tx, receipt)
		}
	})
}

// GetTransactionsPoolForSender returns an empty slice, only to respect the interface
// CrossTxCache does not support transaction selection (not applicable, since transactions are already half-executed),
// thus does not handle nonces, nonce gaps etc.
func (cache *CrossTxCache) GetTransactionsPoolForSender(_ string) []*WrappedTransaction {
	return make([]*WrappedTransaction, 0)
}

// OnProposedBlock does nothing (only to satisfy the interface)
func (cache *CrossTxCache) OnProposedBlock(_ []byte, _ data.BodyHandler, _ data.HeaderHandler, _ common.AccountNonceAndBalanceProvider, _ []byte) error {
	return nil
}

// OnBackfilledBlock does nothing (only to satisfy the interface)
func (cache *CrossTxCache) OnBackfilledBlock(_ []byte, _ data.BodyHandler, _ data.HeaderHandler) error {
	return nil
}

// OnExecutedBlock does nothing (only to satisfy the interface)
func (cache *CrossTxCache) OnExecutedBlock(data.HeaderHandler, []byte) error {
	return nil
}

// ResetTracker does nothing (only to satisfy the interface)
func (cache *CrossTxCache) ResetTracker() {}

// GetTrackerDiagnosis returns nil (only to satisfy the interface)
func (cache *CrossTxCache) GetTrackerDiagnosis() TrackerDiagnosis {
	return nil
}

// Cleanup does nothing (only to satisfy the interface)
func (cache *CrossTxCache) Cleanup(_ common.AccountNonceProvider, _ uint64, _ int, _ time.Duration) uint64 {
	return 0
}

// IsInterfaceNil returns true if there is no value under the interface
func (cache *CrossTxCache) IsInterfaceNil() bool {
	return cache == nil
}
