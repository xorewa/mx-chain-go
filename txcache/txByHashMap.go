package txcache

import (
	"unsafe"

	"github.com/multiversx/mx-chain-core-go/core/atomic"
	"github.com/multiversx/mx-chain-go/txcache/maps"
)

// ForEachTransactionWithValidationReceipt is an iterator over paired cache entries.
type ForEachTransactionWithValidationReceipt func(txHash []byte, tx *WrappedTransaction, receipt interface{})

// transactionWithValidationReceipt lives and is removed with its native cache entry.
type transactionWithValidationReceipt struct {
	tx      *WrappedTransaction
	receipt interface{}
}

// ValidationReceiptEntrySize is the extra cache-value size for a retained receipt.
const ValidationReceiptEntrySize = int64(unsafe.Sizeof(transactionWithValidationReceipt{}))

func cachedTransactionValue(tx *WrappedTransaction, receipt interface{}) interface{} {
	if receipt == nil {
		return tx
	}

	return &transactionWithValidationReceipt{tx: tx, receipt: receipt}
}

func unwrapCachedTransaction(value interface{}) (*WrappedTransaction, interface{}, bool) {
	switch item := value.(type) {
	case *WrappedTransaction:
		return item, nil, true
	case *transactionWithValidationReceipt:
		return item.tx, item.receipt, true
	default:
		return nil, nil, false
	}
}

// txByHashMap is a new map-like structure for holding and accessing transactions by txHash
type txByHashMap struct {
	backingMap *maps.ConcurrentMap
	counter    atomic.Counter
	numBytes   atomic.Counter
}

// newTxByHashMap creates a new TxByHashMap instance
func newTxByHashMap(nChunksHint uint32) *txByHashMap {
	backingMap := maps.NewConcurrentMap(nChunksHint)

	return &txByHashMap{
		backingMap: backingMap,
	}
}

// addTx adds a transaction to the map
func (txMap *txByHashMap) addTx(tx *WrappedTransaction) bool {
	return txMap.addTxWithValidationReceipt(tx, nil)
}

func (txMap *txByHashMap) addTxWithValidationReceipt(tx *WrappedTransaction, receipt interface{}) bool {
	added := txMap.backingMap.SetIfAbsent(string(tx.TxHash), cachedTransactionValue(tx, receipt))
	if added {
		txMap.counter.Increment()
		txMap.numBytes.Add(tx.Size)
	}

	return added
}

// removeTx removes a transaction from the map
func (txMap *txByHashMap) removeTx(txHash string) (*WrappedTransaction, bool) {
	item, removed := txMap.backingMap.Remove(txHash)
	if !removed {
		return nil, false
	}

	tx, _, ok := unwrapCachedTransaction(item)
	if !ok {
		return nil, false
	}

	txMap.counter.Decrement()
	txMap.numBytes.Subtract(tx.Size)

	return tx, true
}

// hasTx checks if a transaction exists in the map (without retrieving it)
func (txMap *txByHashMap) hasTx(txHash string) bool {
	return txMap.backingMap.Has(txHash)
}

// getTx gets a transaction from the map
func (txMap *txByHashMap) getTx(txHash string) (*WrappedTransaction, bool) {
	tx, _, ok := txMap.getTxWithValidationReceipt(txHash)
	return tx, ok
}

func (txMap *txByHashMap) getTxWithValidationReceipt(txHash string) (*WrappedTransaction, interface{}, bool) {
	item, ok := txMap.backingMap.Get(txHash)
	if !ok {
		return nil, nil, false
	}

	return unwrapCachedTransaction(item)
}

// GetTxsBulk gets a bulk of transactions from map
func (txMap *txByHashMap) GetTxsBulk(txHashes [][]byte) []*WrappedTransaction {
	txs := make([]*WrappedTransaction, 0, len(txHashes))
	for _, txHash := range txHashes {
		tx, ok := txMap.getTx(string(txHash))
		if !ok {
			continue
		}

		txs = append(txs, tx)
	}

	return txs
}

// RemoveTxsBulk removes transactions, in bulk
func (txMap *txByHashMap) RemoveTxsBulk(txHashes [][]byte) uint32 {
	numRemoved := uint32(0)

	for _, txHash := range txHashes {
		_, removed := txMap.removeTx(string(txHash))
		if removed {
			numRemoved++
		}
	}

	return numRemoved
}

// forEach iterates over the senders
func (txMap *txByHashMap) forEach(function ForEachTransaction) {
	txMap.forEachWithValidationReceipt(func(key []byte, tx *WrappedTransaction, _ interface{}) {
		function(key, tx)
	})
}

func (txMap *txByHashMap) forEachWithValidationReceipt(function ForEachTransactionWithValidationReceipt) {
	txMap.backingMap.IterCb(func(key string, item interface{}) {
		tx, receipt, ok := unwrapCachedTransaction(item)
		if ok {
			function([]byte(key), tx, receipt)
		}
	})
}

func (txMap *txByHashMap) clear() {
	txMap.backingMap.Clear()
	txMap.counter.Set(0)
}

func (txMap *txByHashMap) keys() [][]byte {
	keys := txMap.backingMap.Keys()
	keysAsBytes := make([][]byte, len(keys))
	for i := 0; i < len(keys); i++ {
		keysAsBytes[i] = []byte(keys[i])
	}

	return keysAsBytes
}
