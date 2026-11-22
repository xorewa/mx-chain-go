package transaction_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	nativeTransaction "github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/dataRetriever/txpool"
	"github.com/multiversx/mx-chain-go/p2p"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/interceptors/processor"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	cacheFixture "github.com/multiversx/mx-chain-go/testscommon/cache"
	"github.com/multiversx/mx-chain-go/testscommon/txcachemocks/mempool"
	"github.com/multiversx/mx-chain-go/txcache"
	"github.com/stretchr/testify/require"
)

// Called only with a real native signed/validated DRWA-routed control. Synthetic capacities
// and the gas-host fixture test cache mechanics, not economics or appointment.
type qualD19ReceiptPool interface {
	dataRetriever.ShardedDataCacherNotifier
	ConfigureNativeValidationSource(*transaction.NativeValidationSource) error
	NativeValidationReceiptEnabled() bool
	AddData([]byte, interface{}, int, string)
	AddDataWithNativeValidationReceipt([]byte, interface{}, int, string, *transaction.NativeValidationReceipt)
	NativeValidationReceiptFor([]byte, string, *nativeTransaction.Transaction) *transaction.NativeValidationReceipt
	SearchFirstData([]byte) (interface{}, bool)
	RemoveData([]byte, string)
	MergeShardStores(string, string)
	ShardDataStore(string) storage.Cacher
	RegisterOnAdded(func([]byte, interface{}))
	Clear()
}

type qualD19ReceiptCountingProducer struct {
	*transaction.InterceptedTransaction
	receipts     int
	requirements int
}

func (p *qualD19ReceiptCountingProducer) RequiresDRWANativeValidationReceipt() bool {
	p.requirements++
	return p.InterceptedTransaction.RequiresDRWANativeValidationReceipt()
}

func (p *qualD19ReceiptCountingProducer) NativeValidationReceipt() *transaction.NativeValidationReceipt {
	p.receipts++
	return p.InterceptedTransaction.NativeValidationReceipt()
}

func qualD19ReceiptTransport(t *testing.T, source transaction.NativeValidationSource, inTx *transaction.InterceptedTransaction) {
	t.Helper()
	newPool := func(byteLimit ...uint64) qualD19ReceiptPool {
		fixtureBytes := uint64(409600)
		if len(byteLimit) != 0 {
			fixtureBytes = byteLimit[0]
		}
		pool, err := txpool.NewShardedTxPool(txpool.ArgShardedTxPool{
			Config:      storageunit.CacheConfig{Capacity: 100, SizePerSender: 10, SizeInBytes: fixtureBytes, SizeInBytesPerSender: 40960, Shards: 1},
			Marshalizer: source.ProtoMarshalizer, TxGasHandler: mempool.NewTxGasHandlerMock(), NumberOfShards: 3,
			TxCacheBoundsConfig: config.TxCacheBoundsConfig{MaxNumBytesPerSenderUpperBound: 33554432, MaxTrackedBlocks: 100},
		})
		require.NoError(t, err)
		t.Cleanup(pool.Clear)
		return pool
	}
	tx := inTx.Transaction().(*nativeTransaction.Transaction)
	key := bytes.Clone(inTx.Hash())
	receipt := inTx.NativeValidationReceipt()
	require.NotNil(t, receipt)
	retainedCharge := receipt.RetainedSize() + int64(cap(bytes.Clone(key)))
	require.Greater(t, receipt.RetainedSize(), int64(len(receipt.OriginalBytes())+len(receipt.InnerBytes())+len(receipt.Hash())))
	t.Run("native-whitelist-denial", func(t *testing.T) {
		// This stub changes only the native whitelist decision. It cannot
		// replace the real signature validation that supplied inTx above.
		for _, configured := range []bool{false, true} {
			for _, method := range []p2p.BroadcastMethod{p2p.Direct, p2p.Broadcast} {
				pool := newPool()
				require.NoError(t, pool.ConfigureNativeValidationSource(nil))
				require.False(t, pool.NativeValidationReceiptEnabled())
				if configured {
					require.NoError(t, pool.ConfigureNativeValidationSource(&source))
				}
				producer := &qualD19ReceiptCountingProducer{InterceptedTransaction: inTx}
				rejected := true
				callbacks, directWrites, broadcastRemovals := 0, 0, 0
				pool.RegisterOnAdded(func(_ []byte, _ interface{}) { callbacks++ })
				save, err := processor.NewTxInterceptorProcessor(&processor.ArgTxInterceptorProcessor{
					ShardedDataCache: pool,
					TxValidator: &mock.TxValidatorStub{CheckTxWhiteListCalled: func(process.InterceptedData) error {
						if rejected {
							return errors.New("synthetic native whitelist refusal")
						}
						return nil
					}},
					DirectSentTransactionsCache: &cacheFixture.CacherStub{
						PutCalled:    func([]byte, interface{}, int) bool { directWrites++; return false },
						RemoveCalled: func([]byte) { broadcastRemovals++ },
					},
				})
				require.NoError(t, err)
				stored, err := save.Save(producer, "", "", method)
				require.NoError(t, err)
				require.False(t, stored)
				require.Zero(t, producer.receipts)
				require.Zero(t, producer.requirements)
				require.Zero(t, callbacks)
				require.Zero(t, directWrites)
				require.Zero(t, broadcastRemovals)
				_, found := pool.SearchFirstData(key)
				require.False(t, found)
				// Restore only the policy decision; all signed bytes, configured
				// dependencies, native pool and Save consumer remain identical.
				rejected = false
				stored, err = save.Save(producer, "", "", method)
				require.NoError(t, err)
				require.True(t, stored)
				actual, found := pool.SearchFirstData(key)
				require.True(t, found)
				require.Same(t, tx, actual)
				require.Equal(t, 1, callbacks)
				wantReceipts := 0
				if configured {
					wantReceipts = 1
				}
				require.Equal(t, wantReceipts, producer.receipts)
				require.Equal(t, wantReceipts, producer.requirements)
				wantDirect, wantBroadcast := 0, 0
				if inTx.SenderShardId() == inTx.ReceiverShardId() {
					if method == p2p.Direct {
						wantDirect = 1
					} else {
						wantBroadcast = 1
					}
				}
				require.Equal(t, wantDirect, directWrites)
				require.Equal(t, wantBroadcast, broadcastRemovals)
			}
		}
	})
	t.Run("native-save", func(t *testing.T) {
		// The whitelist stub isolates Save routing; it is not the signer.
		// Only the already real-crypto-validated input above can supply a seal.
		producer := &qualD19ReceiptCountingProducer{InterceptedTransaction: inTx}
		route := process.ShardCacherIdentifier(inTx.SenderShardId(), inTx.ReceiverShardId())
		for _, configured := range []bool{false, true} {
			pool := newPool()
			if configured {
				require.NoError(t, pool.ConfigureNativeValidationSource(&source))
			}
			save, err := processor.NewTxInterceptorProcessor(&processor.ArgTxInterceptorProcessor{
				ShardedDataCache: pool, TxValidator: &mock.TxValidatorStub{}, DirectSentTransactionsCache: &cacheFixture.CacherStub{},
			})
			require.NoError(t, err)
			stored, err := save.Save(producer, "", "", p2p.Broadcast)
			require.NoError(t, err)
			require.True(t, stored)
			if configured {
				require.Equal(t, 1, producer.receipts)
				require.NotNil(t, pool.NativeValidationReceiptFor(key, route, tx))
			} else {
				require.Zero(t, producer.receipts, "unconfigured Save does not request or allocate a receipt")
				require.Zero(t, producer.requirements, "unconfigured Save does not invoke the optional route predicate")
				require.Nil(t, pool.NativeValidationReceiptFor(key, route, tx))
			}
		}
	})
	for _, route := range []string{"0_0", "1_0"} {
		t.Run("cache-transport-"+route, func(t *testing.T) {
			ordinary := newPool()
			require.False(t, ordinary.NativeValidationReceiptEnabled())
			ordinary.AddDataWithNativeValidationReceipt(key, tx, tx.Size(), route, receipt)
			base, exists := ordinary.SearchFirstData(key)
			require.True(t, exists)
			require.Same(t, tx, base)
			require.Nil(t, ordinary.NativeValidationReceiptFor(key, route, tx))
			getWrapped := func(pool qualD19ReceiptPool, cacheID string) *txcache.WrappedTransaction {
				cache := pool.ShardDataStore(cacheID).(interface {
					GetByTxHash([]byte) (*txcache.WrappedTransaction, bool)
				})
				wrapped, found := cache.GetByTxHash(key)
				require.True(t, found)
				return wrapped
			}
			require.Equal(t, int64(tx.Size()), getWrapped(ordinary, route).Size)
			require.Nil(t, getWrapped(ordinary, route).DRWAValidationReceipt)

			// A configured pool still inserts an ordinary native entry when
			// there is no observation for this transaction. Inspect the raw
			// cache entry and charge before the later lookup can reject it.
			unobserved := newPool()
			require.NoError(t, unobserved.ConfigureNativeValidationSource(&source))
			unobserved.AddDataWithNativeValidationReceipt(key, tx, tx.Size(), route, nil)
			entry := getWrapped(unobserved, route)
			require.Same(t, tx, entry.Tx)
			require.True(t, entry.DRWAValidationReceipt == nil, "unobserved entry has no receipt field")
			require.Equal(t, int64(tx.Size()), entry.Size, "native insertion charges no retained observation or key copy")
			accounting := unobserved.ShardDataStore(route).(interface{ NumBytes() int })
			require.Equal(t, tx.Size(), accounting.NumBytes())

			pool := newPool()
			require.NoError(t, pool.ConfigureNativeValidationSource(&source))
			require.Error(t, pool.ConfigureNativeValidationSource(&source), "source cannot be replaced underneath retained receipts")
			var callbacksMu sync.Mutex
			var callbacks []*txcache.WrappedTransaction
			pool.RegisterOnAdded(func(_ []byte, value interface{}) {
				callbacksMu.Lock()
				callbacks = append(callbacks, value.(*txcache.WrappedTransaction))
				callbacksMu.Unlock()
			})
			providedKey := bytes.Clone(key)
			pool.AddDataWithNativeValidationReceipt(providedKey, tx, tx.Size(), route, receipt)
			wrapped := getWrapped(pool, route)
			providedKey[0] ^= 1
			require.Equal(t, key, wrapped.TxHash, "cache metadata owns its immutable key snapshot")
			byteCount := func(cacheID string) int {
				return pool.ShardDataStore(cacheID).(interface{ NumBytes() int }).NumBytes()
			}
			require.Same(t, tx, wrapped.Tx)
			require.Same(t, receipt, pool.NativeValidationReceiptFor(key, route, tx))
			require.Equal(t, int64(tx.Size())+retainedCharge, wrapped.Size)
			require.Equal(t, int(wrapped.Size), byteCount(route), "native accounting includes the retained observation")
			require.Len(t, callbacks, 1)
			require.Same(t, wrapped, callbacks[0])
			copyTx := *tx
			require.Nil(t, pool.NativeValidationReceiptFor(key, route, &copyTx), "another object is not this cache entry")
			wrongKey := bytes.Clone(key)
			wrongKey[0] ^= 1
			require.Nil(t, pool.NativeValidationReceiptFor(wrongKey, route, tx))
			tx.Nonce++
			require.Nil(t, pool.NativeValidationReceiptFor(key, route, tx))
			tx.Nonce--
			require.Same(t, receipt, pool.NativeValidationReceiptFor(key, route, tx), "restored real signed control")
			wrapped.TxHash[0] ^= 1
			require.Nil(t, pool.NativeValidationReceiptFor(key, route, tx), "a substituted cache-item hash is not the signed input")
			wrapped.TxHash[0] ^= 1
			require.Same(t, receipt, pool.NativeValidationReceiptFor(key, route, tx))
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); pool.AddDataWithNativeValidationReceipt(key, tx, tx.Size(), route, receipt) }()
			}
			wg.Wait()
			require.Same(t, wrapped, getWrapped(pool, route), "native duplicate retains the original item")
			require.Len(t, callbacks, 1)
			pool.RemoveData(key, route)
			require.Zero(t, byteCount(route), "native removal releases the same byte charge")
			require.Nil(t, pool.NativeValidationReceiptFor(key, route, tx))
			pool.AddData(key, tx, tx.Size(), route)
			require.Nil(t, pool.NativeValidationReceiptFor(key, route, tx), "plain re-insertion cannot inherit the removed seal")
			pool.RemoveData(key, route)
			pool.AddDataWithNativeValidationReceipt(key, tx, tx.Size(), route, receipt)
			if route == "1_0" {
				beforeMerge := getWrapped(pool, route)
				pool.MergeShardStores(route, "2_0")
				require.Same(t, beforeMerge, getWrapped(pool, "2_0"))
				require.Equal(t, int(beforeMerge.Size), byteCount("2_0"))
				require.Same(t, receipt, pool.NativeValidationReceiptFor(key, "2_0", tx))
				require.Nil(t, pool.NativeValidationReceiptFor(key, route, tx))
			}
		})
	}
	t.Run("native-byte-eviction", func(t *testing.T) {
		charged := int64(tx.Size()) + retainedCharge
		// The existing pool reserves half for cross-shard caches and divides
		// that half between two sender shards. This fixture makes that native
		// byte threshold one byte below the observed entry's derived charge.
		// Native immunitycache checks existing capacity BEFORE the next add.
		pool := newPool(uint64(4 * (charged - 1)))
		require.NoError(t, pool.ConfigureNativeValidationSource(&source))
		pool.AddDataWithNativeValidationReceipt(key, tx, tx.Size(), "1_0", receipt)
		require.Same(t, receipt, pool.NativeValidationReceiptFor(key, "1_0", tx))
		pool.AddData([]byte("synthetic-next-cache-item"), tx, tx.Size(), "1_0")
		require.Nil(t, pool.NativeValidationReceiptFor(key, "1_0", tx))
		_, found := pool.SearchFirstData(key)
		require.False(t, found, "the receipt shares the original entry's native eviction")
	})
	for _, mutation := range []string{"nil-seal", "zero-seal", "changed-body", "wrong-hash", "foreign-source"} {
		t.Run(mutation, func(t *testing.T) {
			pool := newPool()
			selectedSource := source
			selectedTx := tx
			selectedKey := bytes.Clone(key)
			selectedReceipt := receipt
			switch mutation {
			case "nil-seal":
				selectedReceipt = nil
			case "zero-seal":
				selectedReceipt = &transaction.NativeValidationReceipt{}
			case "changed-body":
				copyTx := *tx
				copyTx.Nonce++
				selectedTx = &copyTx
			case "wrong-hash":
				selectedKey[0] ^= 1
			case "foreign-source":
				selectedSource.Signer = nil
			}
			require.NoError(t, pool.ConfigureNativeValidationSource(&selectedSource))
			pool.AddDataWithNativeValidationReceipt(selectedKey, selectedTx, selectedTx.Size(), "0_0", selectedReceipt)
			require.Nil(t, pool.NativeValidationReceiptFor(selectedKey, "0_0", selectedTx))
			stored, found := pool.SearchFirstData(selectedKey)
			require.True(t, found, "static-metadata rejection does not replace native transaction policy")
			require.Same(t, selectedTx, stored)
		})
	}
	t.Run("drwa-receipt-transport-preserves-native-fields", func(t *testing.T) {
		for _, route := range []string{"0_0", "1_0"} {
			ordinary, configured := newPool(), newPool()
			require.NoError(t, configured.ConfigureNativeValidationSource(&source))
			for _, step := range []string{"insert", "duplicate", "remove", "reinsert", "clear", "reinsert-after-clear"} {
				for _, pool := range []qualD19ReceiptPool{ordinary, configured} {
					switch step {
					case "remove":
						pool.RemoveData(key, route)
					case "clear":
						pool.Clear()
					default:
						pool.AddDataWithNativeValidationReceipt(key, tx, tx.Size(), route, receipt)
					}
				}
				type nativeView struct {
					Found            bool
					Tx               interface{}
					Hash, FeePayer   []byte
					Sender, Receiver uint32
					Fee, Value       string
					Price            uint64
					Count            int
				}
				view := func(pool qualD19ReceiptPool) nativeView {
					cache := pool.ShardDataStore(route).(interface {
						GetByTxHash([]byte) (*txcache.WrappedTransaction, bool)
						Len() int
					})
					item, found := cache.GetByTxHash(key)
					v := nativeView{Found: found, Count: cache.Len()}
					if !found {
						return v
					}
					v.Tx, v.Hash, v.FeePayer = item.Tx, bytes.Clone(item.TxHash), bytes.Clone(item.FeePayer)
					v.Sender, v.Receiver, v.Price = item.SenderShardID, item.ReceiverShardID, item.PricePerUnit
					if item.Fee != nil {
						v.Fee = item.Fee.String()
					}
					if item.TransferredValue != nil {
						v.Value = item.TransferredValue.String()
					}
					return v
				}
				a, b := view(ordinary), view(configured)
				require.Equal(t, a, b, "native observable cache/fee/routing fields: route=%s step=%s", route, step)
				wantPresent := step != "remove" && step != "clear"
				require.Equal(t, wantPresent, a.Found)
				if wantPresent {
					// DRWA traffic retains a fully charged observation. Ordinary
					// equality separately includes Size/NumBytes, eviction and native work.
					for i, pool := range []qualD19ReceiptPool{ordinary, configured} {
						cache := pool.ShardDataStore(route).(interface {
							GetByTxHash([]byte) (*txcache.WrappedTransaction, bool)
							NumBytes() int
						})
						entry, exists := cache.GetByTxHash(key)
						require.True(t, exists)
						charge := int64(tx.Size())
						if i == 1 {
							charge += retainedCharge
						}
						require.Equal(t, charge, entry.Size)
						require.Equal(t, int(charge), cache.NumBytes())
					}
					require.Same(t, tx, a.Tx)
					require.Equal(t, 1, a.Count)
					require.NotNil(t, configured.NativeValidationReceiptFor(key, route, tx))
				} else {
					require.Zero(t, a.Count)
					require.Nil(t, configured.NativeValidationReceiptFor(key, route, tx))
				}
				require.Nil(t, ordinary.NativeValidationReceiptFor(key, route, tx))
			}
		}
	})
	t.Run("native-clear-accounting", func(t *testing.T) {
		for _, configured := range []bool{false, true} {
			pool := newPool()
			if configured {
				require.NoError(t, pool.ConfigureNativeValidationSource(&source))
			}
			pool.AddDataWithNativeValidationReceipt(key, tx, tx.Size(), "0_0", receipt)
			cache := pool.ShardDataStore("0_0").(interface {
				NumBytes() int
				Len() int
			})
			before := cache.NumBytes()
			require.Positive(t, before)
			wantCharge := int64(tx.Size())
			if configured {
				wantCharge += retainedCharge
			}
			require.Equal(t, int(wantCharge), before)
			pool.ClearShardStore("0_0")
			require.Zero(t, cache.Len())
			require.Nil(t, pool.NativeValidationReceiptFor(key, "0_0", tx))
			t.Logf("configured=%t before_bytes=%d after_clear_bytes=%d retained_entries=%d", configured, before, cache.NumBytes(), cache.Len())
			// Untouched node 9e22a9f8a362 clears membership, but preserves
			// this cache's approximate byte counter. Receipt transport must
			// not introduce an ordinary-path accounting repair.
			require.Equal(t, before, cache.NumBytes())
			pool.AddDataWithNativeValidationReceipt(key, tx, tx.Size(), "0_0", receipt)
			require.Equal(t, 1, cache.Len())
			require.Equal(t, 2*int(wantCharge), cache.NumBytes())
			pool.ClearShardStore("0_0")
			var pending sync.WaitGroup
			for worker := 0; worker < 8; worker++ {
				pending.Add(1)
				go func() {
					defer pending.Done()
					for iteration := 0; iteration < 16; iteration++ {
						pool.AddDataWithNativeValidationReceipt(key, tx, tx.Size(), "0_0", receipt)
						pool.ClearShardStore("0_0")
					}
				}()
			}
			pending.Wait()
			pool.ClearShardStore("0_0")
			require.Zero(t, cache.Len())
			require.Nil(t, pool.NativeValidationReceiptFor(key, "0_0", tx))
			// Membership, not a reset approximate counter, bounds access to
			// retained observations. Concurrent adds/clears preserve native
			// accounting; this does not qualify a native counter repair.
			require.GreaterOrEqual(t, cache.NumBytes(), 2*int(wantCharge))
			require.Zero(t, cache.NumBytes()%int(wantCharge))
		}
	})
}
