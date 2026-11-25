package transaction_test

import (
	"bytes"
	"github.com/multiversx/mx-chain-core-go/core"
	"reflect"
	"sync/atomic"
	"testing"

	dataTransaction "github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever/txpool"
	"github.com/multiversx/mx-chain-go/p2p"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/interceptors/processor"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	cacheFixture "github.com/multiversx/mx-chain-go/testscommon/cache"
	"github.com/multiversx/mx-chain-go/testscommon/txcachemocks/mempool"
	"github.com/multiversx/mx-chain-go/txcache"
	"github.com/stretchr/testify/require"
)

// Delegating native providers count actual work; they never replace native
// encoding, hashing or cryptography with an accepting result.
type qualReceiptCountingMarshalizer struct {
	marshal.Marshalizer
	encodes, decodes atomic.Int64
}

func (m *qualReceiptCountingMarshalizer) Marshal(value interface{}) ([]byte, error) {
	m.encodes.Add(1)
	return m.Marshalizer.Marshal(value)
}
func (m *qualReceiptCountingMarshalizer) Unmarshal(value interface{}, raw []byte) error {
	m.decodes.Add(1)
	return m.Marshalizer.Unmarshal(value, raw)
}

type qualReceiptCountingHasher struct {
	hashing.Hasher
	calls atomic.Int64
}

func (h *qualReceiptCountingHasher) Compute(raw string) []byte {
	h.calls.Add(1)
	return h.Hasher.Compute(raw)
}

type qualReceiptWorkCount [6]int64

func (a qualReceiptWorkCount) subtract(b qualReceiptWorkCount) qualReceiptWorkCount {
	for i := range a {
		a[i] -= b[i]
	}
	return a
}
func qualReceiptWork(source transaction.NativeValidationSource) qualReceiptWorkCount {
	p := source.ProtoMarshalizer.(*qualReceiptCountingMarshalizer)
	s := source.SignMarshalizer.(*qualReceiptCountingMarshalizer)
	h := source.Hasher.(*qualReceiptCountingHasher)
	sh := source.TxSignHasher.(*qualReceiptCountingHasher)
	return qualReceiptWorkCount{p.encodes.Load(), p.decodes.Load(), s.encodes.Load(), s.decodes.Load(), h.calls.Load(), sh.calls.Load()}
}

// The successful storage/direct-cache branch of pinned node 9e22a9f8a362
// TxInterceptorProcessor.Save, after its independently controlled whitelist
// check. It deliberately calls native AddData rather than current Save, so
// ON and OFF cannot conceal a common extra-work/receipt-routing regression.
func qualPinnedOrdinarySave(pool qualD19ReceiptPool, in *transaction.InterceptedTransaction, direct *cacheFixture.CacherStub, method p2p.BroadcastMethod) {
	route := process.ShardCacherIdentifier(in.SenderShardId(), in.ReceiverShardId())
	pool.AddData(in.Hash(), in.Transaction(), in.Transaction().Size(), route)
	if in.SenderShardId() == in.ReceiverShardId() {
		if method == p2p.Direct {
			direct.Put(in.Hash(), struct{}{}, 0)
		}
		if method == p2p.Broadcast {
			direct.Remove(in.Hash())
		}
	}
}

// Real signed ordinary transactions, identical streams and limits, native
// cache/Save implementations. Capacities below are SYNTHETIC boundary fixtures,
// not production profile defaults or qualified economics/authority inputs.
func qualOrdinaryPoolReceiptEquivalence(t *testing.T, source transaction.NativeValidationSource, original *transaction.InterceptedTransaction, key crypto.PrivateKey) {
	t.Helper()
	t.Run("ordinary-pool-on-off", func(t *testing.T) {
		var stream []*transaction.InterceptedTransaction
		for nonce := uint64(100); nonce < 108; nonce++ {
			tx := *original.Transaction().(*dataTransaction.Transaction)
			tx.Nonce = nonce
			signed, err := tx.GetDataForSigning(source.Converter, source.SignMarshalizer, source.TxSignHasher)
			require.NoError(t, err)
			tx.Signature, err = source.Signer.Sign(key, signed)
			require.NoError(t, err)
			raw, err := source.ProtoMarshalizer.Marshal(&tx)
			require.NoError(t, err)
			in, err := transaction.NewInterceptedTransaction(raw, source.ProtoMarshalizer, source.SignMarshalizer, source.Hasher,
				source.KeyGen, source.Signer, source.Converter, source.Coordinator, source.FeeHandler, source.VerifiedTransactions,
				source.ArgsParser, []byte(source.ChainID), source.EnableSignedTxWithHash, source.TxSignHasher, source.VersionChecker, source.EnableEpochsHandler)
			require.NoError(t, err)
			require.NoError(t, in.CheckValidity())
			stream = append(stream, in)
		}
		receipts := make([]*transaction.NativeValidationReceipt, len(stream))
		for i, in := range stream {
			receipts[i] = in.NativeValidationReceipt()
			require.NotNil(t, receipts[i])
		}
		size := stream[0].Transaction().Size()
		for _, in := range stream {
			require.Equal(t, size, in.Transaction().Size())
		}
		route := process.ShardCacherIdentifier(original.SenderShardId(), original.ReceiverShardId())
		type observation struct {
			Found                                      []bool
			Size                                       []int64
			Bytes, Count, Callbacks, Direct, Broadcast int
			Stored                                     bool
			Work                                       qualReceiptWorkCount
		}
		type fixture struct {
			pool                                       qualD19ReceiptPool
			save                                       *processor.TxInterceptorProcessor
			direct                                     *cacheFixture.CacherStub
			callbacks, directWrites, broadcastRemovals int
		}
		for _, limit := range []struct {
			name  string
			bytes uint64
			count uint32
		}{
			{"byte-below", uint64(4*size - 1), 100},
			{"byte-equal", uint64(4 * size), 100},
			{"byte-above", uint64(4*size + 1), 100},
			{"count", 409600, 4},
		} {
			t.Run(limit.name, func(t *testing.T) {
				modes := make([]*fixture, 4)
				for mode := range modes {
					f := &fixture{}
					pool, err := txpool.NewShardedTxPool(txpool.ArgShardedTxPool{
						Config:      storageunit.CacheConfig{Capacity: 2 * limit.count, SizePerSender: 16, SizeInBytes: 2 * limit.bytes, SizeInBytesPerSender: 409600, Shards: 1},
						Marshalizer: source.ProtoMarshalizer, TxGasHandler: mempool.NewTxGasHandlerMock(), NumberOfShards: 3, SelfShardID: original.SenderShardId(),
						TxCacheBoundsConfig: config.TxCacheBoundsConfig{MaxNumBytesPerSenderUpperBound: 33554432, MaxTrackedBlocks: 100},
					})
					require.NoError(t, err)
					f.pool = pool
					t.Cleanup(pool.Clear)
					if mode >= 2 {
						require.NoError(t, pool.ConfigureNativeValidationSource(&source))
					}
					pool.RegisterOnAdded(func([]byte, interface{}) { f.callbacks++ })
					f.direct = &cacheFixture.CacherStub{PutCalled: func([]byte, interface{}, int) bool { f.directWrites++; return false }, RemoveCalled: func([]byte) { f.broadcastRemovals++ }}
					f.save, err = processor.NewTxInterceptorProcessor(&processor.ArgTxInterceptorProcessor{ShardedDataCache: pool, TxValidator: &mock.TxValidatorStub{}, DirectSentTransactionsCache: f.direct})
					require.NoError(t, err)
					modes[mode] = f
				}
				sawEviction := false
				for step := 0; step < 14; step++ {
					views := make([]observation, 4)
					for mode, f := range modes {
						before := qualReceiptWork(source)
						stored := true
						if step < 8 || step == 8 || step == 10 || step == 12 || step == 13 {
							index := step
							if index > 7 {
								index = 7
							}
							method := p2p.Broadcast
							if step == 8 {
								method = p2p.Direct
							}
							if mode == 0 {
								qualPinnedOrdinarySave(f.pool, stream[index], f.direct, method)
							} else if mode == 3 {
								in := stream[index]
								f.pool.AddDataWithNativeValidationReceipt(in.Hash(), in.Transaction(), in.Transaction().Size(), route, receipts[index])
								if in.SenderShardId() == in.ReceiverShardId() {
									if method == p2p.Direct {
										f.direct.Put(in.Hash(), struct{}{}, 0)
									}
									if method == p2p.Broadcast {
										f.direct.Remove(in.Hash())
									}
								}
							} else {
								var err error
								stored, err = f.save.Save(stream[index], "", "", method)
								require.NoError(t, err)
							}
						} else if step == 9 {
							f.pool.RemoveData(stream[7].Hash(), route)
						} else if step == 11 {
							f.pool.ShardDataStore(route).Clear()
						}
						cache := f.pool.ShardDataStore(route).(interface {
							GetByTxHashWithValidationReceipt([]byte) (*txcache.WrappedTransaction, interface{}, bool)
							NumBytes() int
							Len() int
						})
						v := observation{Bytes: cache.NumBytes(), Count: cache.Len(), Callbacks: f.callbacks, Direct: f.directWrites, Broadcast: f.broadcastRemovals, Stored: stored, Work: qualReceiptWork(source).subtract(before)}
						for _, in := range stream {
							tx, metadata, found := cache.GetByTxHashWithValidationReceipt(in.Hash())
							v.Found = append(v.Found, found)
							if found {
								v.Size = append(v.Size, tx.Size)
								if metadata != nil {
									t.Errorf("ordinary receipt retained: mode=%d step=%d", mode, step)
								}
							} else {
								v.Size = append(v.Size, 0)
							}
						}
						views[mode] = v
					}
					require.Equal(t, qualReceiptWorkCount{}, views[0].Work, "pinned native Save performs no extra codec/hash work")
					if step == 0 {
						t.Logf("ordinary first entry: byte_limit=%d count_limit=%d baseline_size=%d off_size=%d on_size=%d direct_pool_size=%d baseline_bytes=%d off_bytes=%d on_bytes=%d work_baseline=%v work_off=%v work_on=%v work_pool=%v", limit.bytes, limit.count, views[0].Size[0], views[1].Size[0], views[2].Size[0], views[3].Size[0], views[0].Bytes, views[1].Bytes, views[2].Bytes, views[0].Work, views[1].Work, views[2].Work, views[3].Work)
					}
					// One sender, untracked entries, native pre-add capacity check:
					// equality is admitted; an already-exceeded limit evicts the
					// prior bunch before the next insert. Expectations are derived
					// from pinned eviction.go, not a second candidate execution.
					if step == 3 {
						require.Equal(t, 4, views[0].Count)
					}
					if step == 4 || step == 5 {
						want := 5
						if step == 5 {
							want = 1
						}
						if limit.name == "byte-below" {
							want = step - 3
						}
						require.Equal(t, want, views[0].Count)
						require.Equal(t, want*size, views[0].Bytes)
						for index, present := range views[0].Found {
							first := 0
							if step == 5 || limit.name == "byte-below" {
								first = step - want + 1
							}
							require.Equal(t, index >= first && index <= step, present)
						}
						t.Logf("ordinary boundary step=%d victims/membership baseline=%v off=%v on=%v direct_pool=%v bytes=%d/%d/%d/%d", step, views[0].Found, views[1].Found, views[2].Found, views[3].Found, views[0].Bytes, views[1].Bytes, views[2].Bytes, views[3].Bytes)
					}
					for mode := 1; mode < len(modes); mode++ {
						if !reflect.DeepEqual(views[0], views[mode]) {
							t.Errorf("mode=%d step=%d baseline=%+v actual=%+v", mode, step, views[0], views[mode])
						}
					}
					if step > 0 && step < 8 && views[0].Count < step+1 {
						sawEviction = true
					}
				}
				require.True(t, sawEviction, "the boundary stream must actually exercise native eviction")
			})
		}
	})
}

// Separately native-signed DRWA-routed control. Dummy arguments supply no
// authority, original G6, canonical intent, profile, funding or execution.
func qualD19RegistrationControl(t *testing.T, source transaction.NativeValidationSource, original *transaction.InterceptedTransaction, key crypto.PrivateKey) *transaction.InterceptedTransaction {
	t.Helper()
	tx := *original.Transaction().(*dataTransaction.Transaction)
	tx.RcvAddr = bytes.Clone(core.ESDTSCAddress)
	tx.Data = []byte("DRWARegisterToken@00@00")
	tx.GasLimit = source.FeeHandler.ComputeGasLimit(&tx)
	message, err := tx.GetDataForSigning(source.Converter, source.SignMarshalizer, source.TxSignHasher)
	require.NoError(t, err)
	tx.Signature, err = source.Signer.Sign(key, message)
	require.NoError(t, err)
	raw, err := source.ProtoMarshalizer.Marshal(&tx)
	require.NoError(t, err)
	in, err := transaction.NewInterceptedTransaction(raw, source.ProtoMarshalizer, source.SignMarshalizer, source.Hasher, source.KeyGen, source.Signer, source.Converter, source.Coordinator, source.FeeHandler, source.VerifiedTransactions, source.ArgsParser, []byte(source.ChainID), source.EnableSignedTxWithHash, source.TxSignHasher, source.VersionChecker, source.EnableEpochsHandler)
	require.NoError(t, err)
	require.NoError(t, in.CheckValidity())
	require.True(t, in.RequiresDRWANativeValidationReceipt())
	return in
}

func TestQualOrdinaryReceiptRouteMatchesNativeDispatch(t *testing.T) {
	for _, tc := range []struct {
		data     string
		receiver []byte
		wanted   bool
	}{
		{"DRWARegisterToken@00@00", core.ESDTSCAddress, true},
		{"DRWARegisterBootstrapIntent@00", core.ESDTSCAddress, true},
		{"DRWARegisterTokenSuffix@00", core.ESDTSCAddress, false},
		{"ordinary@DRWARegisterToken", core.ESDTSCAddress, false},
		{"DRWARegisterToken", []byte("ordinary receiver"), false},
		{"DRWARegisterToken", nil, false},
		{"", core.ESDTSCAddress, false},
		{"DRWAInstallInitialProgrammeAuthorities", core.ESDTSCAddress, false},
	} {
		require.Equal(t, tc.wanted, transaction.RequiresDRWANativeValidationReceipt(&dataTransaction.Transaction{RcvAddr: tc.receiver, Data: []byte(tc.data)}), tc.data)
	}
	require.False(t, transaction.RequiresDRWANativeValidationReceipt(nil))
}
