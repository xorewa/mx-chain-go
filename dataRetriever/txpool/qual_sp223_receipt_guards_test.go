package txpool

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/pubkeyConverter"
	"github.com/multiversx/mx-chain-core-go/core/versioning"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	native "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/txcache"
	"github.com/stretchr/testify/require"
)

// SP2-23, audit finding TA-SP2-23-1-2 (guards M27 and M40 of the pool). The
// pool, the interception and the signature check are production code; the fee
// handler and the whitelist are labelled synthetic collaborators.

type qualSP223Observed struct {
	tx      *transaction.Transaction
	hash    []byte
	route   string
	receipt *native.NativeValidationReceipt
}

func qualSP223ReceiptSource(t *testing.T) *native.NativeValidationSource {
	t.Helper()
	converter, err := pubkeyConverter.NewBech32PubkeyConverter(len(core.ESDTSCAddress), "erd")
	require.NoError(t, err)
	coordinator, err := sharding.NewMultiShardCoordinator(3, 0)
	require.NoError(t, err)
	return &native.NativeValidationSource{
		ProtoMarshalizer: &marshal.GogoProtoMarshalizer{}, SignMarshalizer: &marshal.JsonMarshalizer{},
		Hasher: blake2b.NewBlake2b(), TxSignHasher: blake2b.NewBlake2b(),
		KeyGen: signing.NewKeyGenerator(ed25519.NewEd25519()), Signer: &singlesig.Ed25519Signer{}, Converter: converter,
		VersionChecker: versioning.NewTxVersionChecker(core.InitialVersionOfTransaction),
		ChainID:        "sp2-23-inert", Coordinator: coordinator, FeeHandler: &economicsmocks.EconomicsHandlerMock{},
		VerifiedTransactions: &testscommon.WhiteListHandlerStub{}, ArgsParser: smartContract.NewArgumentParser(),
		EnableEpochsHandler: &enableEpochsHandlerMock.EnableEpochsHandlerStub{},
	}
}

// qualSP223Observe signs and intercepts one registration request and returns
// the receipt the interception produced for it.
func qualSP223Observe(t *testing.T, source *native.NativeValidationSource, data string) qualSP223Observed {
	t.Helper()
	key, public := source.KeyGen.GeneratePair()
	sender, err := public.ToByteArray()
	require.NoError(t, err)
	signed := &transaction.Transaction{Value: big.NewInt(0), SndAddr: sender, RcvAddr: core.ESDTSCAddress,
		Data: []byte(data), ChainID: []byte(source.ChainID), Version: core.InitialVersionOfTransaction}
	message, err := signed.GetDataForSigning(source.Converter, source.SignMarshalizer, source.TxSignHasher)
	require.NoError(t, err)
	signed.Signature, err = source.Signer.Sign(key, message)
	require.NoError(t, err)
	encoded, err := source.ProtoMarshalizer.Marshal(signed)
	require.NoError(t, err)
	in, err := native.NewInterceptedTransaction(encoded, source.ProtoMarshalizer, source.SignMarshalizer,
		source.Hasher, source.KeyGen, source.Signer, source.Converter, source.Coordinator, source.FeeHandler,
		source.VerifiedTransactions, source.ArgsParser, []byte(source.ChainID), false, source.TxSignHasher,
		source.VersionChecker, source.EnableEpochsHandler)
	require.NoError(t, err)
	require.NoError(t, in.CheckValidity())
	receipt := in.NativeValidationReceipt()
	require.NotNil(t, receipt)
	return qualSP223Observed{tx: in.Transaction().(*transaction.Transaction), hash: bytes.Clone(in.Hash()),
		route: process.ShardCacherIdentifier(in.SenderShardId(), in.ReceiverShardId()), receipt: receipt}
}

func qualSP223Stored(t *testing.T, p *shardedTxPool, o qualSP223Observed) (*txcache.WrappedTransaction, interface{}) {
	t.Helper()
	cache, ok := p.ShardDataStore(o.route).(interface {
		GetByTxHashWithValidationReceipt([]byte) (*txcache.WrappedTransaction, interface{}, bool)
	})
	require.True(t, ok)
	wrapped, metadata, found := cache.GetByTxHashWithValidationReceipt(o.hash)
	require.True(t, found)
	return wrapped, metadata
}

// A receipt that does not verify for the inserted transaction is not kept and
// not charged: the transaction is stored exactly as the ordinary insertion
// stores it.
func TestQualSP223PoolKeepsNoUnverifiedReceiptOnInsertion(t *testing.T) {
	source := qualSP223ReceiptSource(t)
	observed := qualSP223Observe(t, source, "DRWARegisterToken@00@00")
	other := qualSP223Observe(t, source, "DRWARegisterToken@00@01")
	foreign := qualSP223Observe(t, qualSP223ReceiptSource(t), "DRWARegisterToken@00@00")
	for _, tc := range []struct {
		name    string
		receipt *native.NativeValidationReceipt
		kept    bool
	}{
		{"receipt of this transaction", observed.receipt, true},
		{"no receipt", nil, false},
		{"empty receipt", &native.NativeValidationReceipt{}, false},
		{"receipt of another transaction", other.receipt, false},
		{"receipt of another node's providers", foreign.receipt, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := newTxPoolToTest()
			require.NoError(t, err)
			p := pool.(*shardedTxPool)
			t.Cleanup(p.Clear)
			require.NoError(t, p.ConfigureNativeValidationSource(source))
			p.AddDataWithNativeValidationReceipt(observed.hash, observed.tx, observed.tx.Size(), observed.route, tc.receipt)
			wrapped, metadata := qualSP223Stored(t, p, observed)
			require.Same(t, observed.tx, wrapped.Tx)
			if tc.kept {
				require.Same(t, tc.receipt, metadata)
				require.Greater(t, wrapped.Size, int64(observed.tx.Size()), "a kept receipt is charged to the entry")
				require.Same(t, tc.receipt, p.NativeValidationReceiptFor(observed.hash, observed.route, observed.tx))
				return
			}
			require.Nil(t, metadata)
			require.Equal(t, int64(observed.tx.Size()), wrapped.Size)
			require.Nil(t, p.NativeValidationReceiptFor(observed.hash, observed.route, observed.tx))
		})
	}
}

// The receipt is returned only for the very transaction object the pool
// holds: an equal copy, which the receipt would verify for, gets none.
func TestQualSP223PoolReturnsTheReceiptOnlyForThePooledObject(t *testing.T) {
	source := qualSP223ReceiptSource(t)
	observed := qualSP223Observe(t, source, "DRWARegisterBootstrapIntent@00")
	pool, err := newTxPoolToTest()
	require.NoError(t, err)
	p := pool.(*shardedTxPool)
	t.Cleanup(p.Clear)
	require.NoError(t, p.ConfigureNativeValidationSource(source))
	p.AddDataWithNativeValidationReceipt(observed.hash, observed.tx, observed.tx.Size(), observed.route, observed.receipt)
	require.Same(t, observed.receipt, p.NativeValidationReceiptFor(observed.hash, observed.route, observed.tx))

	equal := *observed.tx
	current := *source
	require.NoError(t, native.VerifyNativeValidationReceipt(current, observed.receipt, &equal, observed.hash),
		"the copy has the receipt's exact bytes: only its identity differs")
	require.Nil(t, p.NativeValidationReceiptFor(observed.hash, observed.route, &equal))
	require.Same(t, observed.receipt, p.NativeValidationReceiptFor(observed.hash, observed.route, observed.tx))
}
