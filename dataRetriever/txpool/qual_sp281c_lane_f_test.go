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
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	native "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CLaneFPoolRetainsOrdinaryInsertionWithoutReceipt(t *testing.T) {
	pool, err := newTxPoolToTest()
	require.NoError(t, err)
	p := pool.(*shardedTxPool)
	require.NoError(t, p.ConfigureNativeValidationSource(nil))
	require.False(t, p.NativeValidationReceiptEnabled())

	enabled := false
	flags := &enableEpochsHandlerMock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			require.Equal(t, common.TransactionSignedWithTxHashFlag, flag)
			return enabled
		},
	}
	source := &native.NativeValidationSource{EnableEpochsHandler: flags}
	require.NoError(t, p.ConfigureNativeValidationSource(source))
	source.EnableEpochsHandler = nil
	require.True(t, p.NativeValidationReceiptEnabled())
	require.ErrorIs(t, p.ConfigureNativeValidationSource(source), vm.ErrDRWAExecution)
	require.False(t, p.currentNativeValidationSource().EnableSignedTxWithHash)
	enabled = true
	require.True(t, p.currentNativeValidationSource().EnableSignedTxWithHash)

	for _, function := range []string{"ordinary", "DRWARegisterToken"} {
		t.Run(function, func(t *testing.T) {
			tx := &transaction.Transaction{RcvAddr: core.ESDTSCAddress, Data: []byte(function)}
			key := []byte(function)
			require.Nil(t, p.NativeValidationReceiptFor(key, "0", tx))
			p.AddDataWithNativeValidationReceipt(key, tx, 42, "0", nil)
			got, present := p.SearchFirstData(key)
			require.True(t, present)
			require.Same(t, tx, got)
			require.Nil(t, p.NativeValidationReceiptFor(key, "0", tx))
			copyTx := *tx
			require.Nil(t, p.NativeValidationReceiptFor(key, "0", &copyTx))
		})
	}
}

func TestQualSP281CLaneFPoolCannotUseMissingEpochFlagProducer(t *testing.T) {
	for _, source := range []*native.NativeValidationSource{nil, {EnableEpochsHandler: (*enableEpochsHandlerMock.EnableEpochsHandlerStub)(nil)}} {
		pool, err := newTxPoolToTest()
		require.NoError(t, err)
		p := pool.(*shardedTxPool)
		require.NoError(t, p.ConfigureNativeValidationSource(source))
		require.Nil(t, p.currentNativeValidationSource())
		tx := &transaction.Transaction{RcvAddr: core.ESDTSCAddress, Data: []byte("DRWARegisterToken")}
		require.True(t, native.RequiresDRWANativeValidationReceipt(tx))
		require.Nil(t, p.NativeValidationReceiptFor([]byte("unavailable"), "0", tx))
	}
}

func TestQualSP281CLaneFPoolRetainsOnlyMatchingValidatedReceipt(t *testing.T) {
	const chainID = "lane-f-inert"
	converter, err := pubkeyConverter.NewBech32PubkeyConverter(len(core.ESDTSCAddress), "erd")
	require.NoError(t, err)
	coordinator, err := sharding.NewMultiShardCoordinator(3, 0)
	require.NoError(t, err)
	keys := signing.NewKeyGenerator(ed25519.NewEd25519())
	key, public := keys.GeneratePair()
	sender, err := public.ToByteArray()
	require.NoError(t, err)
	source := native.NativeValidationSource{
		ProtoMarshalizer: &marshal.GogoProtoMarshalizer{}, SignMarshalizer: &marshal.JsonMarshalizer{},
		Hasher: blake2b.NewBlake2b(), TxSignHasher: blake2b.NewBlake2b(),
		KeyGen: keys, Signer: &singlesig.Ed25519Signer{}, Converter: converter,
		VersionChecker: versioning.NewTxVersionChecker(core.InitialVersionOfTransaction),
		ChainID:        chainID, Coordinator: coordinator, FeeHandler: &economicsmocks.EconomicsHandlerMock{},
		VerifiedTransactions: &testscommon.WhiteListHandlerStub{}, ArgsParser: smartContract.NewArgumentParser(),
		EnableEpochsHandler: &enableEpochsHandlerMock.EnableEpochsHandlerStub{},
	}
	inert := &transaction.Transaction{Value: big.NewInt(0), SndAddr: sender, RcvAddr: core.ESDTSCAddress,
		Data: []byte("DRWARegisterToken@00@00"), ChainID: []byte(chainID), Version: core.InitialVersionOfTransaction}
	message, err := inert.GetDataForSigning(source.Converter, source.SignMarshalizer, source.TxSignHasher)
	require.NoError(t, err)
	inert.Signature, err = source.Signer.Sign(key, message)
	require.NoError(t, err)
	encoded, err := source.ProtoMarshalizer.Marshal(inert)
	require.NoError(t, err)
	in, err := native.NewInterceptedTransaction(encoded, source.ProtoMarshalizer, source.SignMarshalizer,
		source.Hasher, source.KeyGen, source.Signer, source.Converter, source.Coordinator, source.FeeHandler,
		source.VerifiedTransactions, source.ArgsParser, []byte(chainID), false, source.TxSignHasher,
		source.VersionChecker, source.EnableEpochsHandler)
	require.NoError(t, err)
	require.Nil(t, in.NativeValidationReceipt())
	require.NoError(t, in.CheckValidity())
	receipt := in.NativeValidationReceipt()
	require.NotNil(t, receipt)
	tx := in.Transaction().(*transaction.Transaction)
	route := process.ShardCacherIdentifier(in.SenderShardId(), in.ReceiverShardId())

	for _, tc := range []struct {
		name, route             string
		size                    int
		bind, present, retained bool
	}{
		{"exact observation", route, tx.Size(), true, true, true},
		{"unconfigured fallback", route, tx.Size(), false, true, false},
		{"invalid cache identifier", "invalid-cache-id", tx.Size(), true, false, false},
		{"invalid cache identifier and negative size", "invalid-cache-id", -1, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := newTxPoolToTest()
			require.NoError(t, err)
			p := pool.(*shardedTxPool)
			t.Cleanup(p.Clear)
			if tc.bind {
				require.NoError(t, p.ConfigureNativeValidationSource(&source))
			}
			hash := bytes.Clone(in.Hash())
			p.AddDataWithNativeValidationReceipt(hash, tx, tc.size, tc.route, receipt)
			actual, found := p.SearchFirstData(hash)
			require.Equal(t, tc.present, found)
			if tc.present {
				require.Same(t, tx, actual)
			}
			if tc.retained {
				hash[0] ^= 1
				require.Same(t, receipt, p.NativeValidationReceiptFor(in.Hash(), route, tx))
			} else {
				require.Nil(t, p.NativeValidationReceiptFor(hash, route, tx))
			}
		})
	}
}
