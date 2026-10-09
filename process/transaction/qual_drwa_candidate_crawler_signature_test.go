package transaction_test

import (
	"fmt"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/versioning"
	"github.com/multiversx/mx-chain-core-go/data/block"
	dataTransaction "github.com/multiversx/mx-chain-core-go/data/transaction"
	hashFactory "github.com/multiversx/mx-chain-core-go/hashing/factory"
	marshalFactory "github.com/multiversx/mx-chain-core-go/marshal/factory"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	converterFactory "github.com/multiversx/mx-chain-go/common/factory"
	"github.com/multiversx/mx-chain-go/common/forking"
	nativeFactory "github.com/multiversx/mx-chain-go/factory"
	"github.com/multiversx/mx-chain-go/process/interceptors"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/sharding"
	storageFactory "github.com/multiversx/mx-chain-go/storage/factory"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// T09-M17 exercises the native ordinary authentication/cache path. The existing
// inherited fee double is explicit: no fee, action permission, network submission,
// actual builtin execution, whole startup or all-route crawler proof is claimed.
func TestQualDRWACandidateCrawlerTransactionSignature(t *testing.T) {
	candidate := filepath.Join("..", "..", "..", "..", "evidence", "sp1_t09_configuration_candidate_03")
	cfg, err := common.LoadMainConfig(filepath.Join(candidate, "config.toml"))
	require.NoError(t, err)
	epochCfg, err := common.LoadEpochConfig(filepath.Join(candidate, "enableEpochs.toml"))
	require.NoError(t, err)
	converter, err := converterFactory.NewPubkeyConverter(cfg.AddressPubkeyConverter)
	require.NoError(t, err)
	crawlers, err := nativeFactory.DecodeAddresses(converter, cfg.BuiltInFunctions.AutomaticCrawlerAddresses)
	require.NoError(t, err)
	require.Len(t, crawlers, 3)
	proto, err := marshalFactory.NewMarshalizer(cfg.Marshalizer.Type)
	require.NoError(t, err)
	signMarshal, err := marshalFactory.NewMarshalizer(cfg.TxSignMarshalizer.Type)
	require.NoError(t, err)
	hasher, err := hashFactory.NewHasher(cfg.Hasher.Type)
	require.NoError(t, err)
	signHasher, err := hashFactory.NewHasher(cfg.TxSignHasher.Type)
	require.NoError(t, err)
	notifier := forking.NewGenericEpochNotifier()
	epochs, err := enablers.NewEnableEpochsHandler(epochCfg.EnableEpochs, notifier)
	require.NoError(t, err)
	notifier.CheckEpoch(&block.Header{Epoch: 3, Round: 440})
	require.True(t, epochs.IsFlagEnabled(common.TransactionSignedWithTxHashFlag))
	keyGen := signing.NewKeyGenerator(ed25519.NewEd25519())
	signer := &singlesig.Ed25519Signer{}

	for shardID, crawler := range crawlers {
		for _, function := range []string{vmcommon.ESDTAddMetadata, vmcommon.ESDTDeleteMetadata} {
			for _, hashSign := range []bool{false, true} {
				t.Run(fmt.Sprintf("shard_%d_%s_hash_%t", shardID, function, hashSign), func(t *testing.T) {
					coordinator, err := sharding.NewMultiShardCoordinator(3, uint32(shardID))
					require.NoError(t, err)
					require.Equal(t, uint32(shardID), coordinator.ComputeId(crawler))
					cache, err := storageunit.NewCache(storageFactory.GetCacherFromConfig(cfg.WhiteListerVerifiedTxs))
					require.NoError(t, err)
					t.Cleanup(func() { cache.Clear(); require.NoError(t, cache.Close()) })
					whiteList, err := interceptors.NewWhiteListDataVerifier(cache)
					require.NoError(t, err)
					private, public := keyGen.GeneratePair()
					ordinary, err := public.ToByteArray()
					require.NoError(t, err)
					for _, sender := range []struct {
						name string
						addr []byte
						deny bool
					}{{"crawler", crawler, true}, {"healthy_signature", ordinary, false}} {
						t.Run(sender.name, func(t *testing.T) {
							tx := &dataTransaction.Transaction{
								Nonce: 0, Value: big.NewInt(0), SndAddr: sender.addr, RcvAddr: crawler,
								GasPrice: 1, GasLimit: 100000, Data: []byte(function),
								ChainID: []byte(cfg.GeneralSettings.ChainID), Version: core.InitialVersionOfTransaction,
							}
							if hashSign {
								tx.Version = core.InitialVersionOfTransaction + 1
								tx.Options = dataTransaction.MaskSignedWithHash
							}
							// All keys are ephemeral. For the negative, another genuine key
							// signs that exact transaction; the crawler public key still rejects.
							message, err := tx.GetDataForSigning(converter, signMarshal, signHasher)
							require.NoError(t, err)
							tx.Signature, err = signer.Sign(private, message)
							require.NoError(t, err)
							encoded, err := proto.Marshal(tx)
							require.NoError(t, err)
							inTx, err := transaction.NewInterceptedTransaction(encoded, proto, signMarshal, hasher,
								keyGen, signer, converter, coordinator, createFreeTxFeeHandler(), whiteList,
								smartContract.NewArgumentParser(), tx.ChainID,
								epochs.IsFlagEnabled(common.TransactionSignedWithTxHashFlag), signHasher,
								versioning.NewTxVersionChecker(cfg.GeneralSettings.MinTransactionVersion), epochs)
							require.NoError(t, err)
							require.Equal(t, hasher.Compute(string(encoded)), inTx.Hash())
							require.False(t, whiteList.IsWhiteListed(inTx))
							for attempt := 0; attempt < 2; attempt++ {
								if sender.deny {
									require.ErrorIs(t, inTx.CheckValidity(), crypto.ErrInvalidPublicKey)
									require.False(t, whiteList.IsWhiteListed(inTx))
								} else {
									require.NoError(t, inTx.CheckValidity())
									require.True(t, whiteList.IsWhiteListed(inTx))
								}
							}
							reencoded, err := proto.Marshal(inTx.Transaction())
							require.NoError(t, err)
							require.Equal(t, encoded, reencoded, "signature checking rewrites no native transaction field")
						})
					}
				})
			}
		}
	}
}
