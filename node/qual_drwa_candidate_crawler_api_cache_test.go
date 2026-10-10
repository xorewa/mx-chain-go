package node_test

import (
	"fmt"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/versioning"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
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
	"github.com/multiversx/mx-chain-go/node"
	"github.com/multiversx/mx-chain-go/node/disabled"
	"github.com/multiversx/mx-chain-go/process/interceptors"
	"github.com/multiversx/mx-chain-go/sharding"
	storageFactory "github.com/multiversx/mx-chain-go/storage/factory"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// T09 M21 calls the actual native node validation methods. Inherited component,
// account and economics doubles are explicit; no node startup or transaction
// execution occurs. Simulation acceptance is never canonical permission.
func TestQualDRWACandidateCrawlerAPISimulationCache(t *testing.T) {
	candidate := qualDRWACandidateFixtureDir(t)
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
		coordinator, err := sharding.NewMultiShardCoordinator(3, uint32(shardID))
		require.NoError(t, err)
		require.Equal(t, uint32(shardID), coordinator.ComputeId(crawler))
		var private crypto.PrivateKey
		var ordinary []byte
		for attempt := 0; attempt < 1024; attempt++ {
			key, public := keyGen.GeneratePair()
			address, err := public.ToByteArray()
			require.NoError(t, err)
			if coordinator.ComputeId(address) == uint32(shardID) {
				private, ordinary = key, address
				break
			}
		}
		require.NotNil(t, private, "bounded ephemeral fixture key search exhausted")
		for _, function := range []string{vmcommon.ESDTAddMetadata, vmcommon.ESDTDeleteMetadata} {
			for _, hashSign := range []bool{false, true} {
				for _, sender := range []struct {
					name string
					addr []byte
					deny bool
				}{{"crawler", crawler, true}, {"healthy", ordinary, false}} {
					t.Run(fmt.Sprintf("shard_%d_%s_hash_%t_%s", shardID, function, hashSign, sender.name), func(t *testing.T) {
						cache, err := storageunit.NewCache(storageFactory.GetCacherFromConfig(cfg.WhiteListerVerifiedTxs))
						require.NoError(t, err)
						t.Cleanup(func() { cache.Clear(); require.NoError(t, cache.Close()) })
						verified, err := interceptors.NewWhiteListDataVerifier(cache)
						require.NoError(t, err)
						coreComponents := getDefaultCoreComponents()
						coreComponents.IntMarsh, coreComponents.TxMarsh = proto, signMarshal
						coreComponents.Hash, coreComponents.TxSignHasherField = hasher, signHasher
						coreComponents.AddrPubKeyConv = converter
						coreComponents.ChainIdCalled = func() string { return cfg.GeneralSettings.ChainID }
						coreComponents.TxVersionCheckHandler = versioning.NewTxVersionChecker(cfg.GeneralSettings.MinTransactionVersion)
						coreComponents.EpochChangeNotifier, coreComponents.EnableEpochsHandlerField = notifier, epochs
						cryptoComponents := getDefaultCryptoComponents()
						cryptoComponents.TxKeyGen, cryptoComponents.TxSig = keyGen, signer
						bootstrap := getDefaultBootstrapComponents()
						bootstrap.ShCoordinator = coordinator
						processComponents := getDefaultProcessComponents()
						processComponents.ShardCoord = coordinator
						processComponents.WhiteListerVerifiedTxsInternal = verified
						processComponents.WhiteListHandlerInternal = disabled.NewDisabledWhiteListDataVerifier()
						stateComponents := getDefaultStateComponents()
						// Inherited fixture creates native accounts with nonce1. This
						// balance is non-normative and proves no real fee/funding policy.
						stateComponents.AccountsAPI = getAccAdapter(big.NewInt(1000000))
						n, err := node.NewNode(node.WithCoreComponents(coreComponents), node.WithCryptoComponents(cryptoComponents),
							node.WithBootstrapComponents(bootstrap), node.WithProcessComponents(processComponents),
							node.WithStateComponents(stateComponents),
							node.WithEnableSignTxWithHashEpoch(epochs.GetActivationEpoch(common.TransactionSignedWithTxHashFlag)))
						require.NoError(t, err)
						tx := &transaction.Transaction{Nonce: 1, Value: big.NewInt(0), SndAddr: sender.addr, RcvAddr: crawler,
							GasPrice: 1, GasLimit: 100000, Data: []byte(function), ChainID: []byte(cfg.GeneralSettings.ChainID),
							Version: core.InitialVersionOfTransaction}
						if hashSign {
							tx.Version = core.InitialVersionOfTransaction + 1
							tx.Options = transaction.MaskSignedWithHash
						}
						message, err := tx.GetDataForSigning(converter, signMarshal, signHasher)
						require.NoError(t, err)
						tx.Signature, err = signer.Sign(private, message)
						require.NoError(t, err)
						encoded, err := proto.Marshal(tx)
						require.NoError(t, err)
						hash := hasher.Compute(string(encoded))
						require.Zero(t, cache.Len())
						require.NoError(t, n.ValidateTransactionForSimulation(tx, false))
						require.False(t, cache.Has(hash), "simulation must not seed the normal authentication cache")
						require.Zero(t, cache.Len())
						if sender.deny {
							require.ErrorIs(t, n.ValidateTransactionForSimulation(tx, true), crypto.ErrInvalidPublicKey)
							require.ErrorIs(t, n.ValidateTransaction(tx), crypto.ErrInvalidPublicKey)
							require.ErrorIs(t, n.ValidateTransaction(tx), crypto.ErrInvalidPublicKey)
							require.False(t, cache.Has(hash))
							require.Zero(t, cache.Len())
						} else {
							require.NoError(t, n.ValidateTransactionForSimulation(tx, true))
							require.False(t, cache.Has(hash))
							require.NoError(t, n.ValidateTransaction(tx))
							require.True(t, cache.Has(hash))
							require.Equal(t, 1, cache.Len())
							require.NoError(t, n.ValidateTransaction(tx))
							require.Equal(t, 1, cache.Len())
						}
						reencoded, err := proto.Marshal(tx)
						require.NoError(t, err)
						require.Equal(t, encoded, reencoded)
					})
				}
			}
		}
	}
}
