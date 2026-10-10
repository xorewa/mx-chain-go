package drwa

import (
	"bytes"
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
	"github.com/multiversx/mx-chain-go/common/chainparametersnotifier"
	"github.com/multiversx/mx-chain-go/common/enablers"
	converterFactory "github.com/multiversx/mx-chain-go/common/factory"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/epochStart/notifier"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/economics"
	"github.com/multiversx/mx-chain-go/process/interceptors"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	nativeTransaction "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/sharding"
	storageFactory "github.com/multiversx/mx-chain-go/storage/factory"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/stretchr/testify/require"
)

// DEVELOPMENT model 05: actual native transaction authentication and economics,
// followed by an experimental same-creator producer and existing synthetic
// appointment resolver. No native ENROLL endpoint, executed transaction, real
// appointment, canonical finality, fee debit or admission is supplied here.
func TestQualDRWAScopedAdmissionNativeCreatorControl(t *testing.T) {
	configDir := filepath.Join("..", "..", "cmd", "node", "config")
	cfg, err := common.LoadMainConfig(filepath.Join(configDir, "config.toml"))
	require.NoError(t, err)
	epochCfg, err := common.LoadEpochConfig(filepath.Join(configDir, "enableEpochs.toml"))
	require.NoError(t, err)
	economicsCfg, err := common.LoadEconomicsConfig(filepath.Join(configDir, "economics.toml"))
	require.NoError(t, err)
	converter, err := converterFactory.NewPubkeyConverter(cfg.AddressPubkeyConverter)
	require.NoError(t, err)
	proto, err := marshalFactory.NewMarshalizer(cfg.Marshalizer.Type)
	require.NoError(t, err)
	signMarshal, err := marshalFactory.NewMarshalizer(cfg.TxSignMarshalizer.Type)
	require.NoError(t, err)
	hasher, err := hashFactory.NewHasher(cfg.Hasher.Type)
	require.NoError(t, err)
	signHasher, err := hashFactory.NewHasher(cfg.TxSignHasher.Type)
	require.NoError(t, err)
	coordinator, err := sharding.NewMultiShardCoordinator(3, 0)
	require.NoError(t, err)
	epochNotifier := forking.NewGenericEpochNotifier()
	epochs, err := enablers.NewEnableEpochsHandler(epochCfg.EnableEpochs, epochNotifier)
	require.NoError(t, err)
	chainParameters, err := sharding.NewChainParametersHolder(sharding.ArgsChainParametersHolder{
		ChainParameters:         cfg.GeneralSettings.ChainParametersByEpoch,
		EpochStartEventNotifier: notifier.NewEpochStartSubscriptionHandler(),
		ChainParametersNotifier: chainparametersnotifier.NewChainParametersNotifier(),
	})
	require.NoError(t, err)
	version := versioning.NewTxVersionChecker(cfg.GeneralSettings.MinTransactionVersion)
	fees, err := economics.NewEconomicsData(economics.ArgsNewEconomicsData{
		TxVersionChecker: version, Economics: economicsCfg, ChainParamsHandler: chainParameters,
		EpochNotifier: epochNotifier, EnableEpochsHandler: epochs,
		PubkeyConverter: converter, ShardCoordinator: coordinator,
	})
	require.NoError(t, err)
	epochNotifier.CheckEpoch(&block.Header{Epoch: 10})
	require.True(t, epochs.IsFlagEnabled(common.TransactionSignedWithTxHashFlag))
	keyGen := signing.NewKeyGenerator(ed25519.NewEd25519())
	signer := &singlesig.Ed25519Signer{}
	for _, hashSign := range []bool{false, true} {
		for _, fault := range []string{"healthy", "different-signing-key", "sender-substitution", "data-substitution", "wrong-chain", "different-scope-owner", "mandate-as-tx-signature", "missing-appointment"} {
			t.Run(fmt.Sprintf("hash_%t/%s", hashSign, fault), func(t *testing.T) {
				private, public := keyGen.GeneratePair()
				owner, err := public.ToByteArray()
				require.NoError(t, err)
				otherPrivate, otherPublic := keyGen.GeneratePair()
				other, err := otherPublic.ToByteArray()
				require.NoError(t, err)
				require.NotEqual(t, owner, other)
				f := qualScopedNew(t)
				f.d.owner = owner
				f.scope = qualRecordFrame([]byte("fixture-domain"), owner, f.d.program)
				f.d.authority = qualScopedHash("VERSION", f.scope, nil, f.versionBody)
				f.mandates.scope = f.scope
				proof := f.mandates.proof("ENROLL", nil, f.d.authority)
				if fault == "missing-appointment" {
					delete(f.mandates.roles, "ENROLL")
				}
				tx := &dataTransaction.Transaction{
					Value: big.NewInt(0), SndAddr: owner, RcvAddr: core.ESDTSCAddress,
					GasPrice: fees.MinGasPrice(), Data: []byte("experimentalScopedEnrollment"),
					ChainID: []byte(cfg.GeneralSettings.ChainID), Version: core.InitialVersionOfTransaction,
				}
				if hashSign {
					tx.Version = core.InitialVersionOfTransaction + 1
					tx.Options = dataTransaction.MaskSignedWithHash
				}
				if fault == "wrong-chain" {
					tx.ChainID = []byte("different-native-chain")
				}
				if fault == "different-scope-owner" {
					tx.SndAddr = other
				}
				tx.GasLimit = fees.ComputeGasLimit(tx)
				require.NoError(t, fees.CheckValidityTxValues(tx))
				message, err := tx.GetDataForSigning(converter, signMarshal, signHasher)
				require.NoError(t, err)
				signingKey := private
				if fault == "different-signing-key" || fault == "different-scope-owner" {
					signingKey = otherPrivate
				}
				tx.Signature, err = signer.Sign(signingKey, message)
				require.NoError(t, err)
				switch fault {
				case "sender-substitution":
					tx.SndAddr = other
				case "data-substitution":
					tx.Data[0] ^= 1
				case "mandate-as-tx-signature":
					tx.Signature = proof
				}
				encoded, err := proto.Marshal(tx)
				require.NoError(t, err)
				cache, err := storageunit.NewCache(storageFactory.GetCacherFromConfig(cfg.WhiteListerVerifiedTxs))
				require.NoError(t, err)
				t.Cleanup(func() { cache.Clear(); require.NoError(t, cache.Close()) })
				whiteList, err := interceptors.NewWhiteListDataVerifier(cache)
				require.NoError(t, err)
				inTx, err := nativeTransaction.NewInterceptedTransaction(encoded, proto, signMarshal, hasher,
					keyGen, signer, converter, coordinator, fees, whiteList, smartContract.NewArgumentParser(),
					[]byte(cfg.GeneralSettings.ChainID), epochs.IsFlagEnabled(common.TransactionSignedWithTxHashFlag),
					signHasher, version, epochs)
				require.NoError(t, err)
				require.False(t, whiteList.IsWhiteListed(inTx))
				before, err := f.store.RootHash()
				require.NoError(t, err)
				journal := f.store.JournalLen()
				// This is an explicit experimental producer sequence, not a
				// production dispatch seam or a native-execution claim.
				enroll := func() error {
					if err := inTx.CheckValidity(); err != nil {
						return err
					}
					if !bytes.Equal(inTx.SenderAddress(), f.d.owner) {
						return errScopedAdmission
					}
					return f.records.install(f.context, f.d.owner, f.d.program, nil, f.versionBody, proof)
				}
				err = enroll()
				switch fault {
				case "healthy":
					require.NoError(t, err)
					account, e := f.records.codec.state.systemAccount()
					require.NoError(t, e)
					current, e := f.records.current(account, f.scope)
					require.NoError(t, e)
					require.Equal(t, f.d.authority, current)
					journal = f.store.JournalLen()
					require.NoError(t, enroll())
					require.Equal(t, journal, f.store.JournalLen())
				case "wrong-chain":
					require.ErrorIs(t, err, process.ErrInvalidChainID)
				case "different-scope-owner", "missing-appointment":
					require.ErrorIs(t, err, errScopedAdmission)
				default:
					require.ErrorIs(t, err, crypto.ErrEd25519InvalidSignature)
				}
				authenticated := fault == "healthy" || fault == "different-scope-owner" || fault == "missing-appointment"
				require.Equal(t, authenticated, whiteList.IsWhiteListed(inTx), "native authentication cache is not enrollment permission")
				if fault != "healthy" {
					after, e := f.store.RootHash()
					require.NoError(t, e)
					require.Equal(t, before, after)
					require.Equal(t, journal, f.store.JournalLen())
					if fault == "missing-appointment" {
						require.Equal(t, 1, f.mandates.calls)
					} else {
						require.Zero(t, f.mandates.calls)
					}
				}
				reencoded, err := proto.Marshal(inTx.Transaction())
				require.NoError(t, err)
				require.Equal(t, encoded, reencoded)
			})
		}
	}
}
