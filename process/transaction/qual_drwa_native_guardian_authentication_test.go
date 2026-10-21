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
	"github.com/multiversx/mx-chain-go/common/chainparametersnotifier"
	"github.com/multiversx/mx-chain-go/common/enablers"
	converterFactory "github.com/multiversx/mx-chain-go/common/factory"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/epochStart/notifier"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/economics"
	"github.com/multiversx/mx-chain-go/process/interceptors"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/sharding"
	storageFactory "github.com/multiversx/mx-chain-go/storage/factory"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/stretchr/testify/require"
)

// Native ingress only, using repository-contained configuration and real
// economics/signatures/cache. No account guardian selection, execution, fee
// debit, DRWA enablement or compliance permission is supplied by interception.
// Private keys exist only in memory; only public addresses are encoded.
func TestQualDRWANativeGuardianAuthentication(t *testing.T) {
	dir := filepath.Join("..", "..", "cmd", "node", "config")
	cfg, err := common.LoadMainConfig(filepath.Join(dir, "config.toml"))
	require.NoError(t, err)
	epochCfg, err := common.LoadEpochConfig(filepath.Join(dir, "enableEpochs.toml"))
	require.NoError(t, err)
	economicsCfg, err := common.LoadEconomicsConfig(filepath.Join(dir, "economics.toml"))
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
	capPrice := fees.MaxGasPriceSetGuardian()
	require.GreaterOrEqual(t, capPrice, fees.MinGasPrice())
	require.Less(t, capPrice, ^uint64(0))
	keyGen := signing.NewKeyGenerator(ed25519.NewEd25519())
	signer := &singlesig.Ed25519Signer{}
	for _, hashSign := range []bool{false, true} {
		for _, scenario := range []string{"unguarded-at-cap", "unguarded-above-cap", "guarded-at-cap", "guarded-above-cap",
			"ordinary-above-cap", "wrong-owner-signature", "wrong-guardian-signature", "changed-guardian-address",
			"changed-body", "unexpected-guardian-address", "unexpected-guardian-signature", "missing-guardian-signature", "wrong-chain"} {
			t.Run(fmt.Sprintf("hash_%t/%s", hashSign, scenario), func(t *testing.T) {
				ownerKey, ownerPublic := keyGen.GeneratePair()
				owner, e := ownerPublic.ToByteArray()
				require.NoError(t, e)
				guardianKey, guardianPublic := keyGen.GeneratePair()
				guardian, e := guardianPublic.ToByteArray()
				require.NoError(t, e)
				otherKey, otherPublic := keyGen.GeneratePair()
				other, e := otherPublic.ToByteArray()
				require.NoError(t, e)
				require.NotEqual(t, owner, guardian)
				require.NotEqual(t, guardian, other)
				guarded := scenario != "unguarded-at-cap" && scenario != "unguarded-above-cap" &&
					scenario != "ordinary-above-cap" && scenario != "unexpected-guardian-address" && scenario != "unexpected-guardian-signature"
				tx := &dataTransaction.Transaction{Value: big.NewInt(0), SndAddr: owner, RcvAddr: owner,
					GasPrice: capPrice, Data: []byte(fmt.Sprintf("%s@%x@%x", core.BuiltInFunctionSetGuardian, guardian, []byte("fixture-service"))),
					ChainID: []byte(cfg.GeneralSettings.ChainID), Version: core.InitialVersionOfTransaction}
				if guarded || hashSign {
					tx.Version = core.InitialVersionOfTransaction + 1
				}
				if hashSign {
					tx.Options |= dataTransaction.MaskSignedWithHash
				}
				if guarded {
					tx.Options |= dataTransaction.MaskGuardedTransaction
					tx.GuardianAddr = guardian
				}
				switch scenario {
				case "unguarded-above-cap", "guarded-above-cap", "ordinary-above-cap":
					tx.GasPrice++
				case "changed-guardian-address":
					tx.GuardianAddr = other // owner signs this exact changed body; guardian verification is isolated
				case "unexpected-guardian-address":
					tx.GuardianAddr = guardian
				case "wrong-chain":
					tx.ChainID = []byte("different-native-chain")
				}
				if scenario == "ordinary-above-cap" {
					tx.Data = nil
				}
				tx.GasLimit = fees.ComputeGasLimit(tx)
				require.NoError(t, fees.CheckValidityTxValues(tx), "independent native fee control")
				message, e := tx.GetDataForSigning(converter, signMarshal, signHasher)
				require.NoError(t, e)
				ownerSigningKey := ownerKey
				if scenario == "wrong-owner-signature" {
					ownerSigningKey = otherKey
				}
				tx.Signature, e = signer.Sign(ownerSigningKey, message)
				require.NoError(t, e)
				if guarded || scenario == "unexpected-guardian-signature" {
					guardianSigningKey := guardianKey
					if scenario == "wrong-guardian-signature" {
						guardianSigningKey = otherKey
					}
					tx.GuardianSignature, e = signer.Sign(guardianSigningKey, message)
					require.NoError(t, e)
				}
				if scenario == "missing-guardian-signature" {
					tx.GuardianSignature = nil
				}
				if scenario == "changed-body" {
					tx.Data[len(tx.Data)-1] ^= 1
				}
				encoded, e := proto.Marshal(tx)
				require.NoError(t, e)
				cache, e := storageunit.NewCache(storageFactory.GetCacherFromConfig(cfg.WhiteListerVerifiedTxs))
				require.NoError(t, e)
				t.Cleanup(func() { cache.Clear(); require.NoError(t, cache.Close()) })
				whiteList, e := interceptors.NewWhiteListDataVerifier(cache, 0)
				require.NoError(t, e)
				inTx, e := transaction.NewInterceptedTransaction(encoded, proto, signMarshal, hasher,
					keyGen, signer, converter, coordinator, fees, whiteList, smartContract.NewArgumentParser(),
					[]byte(cfg.GeneralSettings.ChainID), epochs.IsFlagEnabled(common.TransactionSignedWithTxHashFlag), signHasher, version, epochs)
				require.NoError(t, e)
				require.False(t, whiteList.IsWhiteListed(inTx))
				var expected error
				switch scenario {
				case "unguarded-above-cap":
					expected = process.ErrGasPriceTooHigh
				case "wrong-owner-signature", "wrong-guardian-signature", "changed-guardian-address", "changed-body", "missing-guardian-signature":
					expected = crypto.ErrEd25519InvalidSignature
				case "unexpected-guardian-address":
					expected = process.ErrGuardianAddressNotExpected
				case "unexpected-guardian-signature":
					expected = process.ErrGuardianSignatureNotExpected
				case "wrong-chain":
					expected = process.ErrInvalidChainID
				}
				for attempt := 0; attempt < 2; attempt++ {
					e = inTx.CheckValidity()
					if expected == nil {
						require.NoError(t, e)
					} else {
						require.ErrorIs(t, e, expected)
					}
					require.Equal(t, expected == nil, whiteList.IsWhiteListed(inTx))
				}
				reencoded, e := proto.Marshal(inTx.Transaction())
				require.NoError(t, e)
				require.Equal(t, encoded, reencoded)
			})
		}
	}
}
