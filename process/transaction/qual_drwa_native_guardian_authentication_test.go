package transaction_test

import (
	"bytes"
	"fmt"
	"math/big"
	"path/filepath"
	"sync/atomic"
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

// This counter delegates every check to the real native signer. It is not an
// accepting verifier; it detects an accidental second signature pass.
type qualNativeReceiptCountingSigner struct {
	crypto.SingleSigner
	checks atomic.Int64
}

func (s *qualNativeReceiptCountingSigner) Verify(key crypto.PublicKey, message, signature []byte) error {
	s.checks.Add(1)
	return s.SingleSigner.Verify(key, message, signature)
}

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
	proto = &qualReceiptCountingMarshalizer{Marshalizer: proto}
	signMarshal, err := marshalFactory.NewMarshalizer(cfg.TxSignMarshalizer.Type)
	require.NoError(t, err)
	signMarshal = &qualReceiptCountingMarshalizer{Marshalizer: signMarshal}
	hasher, err := hashFactory.NewHasher(cfg.Hasher.Type)
	require.NoError(t, err)
	hasher = &qualReceiptCountingHasher{Hasher: hasher}
	signHasher, err := hashFactory.NewHasher(cfg.TxSignHasher.Type)
	require.NoError(t, err)
	signHasher = &qualReceiptCountingHasher{Hasher: signHasher}
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
	signer := &qualNativeReceiptCountingSigner{SingleSigner: &singlesig.Ed25519Signer{}}
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
				argsParser := smartContract.NewArgumentParser()
				inTx, e := transaction.NewInterceptedTransaction(encoded, proto, signMarshal, hasher,
					keyGen, signer, converter, coordinator, fees, whiteList, argsParser,
					[]byte(cfg.GeneralSettings.ChainID), epochs.IsFlagEnabled(common.TransactionSignedWithTxHashFlag), signHasher, version, epochs)
				require.NoError(t, e)
				require.False(t, whiteList.IsWhiteListed(inTx))
				require.Nil(t, inTx.NativeValidationReceipt(), "constructor is not validation")
				nativeSource := transaction.NativeValidationSource{ProtoMarshalizer: proto, SignMarshalizer: signMarshal,
					Hasher: hasher, TxSignHasher: signHasher, KeyGen: keyGen, Signer: signer, Converter: converter, VersionChecker: version, ChainID: cfg.GeneralSettings.ChainID, Coordinator: coordinator, FeeHandler: fees, VerifiedTransactions: whiteList, ArgsParser: argsParser, EnableEpochsHandler: epochs, EnableSignedTxWithHash: epochs.IsFlagEnabled(common.TransactionSignedWithTxHashFlag)}
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
					wasCached := whiteList.IsWhiteListed(inTx)
					baselineWorkBefore := qualReceiptWork(nativeSource)
					baselineBefore := signer.checks.Load()
					baselineErr := transaction.QualD18UntouchedNativeCheckValidity(inTx)
					baselineCalls := signer.checks.Load() - baselineBefore
					baselineWork := qualReceiptWork(nativeSource).subtract(baselineWorkBefore)
					if !wasCached {
						cache.Clear()
					}
					currentWorkBefore := qualReceiptWork(nativeSource)
					currentBefore := signer.checks.Load()
					e = inTx.CheckValidity()
					require.Equal(t, baselineCalls, signer.checks.Load()-currentBefore, "unconfigured native signature-call behavior")
					require.Equal(t, baselineWork, qualReceiptWork(nativeSource).subtract(currentWorkBefore), "pinned native CheckValidity codec/hash work")
					if baselineErr == nil {
						require.NoError(t, e)
					} else {
						require.EqualError(t, e, baselineErr.Error())
					}
					if expected == nil {
						require.NoError(t, e)
					} else {
						require.ErrorIs(t, e, expected)
					}
					require.Equal(t, expected == nil, whiteList.IsWhiteListed(inTx))
					if expected == nil && attempt == 0 && !hashSign && scenario == "unguarded-at-cap" {
						qualOrdinaryPoolReceiptEquivalence(t, nativeSource, inTx, ownerKey)
						qualD19ReceiptTransport(t, nativeSource, qualD19RegistrationControl(t, nativeSource, inTx, ownerKey))
					}
					checked := signer.checks.Load()
					receipt := inTx.NativeValidationReceipt()
					if expected != nil {
						require.Nil(t, receipt)
					} else {
						require.NotNil(t, receipt)

						originalHash := bytes.Clone(inTx.Hash())
						require.NoError(t, transaction.VerifyNativeValidationReceipt(nativeSource, receipt, inTx.Transaction().(*dataTransaction.Transaction), originalHash))

						for _, missing := range []string{"coordinator", "fees", "cache", "parser", "epochs", "hash-activation"} {
							foreign := nativeSource
							switch missing {
							case "coordinator":
								foreign.Coordinator = nil
							case "fees":
								foreign.FeeHandler = nil
							case "cache":
								foreign.VerifiedTransactions = nil
							case "parser":
								foreign.ArgsParser = nil
							case "epochs":
								foreign.EnableEpochsHandler = nil
							case "hash-activation":
								foreign.EnableSignedTxWithHash = !nativeSource.EnableSignedTxWithHash
							}
							require.Error(t, transaction.VerifyNativeValidationReceipt(foreign, receipt, inTx.Transaction().(*dataTransaction.Transaction), originalHash), missing)
						}
						require.Equal(t, encoded, receipt.OriginalBytes())
						currentTx := inTx.Transaction().(*dataTransaction.Transaction)
						originalNonce := currentTx.Nonce
						currentTx.Nonce++
						require.Nil(t, inTx.NativeValidationReceipt(), "changed native body cannot mint a new receipt")
						require.Error(t, transaction.VerifyNativeValidationReceipt(nativeSource, receipt, currentTx, originalHash))
						currentTx.Nonce = originalNonce
						require.NoError(t, transaction.VerifyNativeValidationReceipt(nativeSource, receipt, currentTx, originalHash), "restored independently signed control")
						publicHash := inTx.Hash()
						publicHash[0] ^= 1
						require.Error(t, transaction.VerifyNativeValidationReceipt(nativeSource, receipt, currentTx, publicHash))
						require.Equal(t, originalHash, inTx.NativeValidationReceipt().Hash(), "mutable public hash does not replace private original identity")
						publicHash[0] ^= 1
						wrongSource := nativeSource
						wrongSource.Signer = nil
						require.Error(t, transaction.VerifyNativeValidationReceipt(wrongSource, receipt, inTx.Transaction().(*dataTransaction.Transaction), originalHash))
						wrongSource = nativeSource
						wrongSource.Signer = &qualNativeReceiptCountingSigner{SingleSigner: signer.SingleSigner}
						require.Error(t, transaction.VerifyNativeValidationReceipt(wrongSource, receipt, inTx.Transaction().(*dataTransaction.Transaction), originalHash), "foreign real provider is not the bound native source")
						changedHash := bytes.Clone(originalHash)
						changedHash[0] ^= 1
						require.Error(t, transaction.VerifyNativeValidationReceipt(nativeSource, receipt, inTx.Transaction().(*dataTransaction.Transaction), changedHash))
						current := inTx.Transaction().(*dataTransaction.Transaction)
						before := bytes.Clone(current.Data)
						current.Data = append(bytes.Clone(before), '!')
						require.Nil(t, inTx.NativeValidationReceipt())
						require.Error(t, transaction.VerifyNativeValidationReceipt(nativeSource, receipt, current, originalHash))
						current.Data = before
						require.NoError(t, transaction.VerifyNativeValidationReceipt(nativeSource, receipt, current, originalHash), "restored valid control")
						copyOfBytes := receipt.OriginalBytes()
						copyOfBytes[len(copyOfBytes)-1] ^= 1
						require.Equal(t, encoded, receipt.OriginalBytes(), "receipt snapshots do not expose backing bytes")
						if attempt == 0 {
							cached, e := transaction.NewInterceptedTransaction(encoded, proto, signMarshal, hasher, keyGen, signer, converter, coordinator, fees, whiteList, smartContract.NewArgumentParser(), []byte(cfg.GeneralSettings.ChainID), epochs.IsFlagEnabled(common.TransactionSignedWithTxHashFlag), signHasher, version, epochs)
							require.NoError(t, e)
							require.True(t, whiteList.IsWhiteListed(cached))
							require.NoError(t, cached.CheckValidity())
							require.Nil(t, cached.NativeValidationReceipt(), "native cache presence alone is not a cryptographic observation on this object")
						}
					}
					require.Equal(t, checked, signer.checks.Load(), "receipt/check/cache-hit made no new native signature pass")
				}
				reencoded, e := proto.Marshal(inTx.Transaction())
				require.NoError(t, e)
				require.Equal(t, encoded, reencoded)
			})
		}
	}

	// Labelled actual-crypto native relay controls. No fixture claims execution,
	// business appointment, current account authority or production provenance.
	for _, form := range []string{"v1", "v2", "v3"} {
		for _, wrongInner := range []bool{false, true} {
			t.Run(fmt.Sprintf("receipt-relay-%s/wrong-origin-signature-%t", form, wrongInner), func(t *testing.T) {
				selectedEpochs := epochs
				selectedFees := fees
				if form != "v3" {
					legacyNotifier := forking.NewGenericEpochNotifier()
					var e error
					selectedEpochs, e = enablers.NewEnableEpochsHandler(epochCfg.EnableEpochs, legacyNotifier)
					require.NoError(t, e)
					selectedFees, e = economics.NewEconomicsData(economics.ArgsNewEconomicsData{TxVersionChecker: version, Economics: economicsCfg, ChainParamsHandler: chainParameters, EpochNotifier: legacyNotifier, EnableEpochsHandler: selectedEpochs, PubkeyConverter: converter, ShardCoordinator: coordinator})
					require.NoError(t, e)
					legacyNotifier.CheckEpoch(&block.Header{Epoch: 0})
					require.False(t, selectedEpochs.IsFlagEnabled(common.RelayedTransactionsV1V2DisableFlag))
				}
				ownerKey, ownerPub := keyGen.GeneratePair()
				owner, e := ownerPub.ToByteArray()
				require.NoError(t, e)
				relayerKey, relayerPub := keyGen.GeneratePair()
				relayer, e := relayerPub.ToByteArray()
				require.NoError(t, e)
				foreignKey, _ := keyGen.GeneratePair()
				inner := &dataTransaction.Transaction{Nonce: 1, Value: big.NewInt(0), SndAddr: owner, RcvAddr: owner, GasPrice: selectedFees.MinGasPrice(), Data: []byte("synthetic ordinary inner"), ChainID: []byte(cfg.GeneralSettings.ChainID), Version: core.InitialVersionOfTransaction}
				inner.GasLimit = selectedFees.ComputeGasLimit(inner)
				if form == "v2" {
					inner.GasLimit = 0
				} // Exact native signed V2 inner rule; no execution gas selected.
				if form == "v3" {
					inner.RelayerAddr = bytes.Clone(owner)
					inner.GasLimit = selectedFees.ComputeGasLimit(inner)
				} // Explicit native self-relay fixture.
				message, e := inner.GetDataForSigning(converter, signMarshal, signHasher)
				require.NoError(t, e)
				signingKey := ownerKey
				if wrongInner {
					signingKey = foreignKey
				}
				inner.Signature, e = signer.Sign(signingKey, message)
				require.NoError(t, e)
				var outer *dataTransaction.Transaction
				switch form {
				case "v1":
					payload, e := signMarshal.Marshal(inner)
					require.NoError(t, e)
					outer = &dataTransaction.Transaction{Value: big.NewInt(0), SndAddr: relayer, RcvAddr: owner, GasPrice: inner.GasPrice, Data: []byte(fmt.Sprintf("%s@%x", core.RelayedTransaction, payload)), ChainID: bytes.Clone(inner.ChainID), Version: inner.Version}
				case "v2":
					nonce := new(big.Int).SetUint64(inner.Nonce).Bytes()
					outer = &dataTransaction.Transaction{Value: big.NewInt(0), SndAddr: relayer, RcvAddr: owner, GasPrice: inner.GasPrice, Data: []byte(fmt.Sprintf("%s@%x@%x@%x@%x", core.RelayedTransactionV2, inner.RcvAddr, nonce, inner.Data, inner.Signature)), ChainID: bytes.Clone(inner.ChainID), Version: inner.Version}
				case "v3":
					outer = inner
					outer.RelayerSignature, e = signer.Sign(ownerKey, message)
					require.NoError(t, e)
				}
				if form != "v3" {
					outer.GasLimit = selectedFees.ComputeGasLimit(outer) + selectedFees.ComputeGasLimit(inner)
					message, e = outer.GetDataForSigning(converter, signMarshal, signHasher)
					require.NoError(t, e)
					outer.Signature, e = signer.Sign(relayerKey, message)
					require.NoError(t, e)
				}
				raw, e := proto.Marshal(outer)
				require.NoError(t, e)
				cache, e := storageunit.NewCache(storageFactory.GetCacherFromConfig(cfg.WhiteListerVerifiedTxs))
				require.NoError(t, e)
				t.Cleanup(func() { cache.Clear(); require.NoError(t, cache.Close()) })
				wl, e := interceptors.NewWhiteListDataVerifier(cache, 0)
				require.NoError(t, e)
				parser := smartContract.NewArgumentParser()
				in, e := transaction.NewInterceptedTransaction(raw, proto, signMarshal, hasher, keyGen, signer, converter, coordinator, selectedFees, wl, parser, []byte(cfg.GeneralSettings.ChainID), selectedEpochs.IsFlagEnabled(common.TransactionSignedWithTxHashFlag), signHasher, version, selectedEpochs)
				require.NoError(t, e)
				e = in.CheckValidity()
				if wrongInner {
					require.ErrorIs(t, e, crypto.ErrEd25519InvalidSignature)
					require.Nil(t, in.NativeValidationReceipt())
					return
				}
				require.NoError(t, e)
				before := signer.checks.Load()
				receipt := in.NativeValidationReceipt()
				require.NotNil(t, receipt)
				source := transaction.NativeValidationSource{ProtoMarshalizer: proto, SignMarshalizer: signMarshal, Hasher: hasher, TxSignHasher: signHasher, KeyGen: keyGen, Signer: signer, Converter: converter, VersionChecker: version, Coordinator: coordinator, FeeHandler: selectedFees, VerifiedTransactions: wl, ArgsParser: parser, EnableEpochsHandler: selectedEpochs, EnableSignedTxWithHash: selectedEpochs.IsFlagEnabled(common.TransactionSignedWithTxHashFlag), ChainID: cfg.GeneralSettings.ChainID}
				require.NoError(t, transaction.VerifyNativeValidationReceipt(source, receipt, in.Transaction().(*dataTransaction.Transaction), in.Hash()))
				require.Equal(t, raw, receipt.OriginalBytes())
				expectedInner := *inner
				if form == "v3" {
					expectedInner.RelayerSignature = []byte{}
				}
				expectedRaw, e := proto.Marshal(&expectedInner)
				require.NoError(t, e)
				require.Equal(t, expectedRaw, receipt.InnerBytes())
				require.Equal(t, before, signer.checks.Load(), "static observation does not reverify signatures")
			})
		}
	}
}
