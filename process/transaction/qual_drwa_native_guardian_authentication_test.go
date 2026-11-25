package transaction_test

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"
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
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/dataRetriever/txpool"
	"github.com/multiversx/mx-chain-go/epochStart/notifier"
	"github.com/multiversx/mx-chain-go/p2p"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/economics"
	"github.com/multiversx/mx-chain-go/process/interceptors"
	"github.com/multiversx/mx-chain-go/process/interceptors/processor"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/storage"
	storageFactory "github.com/multiversx/mx-chain-go/storage/factory"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	cacheFixture "github.com/multiversx/mx-chain-go/testscommon/cache"
	"github.com/multiversx/mx-chain-go/testscommon/txcachemocks/mempool"
	"github.com/multiversx/mx-chain-go/txcache"
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

// Called only with a real native signed/validated DRWA-routed control. Synthetic capacities
// and the gas-host fixture test cache mechanics, not economics or appointment.
type qualD19ReceiptPool interface {
	dataRetriever.ShardedDataCacherNotifier
	ConfigureNativeValidationSource(*transaction.NativeValidationSource) error
	NativeValidationReceiptEnabled() bool
	AddData([]byte, interface{}, int, string)
	AddDataWithNativeValidationReceipt([]byte, interface{}, int, string, *transaction.NativeValidationReceipt)
	NativeValidationReceiptFor([]byte, string, *dataTransaction.Transaction) *transaction.NativeValidationReceipt
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
	tx := inTx.Transaction().(*dataTransaction.Transaction)
	key := bytes.Clone(inTx.Hash())
	receipt := inTx.NativeValidationReceipt()
	require.NotNil(t, receipt)
	retainedCharge := receipt.RetainedSize() + int64(cap(bytes.Clone(key))) + txcache.ValidationReceiptEntrySize
	require.Greater(t, receipt.RetainedSize(), int64(len(receipt.OriginalBytes())+len(receipt.InnerBytes())+len(receipt.Hash())))
	t.Run("receipt-does-not-override-native-cache-rejection", func(t *testing.T) {
		pool := newPool()
		require.NoError(t, pool.ConfigureNativeValidationSource(&source))
		pool.AddDataWithNativeValidationReceipt(key, tx, tx.Size(), "invalid-cache-id", receipt)
		pool.AddDataWithNativeValidationReceipt(key, tx, -1, "invalid-cache-id", receipt)
		_, exists := pool.SearchFirstData(key)
		require.False(t, exists)
		require.Nil(t, pool.NativeValidationReceiptFor(key, "0_0", tx))
	})
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
			getEntry := func(pool qualD19ReceiptPool, cacheID string) (*txcache.WrappedTransaction, interface{}) {
				cache := pool.ShardDataStore(cacheID).(interface {
					GetByTxHashWithValidationReceipt([]byte) (*txcache.WrappedTransaction, interface{}, bool)
				})
				wrapped, metadata, found := cache.GetByTxHashWithValidationReceipt(key)
				require.True(t, found)
				return wrapped, metadata
			}
			getWrapped := func(pool qualD19ReceiptPool, cacheID string) *txcache.WrappedTransaction {
				wrapped, _ := getEntry(pool, cacheID)
				return wrapped
			}
			ordinaryEntry, ordinaryMetadata := getEntry(ordinary, route)
			require.Equal(t, int64(tx.Size()), ordinaryEntry.Size)
			require.Nil(t, ordinaryMetadata)

			// A configured pool still inserts an ordinary native entry when
			// there is no observation for this transaction. Inspect the raw
			// cache entry and charge before the later lookup can reject it.
			unobserved := newPool()
			require.NoError(t, unobserved.ConfigureNativeValidationSource(&source))
			unobserved.AddDataWithNativeValidationReceipt(key, tx, tx.Size(), route, nil)
			entry, unobservedMetadata := getEntry(unobserved, route)
			require.Same(t, tx, entry.Tx)
			require.Nil(t, unobservedMetadata, "unobserved entry has no receipt")
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
