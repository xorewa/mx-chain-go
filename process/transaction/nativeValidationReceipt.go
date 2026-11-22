package transaction

import (
	"bytes"
	"reflect"
	"unsafe"

	"github.com/multiversx/mx-chain-core-go/core"
	nativeTransaction "github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/vm"
)

// NativeValidationSource is the existing native factory's explicit provider
// binding, not caller metadata or a default verifier. The execution owner must
// bind its actual admitted providers; none are selected by a receipt.
// Provider correspondence does not admit their official provenance or current
// native context, appointment, original-G6 lease, fees or funding.
type NativeValidationSource struct {
	ProtoMarshalizer, SignMarshalizer marshal.Marshalizer
	Hasher, TxSignHasher              hashing.Hasher
	KeyGen                            crypto.KeyGenerator
	Signer                            crypto.SingleSigner
	Converter                         core.PubkeyConverter
	VersionChecker                    process.TxVersionCheckerHandler
	Coordinator                       sharding.Coordinator
	FeeHandler                        process.FeeHandler
	VerifiedTransactions              process.WhiteListHandler
	ArgsParser                        process.ArgumentsParser
	EnableEpochsHandler               common.EnableEpochsHandler
	EnableSignedTxWithHash            bool
	ChainID                           string
}

// NativeValidationReceipt has no accepting constructor or exported fields.
// Only the actual native CheckValidity cryptographic path can supply its
// private observation. It is static validated input, NOT an operation lifetime
// or permission to act for a programme. In particular a native verified-cache
// hit on a different object cannot manufacture this observation.
type NativeValidationReceipt struct {
	source                NativeValidationSource
	original, inner, hash []byte
	validated             bool
}

// RetainedSize reports this immutable observation's own allocation, including
// owned buffer capacities and its chain string. Provider objects are existing
// node-owned dependencies, not copied into each cache entry. This is cache
// accounting, never a transaction fee or authority claim.
func (r *NativeValidationReceipt) RetainedSize() int64 {
	if r == nil {
		return 0
	}
	size := uint64(unsafe.Sizeof(*r) + unsafe.Sizeof(any(r)))
	for _, n := range []int{cap(r.original), cap(r.inner), cap(r.hash), len(r.source.ChainID)} {
		if uint64(n) > uint64(1<<63-1)-size {
			return -1
		}
		size += uint64(n)
	}
	return int64(size)
}

// RequiresDRWANativeValidationReceipt is only the existing metachain native
// registration-route discriminator. It is not authority, signature validation,
// programme classification or permission to execute. Ordinary calls retain the
// native pool path and allocate no retained validation observation.
func RequiresDRWANativeValidationReceipt(tx *nativeTransaction.Transaction) bool {
	if tx == nil || !bytes.Equal(tx.RcvAddr, core.ESDTSCAddress) {
		return false
	}
	function, _, _ := bytes.Cut(tx.Data, []byte("@"))
	return string(function) == "DRWARegisterBootstrapIntent" || string(function) == "DRWARegisterToken"
}

func (inTx *InterceptedTransaction) RequiresDRWANativeValidationReceipt() bool {
	return inTx != nil && RequiresDRWANativeValidationReceipt(inTx.tx)
}

// NativeValidationReceipt snapshots exact native input only on request. Normal
// CheckValidity makes no extra codec/signature call. Its frozen private hash
// prevents mutation of Transaction()/Hash() buffers from re-binding validation.
func (inTx *InterceptedTransaction) NativeValidationReceipt() *NativeValidationReceipt {
	if inTx == nil || !inTx.nativeCryptoValidated || inTx.nativeOriginalHash == "" {
		return nil
	}
	raw, err := inTx.protoMarshalizer.Marshal(inTx.tx)
	if err != nil || string(inTx.hasher.Compute(string(raw))) != inTx.nativeOriginalHash {
		return nil
	}
	var inner []byte
	if inTx.nativeValidatedInner != nil {
		inner, err = inTx.protoMarshalizer.Marshal(inTx.nativeValidatedInner)
		if err != nil {
			return nil
		}
	}
	return &NativeValidationReceipt{source: NativeValidationSource{
		ProtoMarshalizer: inTx.protoMarshalizer, SignMarshalizer: inTx.signMarshalizer, Hasher: inTx.hasher, TxSignHasher: inTx.txSignHasher,
		KeyGen: inTx.keyGen, Signer: inTx.singleSigner, Converter: inTx.pubkeyConv, VersionChecker: inTx.txVersionChecker, ChainID: string(inTx.chainID), Coordinator: inTx.coordinator, FeeHandler: inTx.feeHandler, VerifiedTransactions: inTx.whiteListerVerifiedTxs, ArgsParser: inTx.argsParser, EnableEpochsHandler: inTx.enableEpochsHandler, EnableSignedTxWithHash: inTx.enableSignedTxWithHash,
	}, original: bytes.Clone(raw), inner: bytes.Clone(inner), hash: []byte(inTx.nativeOriginalHash), validated: true}
}

func (r *NativeValidationReceipt) OriginalBytes() []byte {
	if r == nil {
		return nil
	}
	return bytes.Clone(r.original)
}
func (r *NativeValidationReceipt) InnerBytes() []byte {
	if r == nil {
		return nil
	}
	return bytes.Clone(r.inner)
}
func (r *NativeValidationReceipt) Hash() []byte {
	if r == nil {
		return nil
	}
	return bytes.Clone(r.hash)
}

func sameNativeValidationDependency(a, b any) bool {
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	if !av.IsValid() || !bv.IsValid() || av.Type() != bv.Type() || !av.Comparable() || !bv.Comparable() {
		return false
	}
	if av.Kind() == reflect.Pointer && (av.IsNil() || bv.IsNil()) {
		return false
	}
	return av.Interface() == bv.Interface()
}

// VerifyNativeValidationReceipt reuses the actual native codec/hash and the
// already-executed signature result. It never performs another signature pass.
// Sources must be the qualified factory inputs, never copied from the receipt.
// Matching this static observation does not authorize an inner/effective
// transaction, SCR/callback, current header/store or native operation. Those
// owning comparisons must precede the single all-effect consumer.
func VerifyNativeValidationReceipt(source NativeValidationSource, r *NativeValidationReceipt, tx *nativeTransaction.Transaction, expectedHash []byte) error {
	if r == nil || !r.validated || tx == nil || source.ChainID == "" || source.ChainID != r.source.ChainID || source.EnableSignedTxWithHash != r.source.EnableSignedTxWithHash {
		return vm.ErrDRWAExecution
	}
	pairs := [][2]any{{source.ProtoMarshalizer, r.source.ProtoMarshalizer}, {source.SignMarshalizer, r.source.SignMarshalizer},
		{source.Hasher, r.source.Hasher}, {source.TxSignHasher, r.source.TxSignHasher}, {source.KeyGen, r.source.KeyGen},
		{source.Signer, r.source.Signer}, {source.Converter, r.source.Converter}, {source.VersionChecker, r.source.VersionChecker}, {source.Coordinator, r.source.Coordinator}, {source.FeeHandler, r.source.FeeHandler}, {source.VerifiedTransactions, r.source.VerifiedTransactions}, {source.ArgsParser, r.source.ArgsParser}, {source.EnableEpochsHandler, r.source.EnableEpochsHandler}}
	for _, pair := range pairs {
		if !sameNativeValidationDependency(pair[0], pair[1]) {
			return vm.ErrDRWAExecution
		}
	}
	if !bytes.Equal(tx.ChainID, []byte(source.ChainID)) || len(expectedHash) != source.Hasher.Size() || !bytes.Equal(expectedHash, r.hash) {
		return vm.ErrDRWAExecution
	}
	raw, err := source.ProtoMarshalizer.Marshal(tx)
	if err != nil || !bytes.Equal(raw, r.original) || !bytes.Equal(source.Hasher.Compute(string(raw)), r.hash) {
		return vm.ErrDRWAExecution
	}
	return nil
}
