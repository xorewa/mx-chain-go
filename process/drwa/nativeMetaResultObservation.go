package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-go/dataRetriever"
)

type nativeMetaSCRContext struct {
	committedB, origin, previous, original []byte
	consumer                               uint32
	witness                                canonicalResultWitness
	witnessBytes                           int
}

// readNativeMetaSCRObservation binds one native Meta output to its immediate
// operation AND original transaction identities (Part B 12.3/AM-012). Native
// setOriginalTxHash preserves that distinction for chained results. Neither a
// native success marker nor this observation finalizes a business operation.
//
// This is pointwise transaction evidence, not S1 complete-origin consumption:
// originCommitment stays absent and is NOT authenticated class no-work. The S1
// entry, receiving/application, source completion and accounting are unchanged.
// Actual B/context, verifier/cache/history and source-funded service admission
// remain caller duties. This installs no endpoint, authority, wire or tariff.
func (r *canonicalResultReader) readNativeMetaSCRObservation(committedB []byte, consumer uint32,
	origin, previous, original []byte, w canonicalResultWitness, miniBlockRaw, scrRaw []byte, byteLimit int,
) (*nativeSCRCarrierObservation, error) {
	if len(miniBlockRaw) == 0 || len(miniBlockRaw) > byteLimit ||
		len(scrRaw) == 0 || len(scrRaw) > byteLimit-len(miniBlockRaw) {
		return nil, ErrInvalidAccountWitness
	}
	context, _, err := r.snapshotNativeMetaSCRContext(committedB, consumer, origin, previous, original, w,
		byteLimit-len(miniBlockRaw)-len(scrRaw))
	if err != nil {
		return nil, err
	}

	miniBlockRaw, scrRaw = bytes.Clone(miniBlockRaw), bytes.Clone(scrRaw)
	if err := r.validateNativeMetaSCRIdentity(context); err != nil {
		return nil, err
	}
	return r.decodeNativeMetaSCRObservation(context, miniBlockRaw, scrRaw)
}

// The caller supplies the exact branch and as-of block. The storage epoch is
// only a lookup location. A read failure supplies no observation.
func (r *canonicalResultReader) readStoredNativeMetaSCRObservation(source dataRetriever.StorageService, storageEpoch uint32,
	miniBlockHash, resultHash, committedB []byte, consumer uint32, origin, previous, original []byte,
	w canonicalResultWitness, byteLimit int,
) (*nativeSCRCarrierObservation, error) {
	context, remaining, err := r.snapshotNativeMetaSCRContext(committedB, consumer, origin, previous, original, w, byteLimit)
	if err != nil {
		return nil, err
	}
	if len(miniBlockHash) > remaining || len(resultHash) > remaining-len(miniBlockHash) {
		return nil, ErrInvalidAccountWitness
	}
	miniBlockHash, resultHash = bytes.Clone(miniBlockHash), bytes.Clone(resultHash)
	if err = r.validateNativeMetaSCRIdentity(context); err != nil {
		return nil, err
	}
	miniBlockRaw, scrRaw, err := r.accounts.ReadNativeSCRPayloads(source, storageEpoch, miniBlockHash, resultHash, remaining)
	if err != nil {
		return nil, err
	}

	return r.decodeNativeMetaSCRObservation(context, miniBlockRaw, scrRaw)
}

func (r *canonicalResultReader) snapshotNativeMetaSCRContext(committedB []byte, consumer uint32,
	origin, previous, original []byte, w canonicalResultWitness, byteLimit int,
) (nativeMetaSCRContext, int, error) {
	if r == nil || r.accounts == nil || consumer == core.MetachainShardId || byteLimit <= 0 {
		return nativeMetaSCRContext{}, 0, ErrInvalidAccountWitness
	}
	// Bound the complete snapshot before allocating it or reading native storage.
	// This bounds input bytes, not gas, storage work or retries.
	remaining := byteLimit
	charge := func(raw []byte) bool {
		if len(raw) == 0 || len(raw) > remaining {
			return false
		}
		remaining -= len(raw)
		return true
	}
	for _, raw := range [][]byte{committedB, origin, previous, original} {
		if !charge(raw) {
			return nativeMetaSCRContext{}, 0, ErrInvalidAccountWitness
		}
	}
	witnessLimit := remaining
	if len(w.MetaHeaders) == 0 || len(w.MetaHeaders) != len(w.MetaProofs) || len(w.MetaHeaders) > remaining/2 {
		return nativeMetaSCRContext{}, 0, ErrInvalidAccountWitness
	}
	for _, raw := range [][]byte{w.Consumer, w.Account.Header, w.Account.ExecutedHeader} {
		if !charge(raw) {
			return nativeMetaSCRContext{}, 0, ErrInvalidAccountWitness
		}
	}
	if len(w.HeaderProof) > remaining {
		return nativeMetaSCRContext{}, 0, ErrInvalidAccountWitness
	}
	remaining -= len(w.HeaderProof)
	for _, list := range [][][]byte{w.MetaHeaders, w.MetaProofs, w.Account.AccountProof, w.Account.DataProof} {
		for _, raw := range list {
			if !charge(raw) {
				return nativeMetaSCRContext{}, 0, ErrInvalidAccountWitness
			}
		}
	}
	return nativeMetaSCRContext{
		committedB:   bytes.Clone(committedB),
		origin:       bytes.Clone(origin),
		previous:     bytes.Clone(previous),
		original:     bytes.Clone(original),
		consumer:     consumer,
		witness:      cloneCanonicalResultWitness(w),
		witnessBytes: witnessLimit - remaining,
	}, remaining, nil
}

func (r *canonicalResultReader) validateNativeMetaSCRIdentity(context nativeMetaSCRContext) error {
	if check.IfNil(r.accounts.args.Hasher) || check.IfNil(r.accounts.args.Marshaller) {
		return ErrInvalidAccountWitness
	}
	size := r.accounts.args.Hasher.Size()
	if size <= 0 || len(context.previous) != size || len(context.original) != size {
		return ErrInvalidAccountWitness
	}
	return nil
}

func (r *canonicalResultReader) decodeNativeMetaSCRObservation(context nativeMetaSCRContext,
	miniBlockRaw, scrRaw []byte,
) (*nativeSCRCarrierObservation, error) {
	committedB, origin, previous, original := context.committedB, context.origin, context.previous, context.original
	w, consumer := context.witness, context.consumer
	projection, err := r.readContext(committedB, consumer, core.MetachainShardId, origin, w, context.witnessBytes)
	if err != nil {
		return nil, err
	}
	// Keep the native S/H execution-result identity/uniqueness checks even though
	// this SCR observation does not read an account leaf or protected class list.
	if _, err = r.accounts.executionRoot(core.MetachainShardId, w.Account); err != nil {
		return nil, err
	}
	meta, ok := projection.carryingHeader.(*block.MetaBlockV3)
	if !ok || meta == nil {
		return nil, ErrInvalidAccountWitness
	}
	miniBlock := &block.MiniBlock{}
	if r.accounts.args.Marshaller.Unmarshal(miniBlock, miniBlockRaw) != nil ||
		miniBlock.SenderShardID != core.MetachainShardId || miniBlock.ReceiverShardID != consumer ||
		miniBlock.Type != block.SmartContractResultBlock {
		return nil, ErrInvalidAccountWitness
	}
	hash := r.accounts.args.Hasher.Compute
	miniHash, resultHash := bytes.Clone(hash(string(miniBlockRaw))), bytes.Clone(hash(string(scrRaw)))
	matchedOrigin, matchedHeader, matchedResult := 0, 0, 0
	for _, result := range meta.ExecutionResults {
		if result == nil || result.ExecutionResult == nil || result.ExecutionResult.BaseExecutionResult == nil ||
			!bytes.Equal(result.GetHeaderHash(), origin) {
			continue
		}
		matchedOrigin++
		for _, header := range result.GetMiniBlockHeadersHandlers() {
			if nativeSCRHeaderMatches(header, miniHash, miniBlock) {
				matchedHeader++
			}
		}
	}
	for _, txHash := range miniBlock.TxHashes {
		if bytes.Equal(txHash, resultHash) {
			matchedResult++
		}
	}
	if matchedOrigin != 1 || matchedHeader != 1 || matchedResult != 1 {
		return nil, ErrInvalidAccountWitness
	}
	result := &smartContractResult.SmartContractResult{}
	if r.accounts.args.Marshaller.Unmarshal(result, scrRaw) != nil || result.CheckIntegrity() != nil ||
		!bytes.Equal(result.PrevTxHash, previous) || !bytes.Equal(result.OriginalTxHash, original) {
		return nil, ErrInvalidAccountWitness
	}
	b := projection.consumerHeader
	return &nativeSCRCarrierObservation{result: result, producer: core.MetachainShardId, consumer: consumer,
		originHash: origin, carryingHeaderHash: projection.carryingHash, consumerHeaderHash: committedB,
		metaHeaderHashes: projection.metaHeaderHashes, miniBlockHash: miniHash, resultHash: resultHash,
		asOfNonce: b.GetNonce(), asOfRound: b.GetRound(), asOfEpoch: b.GetEpoch()}, nil
}
