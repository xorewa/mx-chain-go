package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
)

// readNativeSCR joins the existing complete-origin read to one native SCR.
// The original B-admission, historical-context and funding gates of read remain
// caller obligations. This pointwise binding does not discover a whole carrier
// group, establish execution eligibility, apply an item or consume service gas.
func (r *pendingFinalRecords) readNativeSCR(native *canonicalResultReader, committedB []byte, consumer, producer uint32,
	origin []byte, w canonicalResultWitness, miniBlockRaw, scrRaw []byte, byteLimit int,
) ([]byte, *smartContractResult.SmartContractResult, error) {
	observed, err := r.readNativeSCRObservation(native, committedB, consumer, producer, origin, w, miniBlockRaw, scrRaw, byteLimit)
	if err != nil {
		return nil, nil, err
	}
	return observed.originCommitment, observed.result, nil
}

func (r *pendingFinalRecords) readNativeSCRObservation(native *canonicalResultReader, committedB []byte, consumer, producer uint32,
	origin []byte, w canonicalResultWitness, miniBlockRaw, scrRaw []byte, byteLimit int,
) (*nativeSCRCarrierObservation, error) {
	if native == nil || native.accounts == nil || consumer == producer || consumer == core.MetachainShardId || producer == core.MetachainShardId ||
		len(committedB) == 0 || len(committedB) > byteLimit ||
		len(origin) == 0 || len(origin) > byteLimit ||
		len(miniBlockRaw) == 0 || len(scrRaw) == 0 || len(miniBlockRaw) > byteLimit {
		return nil, ErrInvalidAccountWitness
	}
	if len(scrRaw) > byteLimit-len(miniBlockRaw) {
		return nil, ErrInvalidAccountWitness
	}
	witnessLimit := byteLimit - len(miniBlockRaw) - len(scrRaw)
	if _, err := canonicalWitnessRemaining(w, witnessLimit); err != nil {
		return nil, err
	}
	committedB, origin = bytes.Clone(committedB), bytes.Clone(origin)
	miniBlockRaw, scrRaw = bytes.Clone(miniBlockRaw), bytes.Clone(scrRaw)
	w = cloneCanonicalResultWitness(w)
	itemKey, err := r.key("origin", origin)
	if err != nil {
		return nil, err
	}
	projection, err := native.readBoundedContext(committedB, consumer, producer, origin, w)
	if err != nil {
		return nil, err
	}
	value, err := native.accounts.Read(projection.carryingHash, producer, core.SystemAccountAddress, itemKey, w.Account, witnessLimit)
	if err != nil {
		return nil, err
	}
	miniBlock := &block.MiniBlock{}
	if native.accounts.args.Marshaller.Unmarshal(miniBlock, miniBlockRaw) != nil ||
		miniBlock.Type != block.SmartContractResultBlock ||
		miniBlock.SenderShardID != producer || miniBlock.ReceiverShardID != consumer {
		return nil, ErrInvalidAccountWitness
	}
	miniBlockHash := bytes.Clone(native.accounts.args.Hasher.Compute(string(miniBlockRaw)))
	sourceOrigins, sourceReferences := 0, 0
	for _, result := range projection.carryingHeader.(*block.HeaderV3).ExecutionResults {
		if result == nil || result.BaseExecutionResult == nil ||
			!bytes.Equal(result.BaseExecutionResult.HeaderHash, origin) {
			continue
		}
		sourceOrigins++
		for _, header := range result.GetMiniBlockHeadersHandlers() {
			if nativeSCRHeaderMatches(header, miniBlockHash, miniBlock) {
				sourceReferences++
			}
		}
	}
	// The native broad lookup also searches unrelated execution-result headers.
	// Here only this origin's result and B's direct proposal references count.
	consumerReferences := 0
	b := projection.consumerHeader
	for _, header := range b.GetMiniBlockHeaderHandlers() {
		if nativeSCRHeaderMatches(header, miniBlockHash, miniBlock) {
			consumerReferences++
		}
	}
	if sourceOrigins != 1 || sourceReferences != 1 || consumerReferences != 1 {
		return nil, ErrInvalidAccountWitness
	}
	scrHash := bytes.Clone(native.accounts.args.Hasher.Compute(string(scrRaw)))
	matches := 0
	for _, txHash := range miniBlock.TxHashes {
		if bytes.Equal(txHash, scrHash) {
			matches++
		}
	}
	if matches != 1 {
		return nil, ErrInvalidAccountWitness
	}
	scr := &smartContractResult.SmartContractResult{}
	if native.accounts.args.Marshaller.Unmarshal(scr, scrRaw) != nil || scr.CheckIntegrity() != nil {
		return nil, ErrInvalidAccountWitness
	}
	return &nativeSCRCarrierObservation{
		originCommitment: bytes.Clone(value), result: scr,
		producer: producer, consumer: consumer,
		originHash:         origin,
		carryingHeaderHash: projection.carryingHash,
		consumerHeaderHash: committedB, metaHeaderHashes: projection.metaHeaderHashes,
		miniBlockHash: miniBlockHash, resultHash: scrHash,
		asOfNonce: b.GetNonce(), asOfRound: b.GetRound(), asOfEpoch: b.GetEpoch(),
	}, nil
}

func nativeSCRHeaderMatches(header data.MiniBlockHeaderHandler, hash []byte, miniBlock *block.MiniBlock) bool {
	return header != nil && bytes.Equal(header.GetHash(), hash) &&
		header.GetSenderShardID() == miniBlock.SenderShardID &&
		header.GetReceiverShardID() == miniBlock.ReceiverShardID &&
		header.GetTypeInt32() == int32(block.SmartContractResultBlock) &&
		uint64(header.GetTxCount()) == uint64(len(miniBlock.TxHashes))
}
