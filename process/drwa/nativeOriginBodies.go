package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-go/process"
)

// nativeOriginSCRBodies resolves every SCR fragment of one already known origin
// for this destination. Input order and local availability cannot choose a
// prefix. The native source references, then each miniblock's TxHashes, own order.
//
// This is read-only discovery, including fragments absent from B's proposals.
// It does not establish first eligibility, class applicability or authenticated
// class no-work. It must not be used to call ProcessMiniBlock or promoteResult
// until their native admission, host, historical and paid-service gates hold.
func (r *pendingFinalRecords) nativeOriginSCRBodies(native *canonicalResultReader, committedB []byte,
	consumer, producer uint32, origin []byte, w canonicalResultWitness,
	miniBlockRaws, scrRaws [][]byte, byteLimit int,
) ([]byte, *block.Body, []*smartContractResult.SmartContractResult, error) {
	if native == nil || byteLimit <= 0 {
		return nil, nil, nil, ErrInvalidAccountWitness
	}
	// Bound and freeze all supplied payloads before proof callbacks or decoding.
	// This is a byte/work bound supplied by the owner, not a service tariff.
	remaining := byteLimit
	for _, raws := range [][][]byte{miniBlockRaws, scrRaws} {
		for _, raw := range raws {
			if len(raw) == 0 || len(raw) > remaining {
				return nil, nil, nil, ErrInvalidAccountWitness
			}
			remaining -= len(raw)
		}
	}
	miniBlocks := make(map[string][]byte, len(miniBlockRaws))
	transactions := make(map[string][]byte, len(scrRaws))
	for i, raws := range [][][]byte{miniBlockRaws, scrRaws} {
		target := miniBlocks
		if i == 1 {
			target = transactions
		}
		for _, raw := range raws {
			frozen := bytes.Clone(raw)
			key := string(native.accounts.args.Hasher.Compute(string(frozen)))
			if _, duplicate := target[key]; duplicate {
				return nil, nil, nil, ErrInvalidAccountWitness
			}
			target[key] = frozen
		}
	}
	value, references, err := r.nativeOriginSCRReferences(native, committedB, consumer, producer, origin, w, remaining)
	if err != nil {
		return nil, nil, nil, err
	}
	body := &block.Body{}
	var scrs []*smartContractResult.SmartContractResult
	seenFragments := make(map[string]struct{}, len(references))
	seenTransactions := make(map[string]struct{}, len(transactions))
	for _, header := range references {
		key := string(header.GetHash())
		if _, duplicate := seenFragments[key]; duplicate {
			return nil, nil, nil, ErrInvalidAccountWitness
		}
		seenFragments[key] = struct{}{}
		raw, available := miniBlocks[key]
		if !available {
			return nil, nil, nil, process.ErrMissingMiniBlock
		}
		miniBlock := &block.MiniBlock{}
		if native.accounts.args.Marshaller.Unmarshal(miniBlock, raw) != nil ||
			!nativeSCRHeaderMatches(header, header.GetHash(), miniBlock) ||
			miniBlock.Type != block.SmartContractResultBlock {
			return nil, nil, nil, ErrInvalidAccountWitness
		}
		body.MiniBlocks = append(body.MiniBlocks, miniBlock)
		for _, hash := range miniBlock.TxHashes {
			txKey := string(hash)
			if _, duplicate := seenTransactions[txKey]; duplicate {
				return nil, nil, nil, ErrInvalidAccountWitness
			}
			seenTransactions[txKey] = struct{}{}
			txRaw, available := transactions[txKey]
			if !available {
				return nil, nil, nil, process.ErrMissingTransaction
			}
			scr := &smartContractResult.SmartContractResult{}
			if native.accounts.args.Marshaller.Unmarshal(scr, txRaw) != nil || scr.CheckIntegrity() != nil {
				return nil, nil, nil, ErrInvalidAccountWitness
			}
			scrs = append(scrs, scr)
		}
	}
	if len(seenFragments) != len(miniBlocks) || len(seenTransactions) != len(transactions) {
		return nil, nil, nil, ErrInvalidAccountWitness
	}
	// Empty fragments/transactions preserve value. They do not discharge the
	// class list or authorize no-work, application, tracker removal or charging.
	return value, body, scrs, nil
}

// nativeOriginSCRGroup binds the complete registered commitment list for one
// already known source origin to its candidate preimages and native SCR bodies.
// It is read-only. All class records are returned in registration order; this
// does not establish consumer applicability, U_B, first eligibility or funding.
func (r *pendingFinalRecords) nativeOriginSCRGroup(native *canonicalResultReader, committedB []byte,
	consumer, producer uint32, origin []byte, w canonicalResultWitness,
	candidates []pendingFinalCandidate, miniBlockRaws, scrRaws [][]byte, byteLimit int,
) ([]pendingFinalCandidate, *block.Body, []*smartContractResult.SmartContractResult, error) {
	if native == nil || byteLimit <= 0 {
		return nil, nil, nil, ErrInvalidAccountWitness
	}
	origin = bytes.Clone(origin)
	remaining := byteLimit
	var frozen []pendingFinalCandidate
	var digests [][]byte
	// Freeze and bound preimages before any proof callback. Missing local
	// preimages may refuse construction; they cannot choose a committed prefix.
	for _, candidate := range candidates {
		if len(candidate.key) > remaining || len(candidate.body) > remaining ||
			len(candidate.origin) > remaining || len(candidate.predecessor) > remaining {
			return nil, nil, nil, ErrInvalidAccountWitness
		}
		c := pendingFinalCandidate{key: bytes.Clone(candidate.key), version: candidate.version,
			predecessor: bytes.Clone(candidate.predecessor), body: bytes.Clone(candidate.body), origin: bytes.Clone(candidate.origin)}
		encoded, err := r.encode(c)
		if err != nil {
			return nil, nil, nil, err
		}
		if len(encoded) > remaining {
			return nil, nil, nil, ErrInvalidAccountWitness
		}
		remaining -= len(encoded)
		if !bytes.Equal(c.origin, origin) {
			return nil, nil, nil, errPendingFinal
		}
		frozen = append(frozen, c)
		digests = append(digests, r.codec.hasher.Compute(string(encoded)))
	}
	value, body, scrs, err := r.nativeOriginSCRBodies(native, committedB, consumer, producer,
		origin, w, miniBlockRaws, scrRaws, remaining)
	if err != nil {
		return nil, nil, nil, err
	}
	committed, err := r.decodeOriginItems(value)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(committed) != len(digests) {
		return nil, nil, nil, errPendingFinal
	}
	for i, digest := range committed {
		if !bytes.Equal(digest, digests[i]) {
			return nil, nil, nil, errPendingFinal
		}
	}
	return frozen, body, scrs, nil
}
