package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever/dataPool/headersCache"
	proofscache "github.com/multiversx/mx-chain-go/dataRetriever/dataPool/proofsCache"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/track"
)

// canonicalResultWitness is a DRWA prototype input, not an allocated wire form.
// MetaHeaders/MetaProofs are paired native protobuf bytes. Their arrival order
// is immaterial: the reader follows only the ancestry selected by B. The account
// proof authenticates the origin's COMPLETE bounded finalization commitment list.
type canonicalResultWitness struct {
	Consumer                []byte
	Account                 AccountItemWitness
	HeaderProof             []byte
	MetaHeaders, MetaProofs [][]byte
}

// canonicalResultReader composes existing native proof, ancestry, positive
// reconciliation and account-trie checks. It has no node-local finality view.
// The owner must independently admit B and the native header/result/projection
// context through the pinned processors, and bind epoch/configuration, exclusion
// history and a dedicated proof cache before calling it. Hashes supplied by a
// requester cannot select that context. No runtime owner is installed here.
//
// Prototype choice authorized by the owner: require the EXISTING positive native
// reconciliation witness even on the normally one-child path. This delays that
// normal path; it neither invents a depth nor closes AR-01 DESIGN_OPEN.
type canonicalResultReader struct {
	accounts   *ResultAccountReader
	validator  process.HeaderConstructionValidator
	proofs     process.InterceptedHeaderSigVerifier
	integrity  process.HeaderIntegrityVerifier
	exclusions common.RoundExclusionHandler
}

func newCanonicalResultReader(accounts *ResultAccountReader, validator process.HeaderConstructionValidator,
	proofs process.InterceptedHeaderSigVerifier, integrity process.HeaderIntegrityVerifier,
	exclusions common.RoundExclusionHandler) (*canonicalResultReader, error) {
	if accounts == nil || check.IfNil(validator) || check.IfNil(proofs) || check.IfNil(integrity) || check.IfNil(exclusions) {
		return nil, ErrInvalidAccountWitness
	}
	return &canonicalResultReader{accounts: accounts, validator: validator, proofs: proofs, integrity: integrity, exclusions: exclusions}, nil
}

func (r *canonicalResultReader) header(raw []byte, shard uint32) (data.HeaderHandler, error) {
	var h data.HeaderHandler = &block.HeaderV3{}
	if shard == core.MetachainShardId {
		h = &block.MetaBlockV3{}
	}
	if len(raw) == 0 || r.accounts.args.Marshaller.Unmarshal(h, raw) != nil || h.GetShardID() != shard {
		return nil, ErrInvalidAccountWitness
	}
	if err := r.integrity.Verify(h); err != nil {
		return nil, err
	}
	return h, nil
}

func (r *canonicalResultReader) proof(raw []byte, header data.HeaderHandler, hash []byte) (*block.HeaderProof, error) {
	p := &block.HeaderProof{}
	if len(raw) == 0 || r.accounts.args.Marshaller.Unmarshal(p, raw) != nil ||
		!bytes.Equal(p.HeaderHash, hash) || p.HeaderShardId != header.GetShardID() ||
		p.HeaderNonce != header.GetNonce() || p.HeaderRound != header.GetRound() ||
		p.HeaderEpoch != header.GetEpoch() || p.IsStartOfEpoch != header.IsStartOfEpochBlock() ||
		common.IsHeaderExcluded(r.exclusions, header.GetRound(), header.GetShardID(), hash) {
		return nil, ErrInvalidAccountWitness
	}
	if err := r.proofs.VerifyHeaderProof(p); err != nil {
		return nil, err
	}
	return p, nil
}

// read authenticates one origin's bounded item list. committedB and both shard
// IDs are native-owner inputs. The prototype origin reuses S's native hash;
// no new allocator, hash formula, release codec or G3 family mapping is selected.
// Inputs and native dependencies must remain stable throughout the call.
func (r *canonicalResultReader) read(committedB []byte, consumer, producer uint32, origin, itemKey []byte,
	w canonicalResultWitness, byteLimit int) ([]byte, error) {
	if len(w.MetaHeaders) == 0 || len(w.MetaHeaders) != len(w.MetaProofs) || len(w.MetaHeaders) > byteLimit/2 {
		return nil, ErrInvalidAccountWitness
	}
	remaining := byteLimit
	charge := func(raw []byte) bool {
		if len(raw) > remaining {
			return false
		}
		remaining -= len(raw)
		return true
	}
	for _, raw := range [][]byte{w.Consumer, w.Account.Header, w.Account.ExecutedHeader, w.HeaderProof} {
		if !charge(raw) {
			return nil, ErrInvalidAccountWitness
		}
	}
	for _, list := range [][][]byte{w.MetaHeaders, w.MetaProofs, w.Account.AccountProof, w.Account.DataProof} {
		for _, raw := range list {
			if len(raw) == 0 || !charge(raw) {
				return nil, ErrInvalidAccountWitness
			}
		}
	}
	hash := r.accounts.args.Hasher.Compute
	if len(committedB) == 0 || !bytes.Equal(hash(string(w.Consumer)), committedB) ||
		!bytes.Equal(hash(string(w.Account.ExecutedHeader)), origin) {
		return nil, ErrInvalidAccountWitness
	}
	b, err := r.header(w.Consumer, consumer)
	if err != nil {
		return nil, err
	}
	s, err := r.header(w.Account.ExecutedHeader, producer)
	if err != nil {
		return nil, err
	}
	h, err := r.header(w.Account.Header, producer)
	if err != nil {
		return nil, err
	}
	hashH := hash(string(w.Account.Header))
	if producer != core.MetachainShardId {
		if _, err = r.proof(w.HeaderProof, h, hashH); err != nil {
			return nil, err
		}
	} else if len(w.HeaderProof) != 0 {
		return nil, ErrInvalidAccountWitness
	}
	anchor := b.GetPrevHash()
	if consumer != core.MetachainShardId {
		refs := b.(data.ShardHeaderHandler).GetMetaBlockHashes()
		if len(refs) == 0 || len(refs) > process.MaxMetaHeadersAllowedInOneShardBlock {
			return nil, ErrInvalidAccountWitness
		}
		anchor = refs[len(refs)-1]
	}
	// This index contains only bounded supplied bytes, never pool-selected state.
	indices := make(map[string]int, len(w.MetaHeaders))
	for i, raw := range w.MetaHeaders {
		key := string(hash(string(raw)))
		if _, duplicate := indices[key]; duplicate {
			return nil, ErrInvalidAccountWitness
		}
		indices[key] = i
	}
	pool, err := headersCache.NewHeadersPoolWithRoundExclusions(config.HeadersPoolConfig{
		MaxHeadersPerShard: len(w.MetaHeaders), NumElementsToRemoveOnEviction: 1}, r.exclusions)
	if err != nil {
		return nil, err
	}
	proofs := proofscache.NewProofsPoolWithRoundExclusions(0, len(w.MetaHeaders), r.exclusions)
	var newer data.HeaderHandler
	for visited := 0; visited < len(w.MetaHeaders); visited++ {
		i, found := indices[string(anchor)]
		if !found {
			return nil, ErrInvalidAccountWitness
		}
		current, parseErr := r.header(w.MetaHeaders[i], core.MetachainShardId)
		if parseErr != nil {
			return nil, parseErr
		}
		proof, proofErr := r.proof(w.MetaProofs[i], current, anchor)
		if proofErr != nil {
			return nil, proofErr
		}
		if newer != nil {
			if err = r.validator.IsHeaderConstructionValid(newer, current); err != nil {
				return nil, err
			}
		} else if consumer == core.MetachainShardId {
			if err = r.validator.IsHeaderConstructionValid(b, current); err != nil {
				return nil, err
			}
		}
		pool.AddHeader(bytes.Clone(anchor), current)
		if !proofs.AddProof(proof) {
			return nil, ErrInvalidAccountWitness
		}
		m := current.(*block.MetaBlockV3)
		matches := bytes.Equal(anchor, hashH) && producer == core.MetachainShardId
		if producer != core.MetachainShardId {
			matches = r.projection(m, h, s, hashH, origin)
		}
		if matches {
			if !track.HasMetaReconciliationEvidence(pool, proofs, m.Nonce, anchor) {
				return nil, ErrInvalidAccountWitness
			}
			return r.accounts.Read(hashH, producer, core.SystemAccountAddress, itemKey, w.Account, byteLimit)
		}
		newer = current
		anchor = current.GetPrevHash()
	}
	return nil, ErrInvalidAccountWitness
}

// Native M admission validates the complete ShardInfo projection (shardInfo.go,
// metablockProposal.go). Here bind its proposal to H and its executed identity
// to S; H's COMPLETE native result/root is authenticated by the account reader.
// Projection metadata is never used as a substitute for that result/root proof.
func (r *canonicalResultReader) projection(m *block.MetaBlockV3, h, s data.HeaderHandler, hashH, hashS []byte) bool {
	proposals, executed := 0, 0
	for _, p := range m.ShardInfoProposal {
		if p.ShardID == h.GetShardID() && bytes.Equal(p.HeaderHash, hashH) {
			if p.Nonce != h.GetNonce() || p.Round != h.GetRound() || p.Epoch != h.GetEpoch() {
				return false
			}
			proposals++
		}
	}
	for _, p := range m.ShardInfo {
		if p.ShardID == s.GetShardID() && bytes.Equal(p.HeaderHash, hashS) {
			if p.Nonce != s.GetNonce() || p.Round != s.GetRound() || p.Epoch != s.GetEpoch() {
				return false
			}
			executed++
		}
	}
	return proposals == 1 && executed == 1
}

// promoteCanonicalResult obtains the complete commitment list from S's native
// authenticated system-account root before entering the existing atomic import.
// Proof verification writes only the reader's dedicated proof cache, never the
// execution store. Class-specific Canonical/Observe obligations remain mandatory;
// this is not a permissive replacement host or an installed block dispatcher.
func (r *pendingFinalRecords) promoteCanonicalResult(native *canonicalResultReader, committedB []byte,
	consumer, producer uint32, items []pendingFinalPromotion, witness canonicalResultWitness,
	maxItems, byteLimit int) error {
	if native == nil || maxItems <= 0 || len(items) == 0 || len(items) > maxItems || byteLimit <= 0 {
		return ErrInvalidAccountWitness
	}
	remaining := byteLimit
	frozen := make([]pendingFinalPromotion, 0, len(items))
	for _, item := range items {
		p, err := r.preparePromotion(item.candidate, item.evidence)
		if err != nil {
			return err
		}
		for _, raw := range [][]byte{p.encoded, p.evidence} {
			if len(raw) > remaining {
				return ErrInvalidAccountWitness
			}
			remaining -= len(raw)
		}
		frozen = append(frozen, pendingFinalPromotion{candidate: p.candidate, evidence: p.evidence})
	}
	origin := frozen[0].candidate.origin
	key, err := r.key("origin", origin)
	if err != nil {
		return err
	}
	encoded, err := native.read(committedB, consumer, producer, origin, key, witness, remaining)
	if err != nil {
		return err
	}
	committedItems, err := r.decodeOriginItems(encoded)
	if err != nil {
		return err
	}
	return r.promoteResult(frozen, committedItems, maxItems, byteLimit)
}
