package drwa

import (
	"bytes"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/process"
)

var errInvalidMetaContext = errors.New("invalid DRWA native meta context")

// nativeMetaContext selects the registry state anchor for ledger L28. The
// executing owner supplies its independently authenticated candidate hash and
// cross-notarized predecessor hash, after native header/proof/finality and
// execution-result validation. This component reuses native ancestry validation;
// it does not replace any native proof, epoch-start or settlement check.
// There are no external production callers. Wiring must establish this ownership
// before selection; pool arrival or caller-provided transport is not authority.
type nativeMetaContext struct {
	marshaller marshal.Marshalizer
	hasher     hashing.Hasher
	validator  process.HeaderConstructionValidator
}

// metaRegistryAnchor names the latest execution reported by the native context
// tip, including a retained LastExecutionResult when its result list is empty.
// These are native commitment identities, not a new hash, wire format or root.
// The complete registry/projection must still be authenticated and materialized
// before any dependent effect; this selector alone is not a classifier.
type metaRegistryAnchor struct {
	candidateHash, metaHash, executedHash, root []byte
	nonce, round                                uint64
	epoch                                       uint32
}

func newNativeMetaContext(marshaller marshal.Marshalizer, hasher hashing.Hasher,
	validator process.HeaderConstructionValidator) (*nativeMetaContext, error) {
	if check.IfNil(marshaller) {
		return nil, process.ErrNilMarshalizer
	}
	if check.IfNil(hasher) {
		return nil, process.ErrNilHasher
	}
	if check.IfNil(validator) {
		return nil, errInvalidMetaContext
	}
	return &nativeMetaContext{marshaller: marshaller, hasher: hasher, validator: validator}, nil
}

// selectAnchor consumes native header bytes only. Reference order comes from
// the authenticated candidate, never from proof arrival or a proposed token
// list. Inputs/dependencies must remain stable during this call. No native
// executing account store is read or changed, and no partial anchor is returned.
func (c *nativeMetaContext) selectAnchor(candidateHash, candidateBytes,
	predecessorHash, predecessorBytes []byte, references [][]byte) (*metaRegistryAnchor, error) {
	if len(candidateHash) == 0 || len(predecessorHash) == 0 ||
		!bytes.Equal(c.hasher.Compute(string(candidateBytes)), candidateHash) ||
		!bytes.Equal(c.hasher.Compute(string(predecessorBytes)), predecessorHash) {
		return nil, errInvalidMetaContext
	}
	candidate := &block.HeaderV3{}
	previous := &block.MetaBlockV3{}
	if c.marshaller.Unmarshal(candidate, candidateBytes) != nil || c.marshaller.Unmarshal(previous, predecessorBytes) != nil {
		return nil, errInvalidMetaContext
	}
	if len(references) != len(candidate.MetaBlockHashes) || len(references) > process.MaxMetaHeadersAllowedInOneShardBlock {
		return nil, errInvalidMetaContext
	}
	tipHash := predecessorHash
	for i, raw := range references {
		if !bytes.Equal(c.hasher.Compute(string(raw)), candidate.MetaBlockHashes[i]) {
			return nil, errInvalidMetaContext
		}
		next := &block.MetaBlockV3{}
		if c.marshaller.Unmarshal(next, raw) != nil {
			return nil, errInvalidMetaContext
		}
		if err := c.validator.IsHeaderConstructionValid(next, previous); err != nil {
			return nil, err
		}
		previous, tipHash = next, candidate.MetaBlockHashes[i]
	}
	info := previous.LastExecutionResult
	if info == nil || info.ExecutionResult == nil || info.ExecutionResult.BaseExecutionResult == nil {
		return nil, errInvalidMetaContext
	}
	result := info.ExecutionResult.BaseExecutionResult
	if len(result.HeaderHash) == 0 || len(result.RootHash) == 0 {
		return nil, errInvalidMetaContext
	}
	return &metaRegistryAnchor{candidateHash: bytes.Clone(candidateHash), metaHash: bytes.Clone(tipHash),
		executedHash: bytes.Clone(result.HeaderHash), root: bytes.Clone(result.RootHash),
		nonce: result.HeaderNonce, round: result.HeaderRound, epoch: result.HeaderEpoch}, nil
}
