package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
)

// nativeOriginSCRReferences discovers the complete native SCR reference list
// for one known origin/consumer after the existing canonical-origin read.
// It preserves source order and does not trim to B's currently proposed work.
// Empty references are not an authenticated no-work result for the class list.
// Native admission, first eligibility, class applicability and funding remain
// caller obligations; this method neither imports nor applies any item.
func (r *pendingFinalRecords) nativeOriginSCRReferences(native *canonicalResultReader, committedB []byte,
	consumer, producer uint32, origin []byte, w canonicalResultWitness, byteLimit int,
) ([]byte, []data.MiniBlockHeaderHandler, error) {
	if native == nil || consumer == producer || consumer == core.MetachainShardId || producer == core.MetachainShardId ||
		len(origin) == 0 || len(origin) > byteLimit {
		return nil, nil, ErrInvalidAccountWitness
	}
	key, err := r.key("origin", origin)
	if err != nil {
		return nil, nil, err
	}
	value, err := native.read(committedB, consumer, producer, origin, key, w, byteLimit)
	if err != nil {
		return nil, nil, err
	}
	h, err := native.header(w.Account.Header, producer)
	if err != nil {
		return nil, nil, err
	}
	origins := 0
	var references []data.MiniBlockHeaderHandler
	for _, result := range h.(*block.HeaderV3).ExecutionResults {
		if result == nil || result.BaseExecutionResult == nil ||
			!bytes.Equal(result.BaseExecutionResult.HeaderHash, origin) {
			continue
		}
		origins++
		for _, header := range result.GetMiniBlockHeadersHandlers() {
			mb, ok := header.(*block.MiniBlockHeader)
			if !ok || mb == nil {
				return nil, nil, ErrInvalidAccountWitness
			}
			if mb.Type != block.SmartContractResultBlock || mb.SenderShardID != producer ||
				mb.ReceiverShardID != consumer {
				continue
			}
			if len(mb.Hash) == 0 {
				return nil, nil, ErrInvalidAccountWitness
			}
			references = append(references, mb)
		}
	}
	if origins != 1 {
		return nil, nil, ErrInvalidAccountWitness
	}
	return value, references, nil
}
