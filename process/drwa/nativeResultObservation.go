package drwa

import "github.com/multiversx/mx-chain-core-go/data/smartContractResult"

// nativeSCRCarrierObservation is an internal SP2 read model, not a wire status.
// It records only the checked carrier and its S/H/M/B coordinates. Meta hashes
// are ordered from B's anchor back through the matching projection. Neither its
// existence nor a native success marker proves submission, receiving execution,
// canonical business outcome, settlement/return, economic gas refund or source
// completion. Each of those needs its own actual native producer and evidence.
// Native context/profile admission remains the canonicalResultReader caller's duty.
type nativeSCRCarrierObservation struct {
	originCommitment                                   []byte
	result                                             *smartContractResult.SmartContractResult
	producer, consumer                                 uint32
	originHash, carryingHeaderHash, consumerHeaderHash []byte
	metaHeaderHashes                                   [][]byte
	miniBlockHash, resultHash                          []byte
	asOfNonce, asOfRound                               uint64
	asOfEpoch                                          uint32
}
