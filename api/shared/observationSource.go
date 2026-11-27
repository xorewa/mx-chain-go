package shared

import (
	"strconv"

	"github.com/multiversx/mx-chain-core-go/data/api"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
)

// ObservationSubjectFromPublicTransaction copies only explicit public hashes
// from the ordinary transaction DTO. It supplies neither a DRWA association
// nor an observation, finality classification, or any other outcome.
func ObservationSubjectFromPublicTransaction(tx *transaction.ApiTransactionResult) (*PublicObservationSubject, error) {
	if tx == nil {
		return nil, nil
	}
	subject := &PublicObservationSubject{}
	for _, field := range []struct {
		value  string
		target **ObservationHash
	}{
		{tx.Hash, &subject.TransactionHash},
		{tx.OriginalTransactionHash, &subject.OriginalTransactionHash},
	} {
		if field.value == "" {
			continue
		}
		value := ObservationHash(field.value)
		if !validObservationHash(value) {
			return nil, ErrMalformedObservation
		}
		*field.target = &value
	}
	if subject.TransactionHash == nil && subject.OriginalTransactionHash == nil {
		return nil, nil
	}
	return subject, nil
}

// ObservationSubjectFromPublicTokenFields copies an explicitly supplied public
// token identifier and optional public nonce. The caller preserves presence
// from its source DTO; nil does not stand for zero. This is a presentation
// fragment, not an observation or a claim about token ownership or outcomes.
func ObservationSubjectFromPublicTokenFields(tokenID string, tokenNonce *uint64) (*PublicObservationSubject, error) {
	if tokenID == "" {
		return nil, nil
	}
	if !validObservationText(tokenID) {
		return nil, ErrMalformedObservation
	}
	id := ObservationTokenID(tokenID)
	subject := &PublicObservationSubject{TokenID: &id}
	if tokenNonce != nil {
		nonce := ObservationUInt64(strconv.FormatUint(*tokenNonce, 10))
		subject.TokenNonce = &nonce
	}
	return subject, nil
}

// ObservationProvenanceFromPublicBlockInfo copies the explicit as-of metadata
// of an existing ordinary account-query response. It does not establish an
// observation association, canonical finality, or an observation timestamp.
// BlockInfo omits a zero nonce on its public wire and has no round or shard.
func ObservationProvenanceFromPublicBlockInfo(info *api.BlockInfo) (*PublicObservationProvenance, error) {
	if info == nil {
		return nil, nil
	}
	provenance := &PublicObservationProvenance{}
	if info.Hash != "" {
		hash := ObservationHash(info.Hash)
		if !validObservationHash(hash) {
			return nil, ErrMalformedObservation
		}
		provenance.AsOfBlockHash = &hash
	}
	if info.Nonce != 0 {
		nonce := ObservationUInt64(strconv.FormatUint(info.Nonce, 10))
		provenance.AsOfBlockNonce = &nonce
	}
	if provenance.AsOfBlockHash == nil && provenance.AsOfBlockNonce == nil {
		return nil, nil
	}
	return provenance, nil
}
