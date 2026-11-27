package groups

import "github.com/multiversx/mx-chain-go/api/shared"

// ObservationSubject copies the existing public token identity, with no nonce
// inferred for the fungible token DTO. It changes neither the legacy JSON
// response nor the interpretation of the balance or properties.
func (token *esdtTokenData) ObservationSubject() (*shared.PublicObservationSubject, error) {
	if token == nil {
		return nil, nil
	}
	return shared.ObservationSubjectFromPublicTokenFields(token.TokenIdentifier, nil)
}

// ObservationSubject copies the existing public NFT DTO identity. Its legacy
// nonce is omitted for zero, so only a present nonzero nonce is copied. It does
// not supply a holder, beneficiary, value outcome, or producer evidence.
func (token *ESDTNFTTokenData) ObservationSubject() (*shared.PublicObservationSubject, error) {
	if token == nil {
		return nil, nil
	}
	var nonce *uint64
	if token.Nonce != 0 {
		nonce = &token.Nonce
	}
	return shared.ObservationSubjectFromPublicTokenFields(token.TokenIdentifier, nonce)
}
