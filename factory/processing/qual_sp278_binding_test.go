package processing

import "github.com/multiversx/mx-chain-go/process/drwa"

func drwaSupplyBindingForTest() drwa.SupplyEvidenceBinding {
	return drwa.SupplyEvidenceBinding{Token: []byte("FIXT-0a1b2c"), CEBEpoch: 3, CEBHash: make([]byte, 32), Action: []byte("action"), Closure: 1, OriginShard: 1}
}
