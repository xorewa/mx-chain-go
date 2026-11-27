package groups

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
)

func TestQualSP281COrdinaryTokenDisplayDTO(t *testing.T) {
	t.Run("plain label", func(t *testing.T) {
		input := &esdt.ESDigitalToken{Type: uint32(core.Fungible), Value: big.NewInt(42)}
		got := buildTokenDataApiResponse("example-label", input)
		if got.TokenIdentifier != "example-label" || got.Balance != "42" || got.Type != "FungibleESDT" || got.Properties != "" {
			t.Fatalf("unexpected basic presentation: %+v", got)
		}
		if got.Name != "" || got.Nonce != 0 || got.Royalties != "" {
			t.Fatalf("unexpected absent metadata presentation: %+v", got)
		}
	})
	t.Run("nominal name", func(t *testing.T) {
		input := &esdt.ESDigitalToken{Type: uint32(core.Fungible), Value: big.NewInt(17), TokenMetaData: &esdt.MetaData{Name: []byte("Example")}}
		got := buildTokenDataApiResponse("example-name", input)
		if got.TokenIdentifier != "example-name" || got.Balance != "17" || got.Type != "FungibleESDT" || got.Name != "Example" || got.Nonce != 0 || got.Royalties != "0" {
			t.Fatalf("unexpected named presentation: %+v", got)
		}
	})
}
