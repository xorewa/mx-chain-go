package alteredaccounts

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/alteredAccount"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryMetadataDTOConversion(t *testing.T) {
	provider := &alteredAccountsProvider{addressConverter: testscommon.NewPubkeyConverterMock(4)}

	t.Run("absent_metadata", func(t *testing.T) {
		require.Nil(t, provider.convertMetaData(nil))
	})

	t.Run("ordinary_metadata", func(t *testing.T) {
		input := &esdt.MetaData{
			Nonce: 9, Name: []byte("collectible"), Creator: []byte("make"), Royalties: 250,
			Hash: []byte("hash"), URIs: [][]byte{[]byte("first"), []byte("second")}, Attributes: []byte("attrs"),
		}
		want := &alteredAccount.TokenMetaData{
			Nonce: 9, Name: "collectible", Creator: "6d616b65", Royalties: 250,
			Hash: []byte("hash"), URIs: [][]byte{[]byte("first"), []byte("second")}, Attributes: []byte("attrs"),
		}
		require.Equal(t, want, provider.convertMetaData(input))
	})
}
