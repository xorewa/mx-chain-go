package alteredaccounts

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/alteredAccount"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

func TestQualSP240OrdinaryMetadataPreservesOpaqueFields(t *testing.T) {
	t.Parallel()

	provider := &alteredAccountsProvider{addressConverter: testscommon.NewPubkeyConverterMock(4)}
	input := &esdt.MetaData{
		Nonce: 5, Name: []byte("Café"), Creator: []byte("make"), Royalties: 125,
		Hash: []byte{0x00, 0xa5, 0x7f}, Attributes: []byte{0x29, 0x00, 0x82},
		URIs: [][]byte{[]byte("first"), []byte("second"), []byte("first")},
	}
	want := &alteredAccount.TokenMetaData{
		Nonce: 5, Name: "Café", Creator: "6d616b65", Royalties: 125,
		Hash: []byte{0x00, 0xa5, 0x7f}, Attributes: []byte{0x29, 0x00, 0x82},
		URIs: [][]byte{[]byte("first"), []byte("second"), []byte("first")},
	}
	require.Equal(t, want, provider.convertMetaData(input))
}
