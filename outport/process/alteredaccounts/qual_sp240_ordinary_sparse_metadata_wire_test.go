package alteredaccounts

import (
	"encoding/hex"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/alteredAccount"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// A detached presentation DTO: sparse optional metadata and the outer report
// properties must survive their wire representation without inventing defaults.
func TestQualSP240OrdinarySparseMetadataWire(t *testing.T) {
	provider := &alteredAccountsProvider{addressConverter: testscommon.NewPubkeyConverterMock(4)}
	// Independent AccountTokenData field tags: nonce=1, identifier=2,
	// balance=3, properties=4, metadata=5, type=7.
	const header = "0809120b4954454d2d6162636465661a023337220430313032"
	const suffix = "3a1053656d6946756e6769626c6545534454"
	for _, tc := range []struct {
		name         string
		input        *esdt.MetaData
		want         *alteredAccount.TokenMetaData
		metadataWire string
	}{
		{name: "omitted", input: nil, want: nil, metadataWire: ""},
		{name: "sparse", input: &esdt.MetaData{Nonce: 9, Name: []byte("Leaf")},
			want:         &alteredAccount.TokenMetaData{Nonce: 9, Name: "Leaf"},
			metadataWire: "2a08080912044c656166"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			converted := provider.convertMetaData(tc.input)
			require.Equal(t, tc.want, converted)
			report := &alteredAccount.AccountTokenData{
				Nonce: 9, Identifier: "ITEM-abcdef", Balance: "37", Properties: "0102",
				MetaData: converted, Type: getTokenType(uint32(core.SemiFungible), 9),
			}
			want := &alteredAccount.AccountTokenData{
				Nonce: 9, Identifier: "ITEM-abcdef", Balance: "37", Properties: "0102",
				MetaData: tc.want, Type: "SemiFungibleESDT",
			}
			require.Equal(t, want, report)
			oracle, err := hex.DecodeString(header + tc.metadataWire + suffix)
			require.NoError(t, err)
			wire, err := report.Marshal()
			require.NoError(t, err)
			require.Equal(t, oracle, wire)
			require.Equal(t, len(oracle), report.Size())
			var decoded alteredAccount.AccountTokenData
			require.NoError(t, decoded.Unmarshal(oracle))
			require.Equal(t, want, &decoded)
		})
	}
}
