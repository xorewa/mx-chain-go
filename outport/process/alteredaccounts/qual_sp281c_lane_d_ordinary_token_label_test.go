package alteredaccounts

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

// The outport token label is presentation metadata, not a token operation.
func TestQualLaneDOrdinaryOutportTokenLabels(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  core.ESDTType
		want string
	}{
		{name: "meta", typ: core.MetaFungible, want: "MetaESDT"},
		{name: "dynamic NFT", typ: core.DynamicNFT, want: "DynamicNonFungibleESDT"},
		{name: "dynamic SFT", typ: core.DynamicSFT, want: "DynamicSemiFungibleESDT"},
		{name: "dynamic meta", typ: core.DynamicMeta, want: "DynamicMetaESDT"},
		{name: "legacy NFT display", typ: core.NonFungible, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, getTokenType(uint32(tc.typ), 7))
		})
	}
}
