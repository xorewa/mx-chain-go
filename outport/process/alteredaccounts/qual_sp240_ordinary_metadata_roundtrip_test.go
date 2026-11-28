package alteredaccounts

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/alteredAccount"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// Ordinary outport presentation data only; no account, state, or metadata operation.
func TestQualSP240OrdinaryMetadataNonceRoundTrip(t *testing.T) {
	provider := &alteredAccountsProvider{addressConverter: testscommon.NewPubkeyConverterMock(4)}
	// Independent protobuf literals from the pinned TokenMetaData schema:
	// fields 2–7 (UTF-8 name, creator label, royalties, opaque bytes, ordered URIs).
	const metadataSuffix = "1205436166c3a91a08366436313662363520fa012a0300a57f3205666972737432067365636f6e64320566697273743a03290082"
	for _, tc := range []struct {
		family    core.ESDTType
		label     string
		nonce     uint64
		nonceWire string
	}{
		{core.NonFungibleV2, "NonFungibleESDTv2", 127, "087f"},
		{core.SemiFungible, "SemiFungibleESDT", 128, "088001"},
		{core.MetaFungible, "MetaESDT", 255, "08ff01"},
		{core.DynamicNFT, "DynamicNonFungibleESDT", 256, "088002"},
		{core.DynamicSFT, "DynamicSemiFungibleESDT", 65535, "08ffff03"},
		{core.DynamicMeta, "DynamicMetaESDT", 65536, "08808004"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			input := &esdt.MetaData{
				Nonce: tc.nonce, Name: []byte("Café"), Creator: []byte("make"), Royalties: 250,
				Hash: []byte{0, 0xa5, 0x7f}, Attributes: []byte{0x29, 0, 0x82},
				URIs: [][]byte{[]byte("first"), []byte("second"), []byte("first")},
			}
			wantMetadata := &alteredAccount.TokenMetaData{
				Nonce: tc.nonce, Name: "Café", Creator: "6d616b65", Royalties: 250,
				Hash: []byte{0, 0xa5, 0x7f}, Attributes: []byte{0x29, 0, 0x82},
				URIs: [][]byte{[]byte("first"), []byte("second"), []byte("first")},
			}
			wantWire, err := hex.DecodeString(tc.nonceWire + metadataSuffix)
			require.NoError(t, err)
			converted := provider.convertMetaData(input)
			require.Equal(t, wantMetadata, converted)
			metadataWire, err := converted.Marshal()
			require.NoError(t, err)
			require.Equal(t, wantWire, metadataWire)
			require.Equal(t, len(wantWire), converted.Size())

			// The enclosing ordinary reporting DTO retains the nonce, type and metadata.
			display := &alteredAccount.AccountTokenData{Nonce: tc.nonce, Identifier: "DISPLAY-abcdef",
				Balance: "1", Type: getTokenType(uint32(tc.family), tc.nonce), MetaData: converted}
			want := &alteredAccount.AccountTokenData{Nonce: tc.nonce, Identifier: "DISPLAY-abcdef",
				Balance: "1", Type: tc.label, MetaData: wantMetadata}
			require.Equal(t, want, display)
			wire, err := display.Marshal()
			require.NoError(t, err)
			snapshot := bytes.Clone(wire)
			var decoded, independent alteredAccount.AccountTokenData
			require.NoError(t, decoded.Unmarshal(wire))
			require.NoError(t, independent.Unmarshal(wire))
			require.Equal(t, want, &decoded)
			require.Equal(t, want, &independent)
			encodedAgain, err := decoded.Marshal()
			require.NoError(t, err)
			require.Equal(t, snapshot, encodedAgain)
			decodedMetadataWire, err := independent.MetaData.Marshal()
			require.NoError(t, err)
			require.Equal(t, wantWire, decodedMetadataWire)

			// Mutate only one deserialized local representation, not the converter's input.
			decoded.MetaData.Hash[0] = 1
			decoded.MetaData.URIs[0][0] = 'x'
			decoded.MetaData.Attributes[0] = 3
			decoded.MetaData.Name = "local copy"
			require.Equal(t, want, &independent)
			require.Equal(t, want, display)
			require.Equal(t, snapshot, wire)
			require.Equal(t, wantWire, metadataWire)
		})
	}
}
