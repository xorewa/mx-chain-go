package groups

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/stretchr/testify/require"
)

// Compare the ordinary token-list response representation using supplied
// display metadata only. No account, token operation or request is performed.
func TestQualSP218OrdinaryTokenMetadataWire(t *testing.T) {
	t.Run("zero balance and absent optional fields", func(t *testing.T) {
		dto := buildTokenDataApiResponse("DISPLAY-abcdef", &esdt.ESDigitalToken{
			Type: uint32(core.Fungible), Value: big.NewInt(0),
		})
		wire, err := json.Marshal(dto)
		require.NoError(t, err)
		require.JSONEq(t, `{"tokenIdentifier":"DISPLAY-abcdef","balance":"0","type":"FungibleESDT"}`, string(wire))
	})

	t.Run("exact balance text and ordered metadata", func(t *testing.T) {
		value, ok := new(big.Int).SetString("9007199254740993", 10)
		require.True(t, ok)
		dto := buildTokenDataApiResponse("ALBUM-abcdef-07", &esdt.ESDigitalToken{
			Type: uint32(core.SemiFungible), Value: value,
			TokenMetaData: &esdt.MetaData{
				Name: []byte("Café"), Nonce: 7, Creator: []byte("Artist"),
				Royalties: 250, Hash: []byte("art"),
				URIs:       [][]byte{[]byte("first"), []byte("second"), []byte("first")},
				Attributes: []byte("blue"),
			},
		})
		wire, err := json.Marshal(dto)
		require.NoError(t, err)
		require.JSONEq(t, `{
			"tokenIdentifier":"ALBUM-abcdef-07",
			"balance":"9007199254740993",
			"type":"SemiFungibleESDT",
			"name":"Café","nonce":7,"creator":"Artist","royalties":"250",
			"hash":"YXJ0","uris":["Zmlyc3Q=","c2Vjb25k","Zmlyc3Q="],
			"attributes":"Ymx1ZQ=="
		}`, string(wire))
	})
}
