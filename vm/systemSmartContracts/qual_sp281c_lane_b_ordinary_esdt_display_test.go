package systemSmartContracts

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryESDTMetadataDTODisplay(t *testing.T) {
	type displayDTO interface {
		String() string
		GoString() string
	}
	name, ticker, tokenType := []byte("OrdinaryToken"), []byte("ORD"), []byte(core.FungibleESDT)
	minted, burnt := big.NewInt(150), big.NewInt(25)
	for _, tc := range []struct {
		version       string
		value, absent displayDTO
	}{
		{"ESDTDataV1", &ESDTDataV1{TokenName: name, TickerName: ticker, TokenType: tokenType, MintedValue: minted, BurntValue: burnt, NumDecimals: 18}, (*ESDTDataV1)(nil)},
		{"ESDTDataV2", &ESDTDataV2{TokenName: name, TickerName: ticker, TokenType: tokenType, MintedValue: minted, BurntValue: burnt, NumDecimals: 18}, (*ESDTDataV2)(nil)},
	} {
		t.Run(tc.version, func(t *testing.T) {
			ordinaryFields := []struct {
				label string
				value interface{}
			}{
				{"TokenName", name}, {"TickerName", ticker}, {"TokenType", tokenType},
				{"MintedValue", minted}, {"BurntValue", burnt}, {"NumDecimals", uint32(18)},
			}
			ordinary, detailed := tc.value.String(), tc.value.GoString()
			require.True(t, strings.HasPrefix(ordinary, "&"+tc.version+"{"))
			require.True(t, strings.HasSuffix(ordinary, "}"))
			require.True(t, strings.HasPrefix(detailed, "&systemSmartContracts."+tc.version+"{"))
			require.True(t, strings.HasSuffix(detailed, "}"))
			for _, field := range ordinaryFields {
				require.Contains(t, ordinary, fmt.Sprintf("%s:%v,", field.label, field.value))
				require.Contains(t, detailed, fmt.Sprintf("%s: %#v,\n", field.label, field.value))
			}
			require.Equal(t, "nil", tc.absent.String())
			require.Equal(t, "nil", tc.absent.GoString())
		})
	}
}
