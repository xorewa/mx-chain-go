package systemSmartContracts

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryESDTMetadataDTOGetters(t *testing.T) {
	type ordinaryMetadata interface {
		GetTokenName() []byte
		GetTickerName() []byte
		GetTokenType() []byte
		GetMintedValue() *big.Int
		GetBurntValue() *big.Int
		GetNumDecimals() uint32
	}
	minted := new(big.Int).Lsh(big.NewInt(1), 70)
	burnt := big.NewInt(25)
	for _, tc := range []struct {
		name          string
		value, absent ordinaryMetadata
	}{
		{"v1", &ESDTDataV1{TokenName: []byte("OrdinaryToken"), TickerName: []byte("ORD"), TokenType: []byte(core.FungibleESDT), MintedValue: new(big.Int).Set(minted), BurntValue: new(big.Int).Set(burnt), NumDecimals: 18}, (*ESDTDataV1)(nil)},
		{"v2", &ESDTDataV2{TokenName: []byte("OrdinaryToken"), TickerName: []byte("ORD"), TokenType: []byte(core.FungibleESDT), MintedValue: new(big.Int).Set(minted), BurntValue: new(big.Int).Set(burnt), NumDecimals: 18}, (*ESDTDataV2)(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, []byte("OrdinaryToken"), tc.value.GetTokenName())
			require.Equal(t, []byte("ORD"), tc.value.GetTickerName())
			require.Equal(t, []byte(core.FungibleESDT), tc.value.GetTokenType())
			require.Equal(t, "1180591620717411303424", tc.value.GetMintedValue().String())
			require.Equal(t, "25", tc.value.GetBurntValue().String())
			require.Equal(t, uint32(18), tc.value.GetNumDecimals())

			require.Nil(t, tc.absent.GetTokenName())
			require.Nil(t, tc.absent.GetTickerName())
			require.Nil(t, tc.absent.GetTokenType())
			require.Nil(t, tc.absent.GetMintedValue())
			require.Nil(t, tc.absent.GetBurntValue())
			require.Zero(t, tc.absent.GetNumDecimals())
		})
	}
}
