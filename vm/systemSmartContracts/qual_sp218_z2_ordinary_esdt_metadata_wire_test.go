package systemSmartContracts

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

// Check only in-memory ordinary token name, ticker, type and numeric metadata.
// The expected wire bytes follow the common fields of the unchanged V1/V2 schema.
func TestQualSP218Z2OrdinaryESDTMetadataWireDTO(t *testing.T) {
	type wireDTO interface {
		Size() int
		Marshal() ([]byte, error)
		MarshalTo([]byte) (int, error)
	}
	want := []byte{
		0x12, 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e',
		0x1a, 4, 'D', 'E', 'M', 'O',
		0x22, 12, 'F', 'u', 'n', 'g', 'i', 'b', 'l', 'e', 'E', 'S', 'D', 'T',
		0x6a, 3, 0, 1, 0, // minted: 256
		0x72, 2, 0, 7, // burnt: 7
		0x78, 8, // decimals: 8
	}
	for _, tc := range []struct {
		name string
		dto  wireDTO
	}{
		{"v1", &ESDTDataV1{TokenName: []byte("Example"), TickerName: []byte("DEMO"), TokenType: []byte(core.FungibleESDT), MintedValue: big.NewInt(256), BurntValue: big.NewInt(7), NumDecimals: 8}},
		{"v2", &ESDTDataV2{TokenName: []byte("Example"), TickerName: []byte("DEMO"), TokenType: []byte(core.FungibleESDT), MintedValue: big.NewInt(256), BurntValue: big.NewInt(7), NumDecimals: 8}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, len(want), tc.dto.Size())
			wire, err := tc.dto.Marshal()
			require.NoError(t, err)
			require.Equal(t, want, wire)

			buf := make([]byte, len(want))
			n, err := tc.dto.MarshalTo(buf)
			require.NoError(t, err)
			require.Equal(t, len(want), n)
			require.Equal(t, want, buf)
		})
	}
}
