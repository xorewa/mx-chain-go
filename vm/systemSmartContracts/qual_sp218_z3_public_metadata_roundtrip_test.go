package systemSmartContracts

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

// A detached public reporting DTO is ordinary data only. Exercise the
// optional display/numeric values and ownership of independently allocated
// byte representations, without account, role or operational inputs.
func TestQualSP218Z3PublicMetadataRoundTrip(t *testing.T) {
	type metadataDTO interface {
		Marshal() ([]byte, error)
		Unmarshal([]byte) error
		Size() int
		GetTokenName() []byte
		GetTickerName() []byte
		GetTokenType() []byte
		GetMintedValue() *big.Int
		GetBurntValue() *big.Int
		GetNumDecimals() uint32
		GetNumWiped() uint32
	}
	type fixture struct {
		name, ticker, tokenType []byte
		minted, burnt           *big.Int
		decimals, reportCount   uint32
	}
	cloneInt := func(value *big.Int) *big.Int {
		if value == nil {
			return nil
		}
		return new(big.Int).Set(value)
	}
	versions := []struct {
		name string
		make func(f fixture) metadataDTO
	}{
		{"v1", func(f fixture) metadataDTO {
			return &ESDTDataV1{TokenName: bytes.Clone(f.name), TickerName: bytes.Clone(f.ticker), TokenType: bytes.Clone(f.tokenType),
				MintedValue: cloneInt(f.minted), BurntValue: cloneInt(f.burnt), NumDecimals: f.decimals, NumWiped: f.reportCount}
		}},
		{"v2", func(f fixture) metadataDTO {
			return &ESDTDataV2{TokenName: bytes.Clone(f.name), TickerName: bytes.Clone(f.ticker), TokenType: bytes.Clone(f.tokenType),
				MintedValue: cloneInt(f.minted), BurntValue: cloneInt(f.burnt), NumDecimals: f.decimals, NumWiped: f.reportCount}
		}},
	}
	cases := []struct {
		name string
		data fixture
		wire []byte
	}{
		{
			name: "optional_nil_and_zero",
			data: fixture{burnt: big.NewInt(0)},
			wire: []byte{0x6a, 1, 0, 0x72, 2, 0, 0},
		},
		{
			name: "public_report_values",
			data: fixture{name: []byte("Sample"), ticker: []byte("SMP"), tokenType: []byte(core.FungibleESDT),
				minted: big.NewInt(65536), burnt: big.NewInt(257), decimals: 18, reportCount: 129},
			wire: []byte{
				0x12, 6, 'S', 'a', 'm', 'p', 'l', 'e',
				0x1a, 3, 'S', 'M', 'P',
				0x22, 12, 'F', 'u', 'n', 'g', 'i', 'b', 'l', 'e', 'E', 'S', 'D', 'T',
				0x6a, 4, 0, 1, 0, 0, // minted report value: 65536
				0x72, 3, 0, 1, 1, // burnt report value: 257
				0x78, 18, // decimals
				0xa0, 1, 0x81, 1, // informational count: 129
			},
		},
	}
	assertValues := func(t *testing.T, want fixture, got metadataDTO) {
		t.Helper()
		require.Equal(t, want.name, got.GetTokenName())
		require.Equal(t, want.ticker, got.GetTickerName())
		require.Equal(t, want.tokenType, got.GetTokenType())
		require.Equal(t, want.minted, got.GetMintedValue())
		require.Equal(t, want.burnt, got.GetBurntValue())
		require.Equal(t, want.decimals, got.GetNumDecimals())
		require.Equal(t, want.reportCount, got.GetNumWiped())
	}
	for _, version := range versions {
		for _, tc := range cases {
			t.Run(version.name+"/"+tc.name, func(t *testing.T) {
				original := version.make(tc.data)
				require.Equal(t, len(tc.wire), original.Size())
				wire, err := original.Marshal()
				require.NoError(t, err)
				require.Equal(t, tc.wire, wire)

				// The only decoder input is a byte representation generated
				// by the normal encoder from the detached fixture.
				first := version.make(fixture{})
				second := version.make(fixture{})
				require.NoError(t, first.Unmarshal(wire))
				require.NoError(t, second.Unmarshal(wire))
				assertValues(t, tc.data, first)
				assertValues(t, tc.data, second)
				encodedAgain, err := second.Marshal()
				require.NoError(t, err)
				require.Equal(t, tc.wire, encodedAgain)

				// Sequential edits of local input/output copies cannot
				// change the independently decoded data or another snapshot.
				if len(original.GetTokenName()) > 0 {
					original.GetTokenName()[0] = 'X'
					original.GetMintedValue().SetInt64(1)
					require.Equal(t, tc.wire, wire)
					first.GetTokenName()[0] = 'Y'
					first.GetMintedValue().SetInt64(2)
				}
				wire[0] = 0
				assertValues(t, tc.data, second)
				require.Equal(t, tc.wire, encodedAgain)
			})
		}
	}
}
