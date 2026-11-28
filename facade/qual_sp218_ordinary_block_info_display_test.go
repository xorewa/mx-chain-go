package facade

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/api"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common/holders"
)

func TestQualSP218OrdinaryBlockInfoDisplay(t *testing.T) {
	t.Parallel()

	// Synthetic byte sequences only; no chain or query execution.
	cases := []struct {
		name  string
		hash  []byte
		root  []byte
		nonce uint64
		want  api.BlockInfo
	}{
		{
			name:  "leading_zero_bytes",
			hash:  []byte{0x00, 0xab, 0x07},
			root:  []byte{0x04, 0x00, 0xff},
			nonce: 7,
			want:  api.BlockInfo{Nonce: 7, Hash: "00ab07", RootHash: "0400ff"},
		},
		{
			name:  "wide_unsigned_coordinate",
			hash:  []byte{0x10, 0x00},
			root:  []byte{0x0a, 0xbc, 0x00},
			nonce: 9007199254740993,
			want:  api.BlockInfo{Nonce: 9007199254740993, Hash: "1000", RootHash: "0abc00"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := holders.NewBlockInfo(tc.hash, tc.nonce, tc.root)
			require.Equal(t, tc.want, queryBlockInfoToApiResource(info))
		})
	}
}
