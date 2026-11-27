package systemSmartContracts

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryESDTMetadataSizes(t *testing.T) {
	t.Parallel()

	type sizedView interface {
		Size() int
		XXX_Size() int
	}
	var absentV1 *ESDTDataV1
	var absentV2 *ESDTDataV2
	var absentConfig *ESDTConfig
	cases := []struct {
		view sizedView
		size int
	}{
		{absentV1, 0}, {absentV2, 0}, {absentConfig, 0},
		{&ESDTDataV1{}, 6}, {&ESDTDataV2{}, 6}, {&ESDTConfig{}, 3},
		{&ESDTDataV1{TokenName: []byte("Example"), TickerName: []byte("DEMO"), MintedValue: big.NewInt(256), BurntValue: big.NewInt(7), NumDecimals: 8}, 26},
		{&ESDTDataV2{TokenName: []byte("Example"), TickerName: []byte("DEMO"), MintedValue: big.NewInt(256), BurntValue: big.NewInt(7), NumDecimals: 8}, 26},
		{&ESDTConfig{BaseIssuingCost: big.NewInt(256), MinTokenNameLength: 3, MaxTokenNameLength: 20}, 9},
	}
	for _, tc := range cases {
		require.Equal(t, tc.size, tc.view.Size())
		require.Equal(t, tc.size, tc.view.XXX_Size())
	}
}
