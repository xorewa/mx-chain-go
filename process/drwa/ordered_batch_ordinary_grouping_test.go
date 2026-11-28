package drwa

import (
	"math/big"
	"testing"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// These are detached numeric observations, not native operations or wire inputs.
// Grouping and ordering of a summary say nothing about an ordered commitment.
func TestSP247OrdinaryDetachedQuantityGrouping(t *testing.T) {
	type observation struct {
		label  string
		nonce  uint64
		amount string
	}
	type expectation struct {
		asset              observedBatchAsset
		first, occurrences int
		quantity           string
	}
	const wide = "18446744073709551617" // 2^64 + 1
	const sum = "18446744073709551626"  // 2^64 + 10
	cases := []struct {
		name  string
		input []observation
		want  []expectation
	}{
		{
			"original_order",
			[]observation{{"example-A", 1, wide}, {"example-B", 0, "7"}, {"example-A", 2, "5"}, {"example-A", 1, "9"}, {"example-B", 0, "11"}},
			[]expectation{{observedBatchAsset{"example-A", 1}, 0, 2, sum}, {observedBatchAsset{"example-B", 0}, 1, 2, "18"}, {observedBatchAsset{"example-A", 2}, 2, 1, "5"}},
		},
		{
			"other_observation_order",
			[]observation{{"example-B", 0, "11"}, {"example-A", 2, "5"}, {"example-B", 0, "7"}, {"example-A", 1, "9"}, {"example-A", 1, wide}},
			[]expectation{{observedBatchAsset{"example-B", 0}, 0, 2, "18"}, {observedBatchAsset{"example-A", 2}, 1, 1, "5"}, {observedBatchAsset{"example-A", 1}, 3, 2, sum}},
		},
		{
			"partitioned_observation",
			[]observation{{"example-A", 1, "18446744073709551616"}, {"example-B", 0, "7"}, {"example-A", 1, "1"}, {"example-A", 2, "5"}, {"example-A", 1, "9"}, {"example-B", 0, "11"}},
			[]expectation{{observedBatchAsset{"example-A", 1}, 0, 3, sum}, {observedBatchAsset{"example-B", 0}, 1, 2, "18"}, {observedBatchAsset{"example-A", 2}, 3, 1, "5"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legs := make([]*vmcommon.ESDTTransfer, 0, len(tc.input))
			for _, item := range tc.input {
				amount, ok := new(big.Int).SetString(item.amount, 10)
				require.True(t, ok)
				legs = append(legs, &vmcommon.ESDTTransfer{ESDTTokenName: []byte(item.label), ESDTTokenNonce: item.nonce, ESDTValue: amount})
			}
			got, err := summarizeOrderedBatchAccounting(legs, orderedBatchAccountingBounds{len(legs), 32, 16})
			require.NoError(t, err)
			require.Len(t, got, len(tc.want))
			for i, want := range tc.want {
				require.Equal(t, want.asset, got[i].asset)
				require.Equal(t, want.first, got[i].firstLeg)
				require.Equal(t, want.occurrences, got[i].occurrences)
				require.Equal(t, want.quantity, got[i].quantity.String())
			}
			for i, item := range tc.input {
				require.Equal(t, item.label, string(legs[i].ESDTTokenName))
				require.Equal(t, item.nonce, legs[i].ESDTTokenNonce)
				require.Equal(t, item.amount, legs[i].ESDTValue.String())
			}
		})
	}
}
