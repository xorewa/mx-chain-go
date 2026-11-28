package drwa

import (
	"math/big"
	"testing"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestSP247OrderedBatchAccounting(t *testing.T) {
	// Independent detached accounting observations, not actual transactions
	// or a native admission/settlement fixture.
	makeObservation := func() []*vmcommon.ESDTTransfer {
		return []*vmcommon.ESDTTransfer{
			{ESDTTokenName: []byte(vmcommon.EGLDIdentifier), ESDTValue: big.NewInt(3)},
			{ESDTTokenName: []byte("example-A"), ESDTTokenNonce: 1, ESDTValue: big.NewInt(2)},
			{ESDTTokenName: []byte("example-B"), ESDTValue: big.NewInt(4)},
			{ESDTTokenName: []byte("example-A"), ESDTTokenNonce: 1, ESDTValue: big.NewInt(5)},
			{ESDTTokenName: []byte("example-A"), ESDTTokenNonce: 2, ESDTValue: big.NewInt(1)},
		}
	}
	expected := []observedBatchAssetTotal{
		{observedBatchAsset{vmcommon.EGLDIdentifier, 0}, 0, 1, big.NewInt(3)},
		{observedBatchAsset{"example-A", 1}, 1, 2, big.NewInt(7)},
		{observedBatchAsset{"example-B", 0}, 2, 1, big.NewInt(4)},
		{observedBatchAsset{"example-A", 2}, 4, 1, big.NewInt(1)},
	}
	bounds := orderedBatchAccountingBounds{legs: 5, identifierBytes: 32, amountBytes: 8}
	t.Run("independent_observations", func(t *testing.T) {
		first := makeObservation()
		second := makeObservation()
		a, err := summarizeOrderedBatchAccounting(first, bounds)
		require.NoError(t, err)
		b, err := summarizeOrderedBatchAccounting(second, bounds)
		require.NoError(t, err)
		require.Equal(t, expected, a)
		require.Equal(t, expected, b)
		require.Equal(t, makeObservation(), first)
		require.Equal(t, makeObservation(), second)
		// The detached result does not alias either native observation.
		a[1].quantity.SetInt64(1)
		require.Equal(t, expected, b)
		require.Equal(t, makeObservation(), first)
	})
	t.Run("arbitrary_precision_observation", func(t *testing.T) {
		quantity := new(big.Int).Lsh(big.NewInt(1), 80)
		legs := []*vmcommon.ESDTTransfer{
			{ESDTTokenName: []byte("example-A"), ESDTValue: new(big.Int).Set(quantity)},
			{ESDTTokenName: []byte("example-A"), ESDTValue: new(big.Int).Set(quantity)},
		}
		got, err := summarizeOrderedBatchAccounting(legs, orderedBatchAccountingBounds{2, 32, 16})
		require.NoError(t, err)
		want := new(big.Int).Lsh(big.NewInt(1), 81)
		require.Equal(t, []observedBatchAssetTotal{{observedBatchAsset{"example-A", 0}, 0, 2, want}}, got)
		require.Equal(t, quantity, legs[0].ESDTValue)
		require.Equal(t, quantity, legs[1].ESDTValue)
	})
	t.Run("local_diagnostic_budget_unavailable", func(t *testing.T) {
		got, err := summarizeOrderedBatchAccounting(makeObservation(), orderedBatchAccountingBounds{})
		require.ErrorIs(t, err, errOrderedBatchAccounting)
		require.Nil(t, got)
		got, err = summarizeOrderedBatchAccounting(makeObservation(), orderedBatchAccountingBounds{5, 1, 8})
		require.ErrorIs(t, err, errOrderedBatchAccounting)
		require.Nil(t, got)
		legs := []*vmcommon.ESDTTransfer{
			{ESDTTokenName: []byte("example-A"), ESDTValue: big.NewInt(200)},
			{ESDTTokenName: []byte("example-A"), ESDTValue: big.NewInt(200)},
		}
		got, err = summarizeOrderedBatchAccounting(legs, orderedBatchAccountingBounds{2, 32, 1})
		require.ErrorIs(t, err, errOrderedBatchAccounting)
		require.Nil(t, got)
	})
}
