package postprocess_test

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/scheduled"
	"github.com/multiversx/mx-chain-go/process/block/postprocess"
	"github.com/stretchr/testify/require"
)

func TestQualSP218OrdinaryFeeAccumulatorSeed(t *testing.T) {
	accumulator := postprocess.NewFeeAccumulator()
	initial := scheduled.GasAndFees{
		AccumulatedFees: big.NewInt(120),
		DeveloperFees:   big.NewInt(30),
	}

	accumulator.CreateBlockStarted(initial)
	require.Equal(t, big.NewInt(120), accumulator.GetAccumulatedFees())
	require.Equal(t, big.NewInt(30), accumulator.GetDeveloperFees())

	// The supplied values and returned report totals are independent copies.
	initial.AccumulatedFees.SetInt64(121)
	initial.DeveloperFees.SetInt64(31)
	accumulator.GetAccumulatedFees().SetInt64(1)
	accumulator.GetDeveloperFees().SetInt64(2)
	require.Equal(t, big.NewInt(120), accumulator.GetAccumulatedFees())
	require.Equal(t, big.NewInt(30), accumulator.GetDeveloperFees())
}
