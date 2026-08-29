package f1t

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExactSignResolutionBoundary(t *testing.T) {
	_, _, err := exactSignP(0, 17)
	require.ErrorIs(t, err, ErrDiagnostics)
	p, resolution, err := exactSignP(0, 18)
	require.NoError(t, err)
	require.Equal(t, new(big.Rat).SetFrac64(1, 131072), p)
	require.Equal(t, p, resolution)
	require.LessOrEqual(t, resolution.Cmp(firstHolmThreshold()), 0)
}

func TestRunsDistributionSumsToConditionalPopulation(t *testing.T) {
	for low := 1; low <= 7; low++ {
		for high := 1; high <= 7; high++ {
			total := new(big.Int)
			for _, count := range runsDistribution(low, high) {
				total.Add(total, count)
			}
			require.Equal(t, new(big.Int).Binomial(int64(low+high), int64(low)), total)
		}
	}
}

func TestDiagnosticCellRejectsDeterministicTrendAndTies(t *testing.T) {
	trend := make([]uint64, SamplesPerProfilePathLoad)
	for index := range trend {
		trend[index] = uint64(index + 1)
	}
	decisions, err := evaluateDiagnosticCell("trend", trend)
	require.NoError(t, err)
	rejected := false
	for _, decision := range decisions {
		rejected = rejected || decision.p.Cmp(firstHolmThreshold()) <= 0
	}
	require.True(t, rejected)

	ties := make([]uint64, SamplesPerProfilePathLoad)
	_, err = evaluateDiagnosticCell("ties", ties)
	require.ErrorIs(t, err, ErrDiagnostics)
}

func TestExactRunsDetectsClusteringAlternationAndResolutionBoundary(t *testing.T) {
	clustered := append(append(make([]uint64, 11), 1), repeatUint64(2, 11)...)
	p, resolution, _, ties, err := exactRunsP(clustered)
	require.NoError(t, err)
	require.Equal(t, 1, ties)
	require.LessOrEqual(t, p.Cmp(firstHolmThreshold()), 0)
	require.LessOrEqual(t, resolution.Cmp(firstHolmThreshold()), 0)

	above := append(append(make([]uint64, 10), 1), repeatUint64(2, 10)...)
	_, aboveResolution, _, _, err := exactRunsP(above)
	require.NoError(t, err)
	require.Greater(t, aboveResolution.Cmp(firstHolmThreshold()), 0)

	alternating := make([]uint64, 0, 23)
	for index := 0; index < 11; index++ {
		alternating = append(alternating, 0, 2)
	}
	alternating = append(alternating, 1)
	p, _, _, _, err = exactRunsP(alternating)
	require.NoError(t, err)
	require.LessOrEqual(t, p.Cmp(firstHolmThreshold()), 0)

	medianHeavy := append(append(make([]uint64, 2292), repeatUint64(1, 19)...), repeatUint64(2, 2292)...)
	_, resolution, effective, ties, err := exactRunsP(medianHeavy)
	require.NoError(t, err)
	require.Equal(t, 4584, effective)
	require.Equal(t, 19, ties)
	require.LessOrEqual(t, resolution.Cmp(firstHolmThreshold()), 0)
}

func TestFrozenBlockLayoutAndHolmDecisionAreMutationSensitive(t *testing.T) {
	require.True(t, validDiagnosticBlockSizes([]int{576, 576, 576, 575, 575, 575, 575, 575}))
	require.False(t, validDiagnosticBlockSizes([]int{575, 576, 576, 576, 575, 575, 575, 575}))
	require.False(t, validDiagnosticBlockSizes([]int{576, 576, 576, 575, 575, 575, 575}))
	require.Equal(t, new(big.Rat).SetFrac64(1, 104400), firstHolmThreshold())

	decisions := make([]exactDecision, TotalDiagnosticDecisions)
	for index := range decisions {
		decisions[index] = newExactDecision("Z", "cell", "pair", big.NewRat(1, 1), 575, 0)
	}
	decisions[0] = newExactDecision("A", "cell", "pair", big.NewRat(1, 104400), 575, 0)
	result, rejected, err := applyHolm(decisions)
	require.NoError(t, err)
	require.True(t, rejected)
	require.True(t, result[0].Rejected)
	require.False(t, result[1].Rejected)
	require.Equal(t, 1, result[0].HolmRank)
	require.Equal(t, "1", result[0].PValue.Numerator)
	require.Equal(t, "104400", result[0].PValue.Denominator)
}

func repeatUint64(value uint64, count int) []uint64 {
	result := make([]uint64, count)
	for index := range result {
		result[index] = value
	}
	return result
}
