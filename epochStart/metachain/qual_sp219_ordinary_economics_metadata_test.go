package metachain

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP219OrdinaryEconomicsTimingMetadata(t *testing.T) {
	t.Parallel()

	// Detached record metadata: the round and timestamp retain their full widths.
	// These literals are fixture values, not an actual epoch or runtime setting.
	record := &economicsComputationData{
		newEpoch:  23,
		round:     4_294_967_300,
		timeStamp: 1_782_345_678_901,
	}

	require.Equal(t, uint32(23), record.GetEpoch())
	require.Equal(t, uint64(4_294_967_300), record.GetRound())
	require.Equal(t, uint64(1_782_345_678_901), record.GetTimeStamp())
}
