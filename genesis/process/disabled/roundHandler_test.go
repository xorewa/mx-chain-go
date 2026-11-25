package disabled

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRoundHandler_TimeDurationForRoundReturnsZero(t *testing.T) {
	t.Parallel()

	handler := &RoundHandler{}
	for _, round := range []uint64{0, 1, 42} {
		require.Equal(t, time.Duration(0), handler.TimeDurationForRound(round))
	}
}
