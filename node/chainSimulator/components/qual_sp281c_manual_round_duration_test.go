package components

import (
	"testing"
	"time"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CManualRoundDurationForRound(t *testing.T) {
	const ordinaryDuration = 2 * time.Second
	const alternateDuration = 750 * time.Millisecond
	const requestedRound = uint64(12)

	for _, tc := range []struct {
		name   string
		active bool
		want   time.Duration
	}{
		{"ordinary duration", false, ordinaryDuration},
		{"alternate duration", true, alternateDuration},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, err := NewManualRoundHandler(ArgManualRoundHandler{
				EnableRoundsHandler: &testscommon.EnableRoundsHandlerStub{
					IsFlagEnabledInRoundCalled: func(flag common.EnableRoundFlag, round uint64) bool {
						require.Equal(t, common.SupernovaRoundFlag, flag)
						require.Equal(t, requestedRound, round)
						return tc.active
					},
				},
				RoundDuration:          ordinaryDuration,
				SupernovaRoundDuration: alternateDuration,
			})
			require.NoError(t, err)
			require.Equal(t, tc.want, handler.TimeDurationForRound(requestedRound))
			require.Zero(t, handler.Index())
		})
	}
}
