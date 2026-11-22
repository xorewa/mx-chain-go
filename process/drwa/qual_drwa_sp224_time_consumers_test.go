package drwa

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

// T05 and AR-05 specify the predicates. This test only compares them with
// synthetic typed headers. It supplies no native authority or debit proof.
func TestQualSP224EvaluatedHeaderTimeConsumerBoundaries(t *testing.T) {
	meta := qualHeaderTimeOwner(t)
	proposed := qualGovernedContext(t, meta, core.MetachainShardId, 100)
	window, err := newGovernedActionWindow(proposed, 5, 20, 105, 120)
	require.NoError(t, err)

	t.Run("metachain certificate and GAS upper boundary", func(t *testing.T) {
		codec := registrationApprovalCodec{bounds: registrationApprovalBounds{maxValidity: 20}}
		for _, tt := range []struct {
			name             string
			millis           uint64
			certificateValid bool
			mayArm           bool
		}{
			{"before", 119, true, true},
			{"equal", 120, true, false},
			{"after", 121, false, false},
		} {
			t.Run(tt.name, func(t *testing.T) {
				context := qualGovernedContext(t, meta, core.MetachainShardId, tt.millis)
				at, readErr := context.Milliseconds()
				require.NoError(t, readErr)
				require.Equal(t, HeaderMilliseconds(tt.millis), at)
				require.Equal(t, tt.certificateValid, codec.bootstrapWindowValid(105, 120, at, 120))
				startErr := window.mayStart(context)
				if tt.mayArm {
					require.NoError(t, startErr)
				} else {
					require.ErrorIs(t, startErr, errGovernedActionTime)
				}
			})
		}
	})

	t.Run("F06 exclusive source cutoff", func(t *testing.T) {
		arm := qualGovernedContext(t, meta, core.MetachainShardId, 119)
		expiry, armErr := window.projectionExpiry(arm, 7)
		require.NoError(t, armErr)
		require.Equal(t, HeaderMilliseconds(126), expiry)

		const sourceShard uint32 = 1
		source := qualHeaderTimeOwner(t)
		for _, tt := range []struct {
			name         string
			millis       uint64
			timeEligible bool
		}{
			{"before", 125, true},
			{"equal", 126, false},
			{"after", 127, false},
		} {
			t.Run(tt.name, func(t *testing.T) {
				context := qualGovernedContext(t, source, sourceShard, tt.millis)
				eligible, checkErr := sourceProjectionBeforeExpiry(context, sourceShard, expiry)
				require.NoError(t, checkErr)
				require.Equal(t, tt.timeEligible, eligible)
			})
		}
	})
}
