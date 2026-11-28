package drwa

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualDRWAP11ReplicationWorkReservationArithmetic(t *testing.T) {
	// Abstract gas units for arithmetic only, not a selected native price.
	work := []replicationShardWork{{2, 3, 5}, {7, 11, 13}, {17, 19, 23}}
	for _, tc := range []struct {
		name      string
		available uint64
		source    uint64
		shards    uint32
		work      []replicationShardWork
		want      uint64
		remaining uint64
	}{
		{name: "complete exact budget", available: 104, source: 4, shards: 3, work: work, want: 104},
		{name: "surplus budget", available: 112, source: 4, shards: 3, work: work, want: 104, remaining: 8},
		{name: "short budget", available: 103, source: 4, shards: 3, work: work},
		{name: "missing cost", available: 104, source: 4, shards: 3, work: work[:2]},
		{name: "no configured set", available: 104, source: 4},
		{name: "no priced work", available: 104, shards: 1, work: []replicationShardWork{{}}},
		{name: "unrepresentable total", available: math.MaxUint64, source: math.MaxUint64, shards: 3, work: work},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reserved, remaining, err := reserveReplicationWork(tc.available, tc.source, tc.shards, tc.work)
			if tc.want == 0 {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.want, reserved)
			require.Equal(t, tc.remaining, remaining)
		})
	}
}
