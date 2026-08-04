package statusHandler_test

import (
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-go/statusHandler"
	"github.com/stretchr/testify/require"
)

// TestStatusMetricsDRWALinesAreStableForConsumers protects consumers that
// scrape the text exposition format. The source snapshots are maps, so their
// iteration order is intentionally unspecified; the set of emitted DRWA
// metric lines must nevertheless remain stable and parseable.
func TestStatusMetricsDRWALinesAreStableForConsumers(t *testing.T) {
	originalGateProvider := statusHandler.DrwaGateMetricsSnapshotProviderForTests()
	originalSyncProvider := statusHandler.DrwaSyncMetricsSnapshotProviderForTests()
	statusHandler.SetDrwaGateMetricsSnapshotProviderForTests(func() map[string]uint64 {
		return map[string]uint64{
			"gate-reader-missing": 2,
			"gate.decode.failure": 1,
		}
	})
	statusHandler.SetDrwaSyncMetricsSnapshotProviderForTests(func() map[string]uint64 {
		return map[string]uint64{"sync_apply_success": 5}
	})
	defer statusHandler.SetDrwaGateMetricsSnapshotProviderForTests(originalGateProvider)
	defer statusHandler.SetDrwaSyncMetricsSnapshotProviderForTests(originalSyncProvider)

	metrics := createStatusMetrics()
	first, err := metrics.StatusMetricsWithoutP2PPrometheusString()
	require.NoError(t, err)
	second, err := metrics.StatusMetricsWithoutP2PPrometheusString()
	require.NoError(t, err)

	firstLines := drwaMetricLines(first)
	secondLines := drwaMetricLines(second)
	require.ElementsMatch(t, firstLines, secondLines)
	require.ElementsMatch(t, []string{
		`erd_drwa_gate_gate_reader_missing{erd_shard_id="0"} 2`,
		`erd_drwa_gate_gate_decode_failure{erd_shard_id="0"} 1`,
		`erd_drwa_sync_sync_apply_success{erd_shard_id="0"} 5`,
	}, firstLines)

	for _, line := range firstLines {
		fields := strings.Fields(line)
		require.Len(t, fields, 2, "metric line must contain a name/labels field and value")
		require.NotEmpty(t, fields[1])
		require.Contains(t, fields[0], `erd_shard_id="0"`)
	}
}

func drwaMetricLines(output string) []string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(line, "erd_drwa_") {
			result = append(result, line)
		}
	}
	return result
}
