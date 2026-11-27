package disabled

import "testing"

// Verify the documented local reporting values without any state or storage access.
func TestQualSP281COrdinaryDisabledStatisticsReports(t *testing.T) {
	t.Parallel()

	stats := NewStateStatistics()
	if got := stats.ProcessingStats(); got != nil {
		t.Fatalf("ProcessingStats() = %v; want nil", got)
	}
	if got := stats.SnapshotStats(); got != nil {
		t.Fatalf("SnapshotStats() = %v; want nil", got)
	}
}
