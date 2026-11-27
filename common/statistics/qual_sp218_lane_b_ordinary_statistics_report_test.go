package statistics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP218OrdinaryStatisticsReportLabels(t *testing.T) {
	t.Parallel()

	stats := NewStateStatistics()
	require.Equal(t, []string{"cache op = 0", "trie op = 0"}, stats.ProcessingStats())
	require.Equal(t, []string{"snapshot cache op = 0"}, stats.SnapshotStats())

	const label uint32 = 7
	stats.IncrCache()
	for range 2 {
		stats.IncrTrie()
	}
	for range 3 {
		stats.IncrPersister(label)
	}
	for range 4 {
		stats.IncrWritePersister(label)
	}
	for range 5 {
		stats.IncrSnapshotCache()
	}
	for range 6 {
		stats.IncrSnapshotPersister(label)
	}

	require.Equal(t, []string{
		"cache op = 1",
		"persister epoch = 7 op = 3",
		"write persister epoch = 7 op = 4",
		"trie op = 2",
	}, stats.ProcessingStats())
	require.Equal(t, []string{
		"snapshot cache op = 5",
		"snapshot persister epoch = 7 op = 6",
	}, stats.SnapshotStats())
}
