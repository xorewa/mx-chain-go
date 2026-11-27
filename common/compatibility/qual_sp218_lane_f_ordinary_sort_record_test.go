package compatibility

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP218OrdinarySortRecordAssociation(t *testing.T) {
	t.Parallel()

	type displayRecord struct {
		rank  int
		label string
		value string
	}

	records := []displayRecord{
		{4, "plum", "four"},
		{1, "pear", "one"},
		{6, "lime", "six"},
		{3, "apple", "three"},
		{5, "fig", "five"},
		{2, "pear", "two"},
	}

	SortSlice(
		func(i, j int) { records[i], records[j] = records[j], records[i] },
		func(i, j int) bool { return records[i].rank < records[j].rank },
		len(records),
	)

	require.Equal(t, []displayRecord{
		{1, "pear", "one"},
		{2, "pear", "two"},
		{3, "apple", "three"},
		{4, "plum", "four"},
		{5, "fig", "five"},
		{6, "lime", "six"},
	}, records)
}
