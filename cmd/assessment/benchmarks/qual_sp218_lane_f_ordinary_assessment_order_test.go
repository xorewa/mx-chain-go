package benchmarks

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestQualSP218OrdinaryAssessmentOrderedRows(t *testing.T) {
	t.Parallel()

	report := &TestResults{
		TotalDuration: 1500 * time.Millisecond,
		Results: []SingleResult{
			{Duration: 1250 * time.Millisecond, Name: "zeta"},
			{Duration: 250 * time.Millisecond, Name: "alpha"},
		},
	}

	wantRows := [][]string{
		{"zeta", "1.250", ""},
		{"alpha", "0.250", ""},
		{"TOTAL", "1.500", ""},
	}
	require.Equal(t, wantRows, report.ToStrings())

	// Verify the table preserves the same input order, row association and total.
	var tableRows [][]string
	for _, line := range strings.Split(report.ToDisplayTable(), "\r\n") {
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(line, "|")
		require.Len(t, cells, 5)
		tableRows = append(tableRows, []string{
			strings.TrimSpace(cells[1]),
			strings.TrimSpace(cells[2]),
			strings.TrimSpace(cells[3]),
		})
	}

	wantTable := append([][]string{{"Benchmark", "Time in seconds", "Error"}}, wantRows...)
	require.Equal(t, wantTable, tableRows)
}
