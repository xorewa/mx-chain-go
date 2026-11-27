package benchmarks

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestQualSP218OrdinaryAssessmentRepeatedRowLabels(t *testing.T) {
	t.Parallel()

	// These are supplied result DTOs, not benchmark executions or injected faults.
	report := &TestResults{
		TotalDuration: 2 * time.Second,
		Results: []SingleResult{
			{Duration: 750 * time.Millisecond, Name: "sample", Error: errors.New("display note")},
			{Duration: 1250 * time.Millisecond, Name: "sample"},
		},
	}

	want := [][]string{
		{"sample", "0.750", "display note"},
		{"sample", "1.250", ""},
		{"TOTAL", "2.000", ""},
	}
	require.Equal(t, want, report.ToStrings())

	var rows [][]string
	for _, line := range strings.Split(report.ToDisplayTable(), "\r\n") {
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(line, "|")
		require.Len(t, cells, 5)
		rows = append(rows, []string{
			strings.TrimSpace(cells[1]),
			strings.TrimSpace(cells[2]),
			strings.TrimSpace(cells[3]),
		})
	}

	require.Equal(t, append([][]string{{"Benchmark", "Time in seconds", "Error"}}, want...), rows)
}
