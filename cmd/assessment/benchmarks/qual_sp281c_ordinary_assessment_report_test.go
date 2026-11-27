package benchmarks

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryAssessmentReportBoundary(t *testing.T) {
	t.Parallel()

	const rule = "+-----------+-----------------+-------+\r\n"
	const header = "| Benchmark | Time in seconds | Error |\r\n"

	t.Run("empty report retains total", func(t *testing.T) {
		t.Parallel()

		report := &TestResults{}
		require.Equal(t, [][]string{{"TOTAL", "0.000", ""}}, report.ToStrings())
		want := rule + header + rule + "| TOTAL     | 0.000           |       |\r\n" + rule
		require.Equal(t, want, report.ToDisplayTable())
	})

	t.Run("single report retains fractional duration", func(t *testing.T) {
		t.Parallel()

		report := &TestResults{
			TotalDuration: 1250 * time.Millisecond,
			Results:       []SingleResult{{Duration: 1250 * time.Millisecond, Name: "sample"}},
		}
		require.Equal(t, [][]string{{"sample", "1.250", ""}, {"TOTAL", "1.250", ""}}, report.ToStrings())
		want := strings.Join([]string{
			rule, header, rule,
			"| sample    | 1.250           |       |\r\n", rule,
			"| TOTAL     | 1.250           |       |\r\n", rule,
		}, "")
		require.Equal(t, want, report.ToDisplayTable())
	})
}
