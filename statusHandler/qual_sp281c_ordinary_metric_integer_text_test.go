package statusHandler

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryMetricIntegerText(t *testing.T) {
	t.Parallel()

	// These independent display values do not come from collected metrics.
	output := strings.Builder{}
	formatter := &statusMetrics{}
	formatter.addPrometheusMetricToStringBuilder(&output, 0, "sample_zero", uint64(0))
	formatter.addPrometheusMetricToStringBuilder(&output, 0, "sample_unsigned", uint64(9007199254740993))
	formatter.addPrometheusMetricToStringBuilder(&output, 0, "sample_signed", int64(-9007199254740993))

	want := "sample_zero{erd_shard_id=\"0\"} 0\n" +
		"sample_unsigned{erd_shard_id=\"0\"} 9007199254740993\n" +
		"sample_signed{erd_shard_id=\"0\"} -9007199254740993\n"
	require.Equal(t, want, output.String())
}
