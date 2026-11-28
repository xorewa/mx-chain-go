package common_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

// Check only the detached dashboard option representation, not a connector.
func TestQualSP219OrdinaryExternalDashboardFlag(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, field string
		want        bool
	}{
		{"stock_false", "UseKibana = false\n", false},
		{"explicit_true", "UseKibana = true\n", true},
		{"omitted", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "external.toml")
			fixture := "[ElasticSearchConnector]\n" + tc.field
			require.NoError(t, os.WriteFile(filename, []byte(fixture), 0600))

			cfg, err := common.LoadExternalConfig(filename)
			require.NoError(t, err)
			require.NotNil(t, cfg)
			require.Equal(t, tc.want, cfg.ElasticSearchConnector.UseKibana)
		})
	}
}
