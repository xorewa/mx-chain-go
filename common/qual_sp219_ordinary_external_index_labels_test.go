package common_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

// Detached index-label representation only; no connector is constructed.
func TestQualSP219OrdinaryExternalIndexLabels(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, fixture string
		want          []string
	}{
		{"ordered_labels", `[ElasticSearchConnector]
EnabledIndexes = ["sample-second", "Sample-first", "sample-third"]
`, []string{"sample-second", "Sample-first", "sample-third"}},
		{"explicit_empty_list", `[ElasticSearchConnector]
EnabledIndexes = []
`, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "external.toml")
			require.NoError(t, os.WriteFile(file, []byte(tc.fixture), 0600))

			cfg, err := common.LoadExternalConfig(file)
			require.NoError(t, err)
			require.NotNil(t, cfg)
			require.NotNil(t, cfg.ElasticSearchConnector.EnabledIndexes)
			require.Equal(t, tc.want, cfg.ElasticSearchConnector.EnabledIndexes)
		})
	}
}
