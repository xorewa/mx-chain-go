package common_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

// Check only the detached representation of the stock JSON format label.
func TestQualSP219OrdinaryExternalFormatLabels(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, fixture, wantEvent string
		wantHosts                []string
	}{
		{"specified_and_omitted", `[EventNotifierConnector]
MarshallerType = "json"
[[HostDriversConfig]]
MarshallerType = "json"
[[HostDriversConfig]]
`, "json", []string{"json", ""}},
		{"only_host", `[[HostDriversConfig]]
MarshallerType = "json"
`, "", []string{"json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "external.toml")
			require.NoError(t, os.WriteFile(file, []byte(tc.fixture), 0600))

			cfg, err := common.LoadExternalConfig(file)
			require.NoError(t, err)
			require.NotNil(t, cfg)
			require.Equal(t, tc.wantEvent, cfg.EventNotifierConnector.MarshallerType)
			require.Len(t, cfg.HostDriversConfig, len(tc.wantHosts))
			for i, want := range tc.wantHosts {
				require.Equal(t, want, cfg.HostDriversConfig[i].MarshallerType)
			}
		})
	}
}
