package presenter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/cmd/termui/presenter"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

// Exercise the detached preferences loader and local display DTO boundary.
// The metric transfer is in memory; no node or metrics provider is started.
func TestQualSP219OrdinaryPreferenceDisplayToPresenter(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, fixture, wantDecoded, wantDisplay string
	}{
		{"stock_empty", "[Preferences]\nNodeDisplayName = \"\"\n", "", "noname"},
		{"omitted", "[Preferences]\n", "", "noname"},
		{"literal_whitespace_and_unicode", "[Preferences]\nNodeDisplayName = \"  Café δ  \"\n", "  Café δ  ", "  Café δ  "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "prefs.toml")
			require.NoError(t, os.WriteFile(filename, []byte(tc.fixture), 0600))

			cfg, err := common.LoadPreferencesConfig(filename)
			require.NoError(t, err)
			require.NotNil(t, cfg)
			require.Equal(t, tc.wantDecoded, cfg.Preferences.NodeDisplayName)

			display := presenter.NewPresenterStatusHandler()
			display.SetStringValue(common.MetricNodeDisplayName, cfg.Preferences.NodeDisplayName)
			require.Equal(t, tc.wantDisplay, display.GetNodeName())
		})
	}
}
