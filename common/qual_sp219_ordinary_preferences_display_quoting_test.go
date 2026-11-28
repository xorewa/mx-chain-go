package common_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

// A friendly display label has the same value in basic and literal TOML strings.
// This checks only detached parsing, not a running node or identity selection.
func TestQualSP219OrdinaryPreferencesDisplayQuoting(t *testing.T) {
	t.Parallel()

	const expected = `Sample "North" \ Desk`
	for _, tc := range []struct {
		name    string
		fixture string
	}{
		{"basic", `[Preferences]
NodeDisplayName = "Sample \"North\" \\ Desk"
`},
		{"literal", `[Preferences]
NodeDisplayName = 'Sample "North" \ Desk'
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "preferences.toml")
			require.NoError(t, os.WriteFile(filename, []byte(tc.fixture), 0600))
			cfg, err := common.LoadPreferencesConfig(filename)
			require.NoError(t, err)
			require.NotNil(t, cfg)
			require.Equal(t, expected, cfg.Preferences.NodeDisplayName)
		})
	}
}
