package common_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

// Decode a supplied display label without constructing any effective configuration.
func TestQualSP219OrdinaryPreferencesDisplayName(t *testing.T) {
	t.Parallel()

	const displayName = "Café 🌿 Display"
	const fixture = "[Preferences]\nNodeDisplayName = \"" + displayName + "\"\n"
	file := filepath.Join(t.TempDir(), "preferences.toml")
	require.NoError(t, os.WriteFile(file, []byte(fixture), 0600))

	preferences, err := common.LoadPreferencesConfig(file)
	require.NoError(t, err)
	require.NotNil(t, preferences)
	require.Equal(t, displayName, preferences.Preferences.NodeDisplayName)
}
