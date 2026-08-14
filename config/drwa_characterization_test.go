package config

import (
	"testing"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
)

// The TOML decoder does not validate DRWA's dependent fields. A profile that
// toggles only Enabled loads successfully, and the node fails later during
// genesis caller provisioning.
func TestCharacterization_DRWAEnabledOnlyTomlDecodesWithZeroValueDependencies(t *testing.T) {
	var cfg Config
	err := toml.Unmarshal([]byte("[DRWA]\nEnabled = true\n"), &cfg)
	require.NoError(t, err)
	require.True(t, cfg.DRWA.Enabled)
	require.Empty(t, cfg.DRWA.KeyManagementModel)
	require.Equal(t, DRWAAuthorizedCallersConfig{}, cfg.DRWA.AuthorizedCallers)
	require.Empty(t, cfg.DRWA.RecoveryGovernance)
}
