package config

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

func TestDRWASettlementLifetimeProfileStockConfigIsExplicitlyDisabled(t *testing.T) {
	t.Parallel()

	cfg := &Config{}
	require.NoError(t, core.LoadTomlFile(cfg, "../cmd/node/config/config.toml"))
	require.Zero(t, cfg.BuiltInFunctions.DRWAMinSettlementLifetimeRounds)
	require.Zero(t, cfg.BuiltInFunctions.DRWASettlementLifetimeRounds)
	require.Zero(t, cfg.BuiltInFunctions.DRWAMaxSettlementLifetimeRounds)
}
