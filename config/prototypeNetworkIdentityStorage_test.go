package config

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

func TestPrototypeNetworkIdentityStorageStockConfigIsCrashDurable(t *testing.T) {
	t.Parallel()

	cfg := &Config{}
	require.NoError(t, core.LoadTomlFile(cfg, "../cmd/node/config/config.toml"))
	require.Equal(t, "LvlDBSerial", cfg.PrototypeNetworkIdentityStorage.DB.Type)
	require.Equal(t, 1, cfg.PrototypeNetworkIdentityStorage.DB.MaxBatchSize)
	require.Equal(t, 2, cfg.PrototypeNetworkIdentityStorage.DB.BatchDelaySeconds)
	require.NotEmpty(t, cfg.PrototypeNetworkIdentityStorage.DB.FilePath)
	require.GreaterOrEqual(t, cfg.PrototypeNetworkIdentityStorage.Cache.Capacity, uint32(1))
}
