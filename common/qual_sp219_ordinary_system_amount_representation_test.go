package common_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

// These two decimal strings are synthetic representation fixtures, not
// selected economic settings. No system contract is created or executed.
func TestQualSP219OrdinarySystemAmountRepresentation(t *testing.T) {
	t.Parallel()

	const fixture = `
[ESDTSystemSCConfig]
BaseIssuingCost = "123456789012345678901234"
[StakingSystemSCConfig]
GenesisNodePrice = "234567890123456789012345"
`
	file := filepath.Join(t.TempDir(), "system.toml")
	require.NoError(t, os.WriteFile(file, []byte(fixture), 0600))

	cfg, err := common.LoadSystemSmartContractsConfig(file)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, "123456789012345678901234", cfg.ESDTSystemSCConfig.BaseIssuingCost)
	require.Equal(t, "234567890123456789012345", cfg.StakingSystemSCConfig.GenesisNodePrice)
}
