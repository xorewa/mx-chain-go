package chainSimulator

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

func TestCharacterizationCheckedOutLdevnetAllowsZeroSupplyBeforeDRWAEnforcement(t *testing.T) {
	t.Parallel()

	profileRoot, err := filepath.Abs(filepath.Join("..", "..", "..", "mx-chain-ldevnet-config"))
	require.NoError(t, err)
	if _, statErr := os.Stat(profileRoot); os.IsNotExist(statErr) {
		t.Skip("mx-chain-ldevnet-config is not present in this checkout")
	}

	epochConfig, err := common.LoadEpochConfig(filepath.Join(profileRoot, "enableEpochs.toml"))
	require.NoError(t, err)
	enableEpochs := epochConfig.EnableEpochs

	require.Equal(t, uint32(1), enableEpochs.ESDTEnableEpoch)
	require.Equal(t, uint32(1), enableEpochs.GlobalMintBurnDisableEpoch)
	require.Equal(t, uint32(3), enableEpochs.DRWAEnforcementEnableEpoch)

	// GlobalMintBurnFlag is defined as epoch < GlobalMintBurnDisableEpoch.
	// Consequently it is already inactive at the first ESDT-enabled epoch, and
	// remains inactive when checked-out Ldevnet DRWA enforcement starts.
	require.False(t, enableEpochs.ESDTEnableEpoch < enableEpochs.GlobalMintBurnDisableEpoch)
	require.False(t, enableEpochs.DRWAEnforcementEnableEpoch < enableEpochs.GlobalMintBurnDisableEpoch)

	systemSCConfig, err := common.LoadSystemSmartContractsConfig(
		filepath.Join(profileRoot, "systemSmartContractsConfig.toml"),
	)
	require.NoError(t, err)
	baseIssuingCost, ok := new(big.Int).SetString(
		systemSCConfig.ESDTSystemSCConfig.BaseIssuingCost,
		10,
	)
	require.True(t, ok)
	require.Equal(t, "50000000000000000", baseIssuingCost.String())
}

func TestCharacterizationCheckedOutNetworkProfilesExposeDifferentESDTPrerequisites(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                   string
		profileDirectory       string
		drwaEnforcementEpoch   uint32
		esdtEnableEpoch        uint32
		globalMintDisableEpoch uint32
		baseIssuingCost        string
	}{
		{
			name:                   "ldevnet",
			profileDirectory:       "mx-chain-ldevnet-config",
			drwaEnforcementEpoch:   3,
			esdtEnableEpoch:        1,
			globalMintDisableEpoch: 1,
			baseIssuingCost:        "50000000000000000",
		},
		{
			name:                   "devnet",
			profileDirectory:       "mx-chain-devnet-config",
			drwaEnforcementEpoch:   0,
			esdtEnableEpoch:        1,
			globalMintDisableEpoch: 1,
			baseIssuingCost:        "50000000000000000",
		},
		{
			name:                   "testnet",
			profileDirectory:       "mx-chain-testnet-config",
			drwaEnforcementEpoch:   0,
			esdtEnableEpoch:        1,
			globalMintDisableEpoch: 1,
			baseIssuingCost:        "50000000000000000",
		},
		{
			name:                   "mainnet",
			profileDirectory:       "mx-chain-mainnet-config",
			drwaEnforcementEpoch:   0,
			esdtEnableEpoch:        272,
			globalMintDisableEpoch: 432,
			baseIssuingCost:        "5000000000000000000",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			profileRoot, err := filepath.Abs(filepath.Join("..", "..", "..", testCase.profileDirectory))
			require.NoError(t, err)
			if _, statErr := os.Stat(profileRoot); os.IsNotExist(statErr) {
				t.Skipf("%s is not present in this checkout", testCase.profileDirectory)
			}

			mainConfig, err := common.LoadMainConfig(filepath.Join(profileRoot, "config.toml"))
			require.NoError(t, err)
			require.False(t, mainConfig.DRWA.Enabled)
			require.Empty(t, mainConfig.DRWA.KeyManagementModel)
			require.Empty(t, mainConfig.DRWA.AuthorizedCallers.AuthAdmin)

			epochConfig, err := common.LoadEpochConfig(filepath.Join(profileRoot, "enableEpochs.toml"))
			require.NoError(t, err)
			require.Equal(t, testCase.drwaEnforcementEpoch, epochConfig.EnableEpochs.DRWAEnforcementEnableEpoch)
			require.Equal(t, testCase.esdtEnableEpoch, epochConfig.EnableEpochs.ESDTEnableEpoch)
			require.Equal(t, testCase.globalMintDisableEpoch, epochConfig.EnableEpochs.GlobalMintBurnDisableEpoch)

			systemConfig, err := common.LoadSystemSmartContractsConfig(
				filepath.Join(profileRoot, "systemSmartContractsConfig.toml"),
			)
			require.NoError(t, err)
			require.Equal(t, testCase.baseIssuingCost, systemConfig.ESDTSystemSCConfig.BaseIssuingCost)
		})
	}
}
