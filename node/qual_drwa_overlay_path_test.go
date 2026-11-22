package node_test

import (
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/factory"
	processing "github.com/multiversx/mx-chain-go/factory/processing"
	"github.com/multiversx/mx-chain-go/node"
	processmock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/components"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

type qualOverlayCore struct {
	factory.CoreComponentsHolder
	epochs common.EnableEpochsHandler
	rounds common.EnableRoundsHandler
}

func (c *qualOverlayCore) EnableEpochsHandler() common.EnableEpochsHandler { return c.epochs }
func (c *qualOverlayCore) EnableRoundsHandler() common.EnableRoundsHandler { return c.rounds }

// Reuse the existing native configuration/component fixtures; no node Start,
// VM creation or transaction is invoked by these cases. The existing fixture
// starts native P2P listeners only inside the loopback-only test namespace.
func qualOverlayArgs(t *testing.T) (*config.Configs, processing.ProcessComponentsFactoryArgs) {
	t.Helper()
	cfg, err := testscommon.CreateTestConfigs(t.TempDir(), "../cmd/node/config")
	require.NoError(t, err)
	// Existing components helper uses paths relative to factory/processing.
	t.Chdir("../factory/processing")
	args := components.GetProcessComponentsFactoryArgs(processmock.NewOneShardCoordinatorMock())
	values := []interface{}{args.BootstrapComponents, args.StatusComponents, args.StatusCoreComponents, args.State, args.Data, args.Network, args.Crypto, args.CoreData}
	t.Cleanup(func() {
		for _, value := range values {
			if closer, ok := value.(interface{ Close() error }); ok {
				require.NoError(t, closer.Close())
			}
		}
	})
	epochs, err := enablers.NewEnableEpochsHandler(cfg.EpochConfig.EnableEpochs, forking.NewGenericEpochNotifier())
	require.NoError(t, err)
	rounds, err := enablers.NewEnableRoundsHandler(*cfg.RoundConfig, forking.NewGenericRoundNotifier())
	require.NoError(t, err)
	args.CoreData = &qualOverlayCore{CoreComponentsHolder: args.CoreData, epochs: epochs, rounds: rounds}
	args.Config = *cfg.GeneralConfig
	args.EpochConfig = *cfg.EpochConfig
	args.RoundConfig = *cfg.RoundConfig
	args.EconomicsConfig = *cfg.EconomicsConfig
	args.DRWAEffectiveConfigs = cfg
	overlay := filepath.Join(t.TempDir(), "drwa.toml")
	require.NoError(t, os.WriteFile(overlay, []byte("DRWAEnforcementEnableEpoch = 3\n"), 0600))
	args.DRWAConfigurationOverlay = overlay
	return cfg, args
}

func TestQualDRWAOverlayActualFactoryAdmission(t *testing.T) {
	for _, mode := range []string{"absent", "valid", "missing-coordinate", "mint-burn", "effective-mismatch", "native-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			cfg, args := qualOverlayArgs(t)
			switch mode {
			case "absent":
				args.DRWAConfigurationOverlay = ""
				args.DRWAEffectiveConfigs = nil
			case "missing-coordinate":
				require.NoError(t, os.WriteFile(args.DRWAConfigurationOverlay, nil, 0600))
			case "mint-burn":
				cfg.EpochConfig.EnableEpochs.GlobalMintBurnDisableEpoch = 4
				args.EpochConfig = *cfg.EpochConfig
			case "effective-mismatch":
				args.Config.GeneralSettings.SetGuardianEpochsDelay++
			case "native-mismatch":
				changed := cfg.EpochConfig.EnableEpochs
				changed.SupernovaEnableEpoch = 3
				epochs, err := enablers.NewEnableEpochsHandler(changed, forking.NewGenericEpochNotifier())
				require.NoError(t, err)
				args.CoreData.(*qualOverlayCore).epochs = epochs
			}
			created, err := processing.NewProcessComponentsFactory(args)
			if mode == "absent" || mode == "valid" {
				require.NoError(t, err)
				require.NotNil(t, created)
				return
			}
			require.Error(t, err)
			require.Nil(t, created)
			switch mode {
			case "missing-coordinate":
				require.ErrorContains(t, err, "missing DRWAEnforcementEnableEpoch")
			case "mint-burn":
				require.ErrorContains(t, err, "GlobalMintBurnFlag=false")
			case "effective-mismatch":
				require.ErrorContains(t, err, "effective inputs do not match")
			case "native-mismatch":
				require.ErrorContains(t, err, "activation inputs do not match")
			}
		})
	}
}

func TestQualDRWAOverlayNodeForwardsExactPath(t *testing.T) {
	for _, mode := range []string{"missing-file", "missing-coordinate"} {
		t.Run(mode, func(t *testing.T) {
			cfg, args := qualOverlayArgs(t)
			overlay := filepath.Join(t.TempDir(), "selected-overlay.toml")
			if mode == "missing-coordinate" {
				require.NoError(t, os.WriteFile(overlay, nil, 0600))
			}
			cfg.ConfigurationPathsHolder.DRWA = overlay
			runner, err := node.NewNodeRunner(cfg)
			require.NoError(t, err)
			created, err := runner.CreateManagedProcessComponents(args.CoreData, args.Crypto, args.Network, args.BootstrapComponents, args.State, args.Data, args.StatusComponents, args.StatusCoreComponents, args.GasSchedule, args.NodesCoordinator)
			require.Error(t, err)
			require.Nil(t, created)
			if mode == "missing-file" {
				require.ErrorIs(t, err, os.ErrNotExist)
			} else {
				require.ErrorContains(t, err, "missing DRWAEnforcementEnableEpoch")
			}
		})
	}
}
