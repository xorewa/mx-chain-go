package main

import (
	"encoding/json"
	"github.com/multiversx/mx-chain-go/config"
	logger "github.com/multiversx/mx-chain-logger-go"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
	"os"
	"path/filepath"
	"testing"
)

func TestQualDRWAOverlayPathUsesNativeCLIAndLoader(t *testing.T) {
	var ordinary []byte
	for _, which := range []string{"absent", "explicit", "missing-file"} {
		app := cli.NewApp()
		app.Flags = getFlags()
		var loaded *config.Configs
		app.Action = func(ctx *cli.Context) error {
			var err error
			loaded, err = readConfigs(ctx, logger.GetOrCreate("qual-drwa-overlay"))
			return err
		}
		overlay := ""
		argv := []string{"qual-node"}
		if which != "absent" {
			overlay = filepath.Join(t.TempDir(), "drwa.toml")
			if which == "explicit" {
				require.NoError(t, os.WriteFile(overlay, []byte("DRWAEnforcementEnableEpoch = 3\n"), 0600))
			}
			argv = append(argv, "--drwa-config", overlay)
		}
		require.NoError(t, app.Run(argv))
		require.Equal(t, overlay, loaded.ConfigurationPathsHolder.DRWA)
		encoded, err := json.Marshal(loaded.GeneralConfig)
		require.NoError(t, err)
		if which == "absent" {
			ordinary = encoded
		} else {
			require.Equal(t, ordinary, encoded, "overlay filename must not alter ordinary main configuration")
		}
	}
}
