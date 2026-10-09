package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
)

// DEVELOPMENT under L46. These are exact loaded, non-normative fixture values,
// not accepted deployment values, complete startup or route qualification.
func qualDRWALoadedFiles(t *testing.T) (config.ConfigurationPathsHolder, string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"config.toml", "enableEpochs.toml", "enableRounds.toml", "economics.toml", "ratings.toml"} {
		value, err := os.ReadFile(filepath.Join("..", "..", "cmd", "node", "config", name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), value, 0600))
	}
	overlay := filepath.Join(dir, "drwa.toml")
	require.NoError(t, os.WriteFile(overlay, []byte("DRWAEnforcementEnableEpoch = 3\n"), 0600))
	return config.ConfigurationPathsHolder{MainConfig: filepath.Join(dir, "config.toml"),
		Epoch: filepath.Join(dir, "enableEpochs.toml"), RoundActivation: filepath.Join(dir, "enableRounds.toml"),
		Economics: filepath.Join(dir, "economics.toml"), Ratings: filepath.Join(dir, "ratings.toml")}, overlay
}

func qualDRWAReplaceLoaded(t *testing.T, path, before, after string) {
	t.Helper()
	value, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(value), before), "unique independently specified input replacement")
	require.NoError(t, os.WriteFile(path, []byte(strings.Replace(string(value), before, after, 1)), 0600))
}

func TestQualDRWALoadedConfigurationNativeLoaderControl(t *testing.T) {
	paths, overlay := qualDRWALoadedFiles(t)
	c, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true, RegisterMetaESDTPath: true})
	require.NoError(t, err)
	require.NoError(t, c.CheckEnforcedBlock(3, 440))
}

// E05 L606 is a native route condition, not a MetaESDT family exclusion.
// Protected DRWA creation calls createNewToken directly; the separate native
// registerMetaESDT route requires its flag when included in the route matrix.
func TestQualDRWALoadedConfigurationRegisterMetaESDTPath(t *testing.T) {
	for _, supported := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct-creation", true: "registerMetaESDT"}[supported], func(t *testing.T) {
			paths, overlay := qualDRWALoadedFiles(t)
			qualDRWAReplaceLoaded(t, paths.Epoch, "\n    MetaESDTSetEnableEpoch = 1", "\n    MetaESDTSetEnableEpoch = 4")
			candidate, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true, RegisterMetaESDTPath: supported})
			if supported {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NoError(t, candidate.CheckEnforcedBlock(3, 440))
			}
		})
	}
}

func TestQualDRWALoadedConfigurationJointPredicate(t *testing.T) {
	paths, overlay := qualDRWALoadedFiles(t)
	c, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true, RegisterMetaESDTPath: true})
	require.NoError(t, err)
	// All four actual native Supernova epoch/round cases, plus the independent
	// DRWA enforcement boundary. Expected values come from A L568-580/L683-688.
	for _, tc := range []struct {
		epoch uint32
		round uint64
		want  bool
	}{{1, 439, false}, {1, 440, false}, {2, 439, false}, {2, 440, false},
		{3, 439, false}, {3, 440, true}, {4, 441, true}, {^uint32(0), ^uint64(0), true}} {
		require.Equal(t, tc.want, c.Enabled(tc.epoch, tc.round))
		if tc.want {
			require.NoError(t, c.CheckEnforcedBlock(tc.epoch, tc.round))
		} else {
			require.Error(t, c.CheckEnforcedBlock(tc.epoch, tc.round))
		}
	}
	for _, tc := range []struct {
		epoch uint32
		round uint64
		want  bool
	}{
		{1, 439, false}, {1, 440, false}, {2, 439, false}, {2, 440, true},
	} {
		require.Equal(t, tc.want, common.IsAsyncExecutionEnabledForEpochAndRound(c.epochs, c.rounds, tc.epoch, tc.round))
	}
	epochs, rounds := c.ActivationInventory()
	require.Equal(t, uint32(1), epochs["GlobalMintBurnDisableEpoch"])
	require.Equal(t, uint32(1), epochs["ESDTMetadataContinuousCleanupEnableEpoch"])
	require.Equal(t, uint32(2), epochs["SupernovaEnableEpoch"])
	require.Equal(t, uint64(440), rounds["SupernovaEnableRound"])
	epochs["GlobalMintBurnDisableEpoch"] = 100
	rounds["SupernovaEnableRound"] = 100
	require.NoError(t, c.CheckEnforcedBlock(3, 440), "inventory mutation grants no change to loaded native predicates")
}

func qualDRWAEncodeLoaded(t *testing.T, path string, value interface{}) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	err = toml.NewEncoder(f).Encode(value)
	closeErr := f.Close()
	require.NoError(t, err)
	require.NoError(t, closeErr)
}

// Each native startup tuple table is an independently selected negative input.
// This encoder only constructs hostile fixture TOML; it is not the candidate
// generator or a producer of expected values from the implementation under test.
func TestQualDRWALoadedConfigurationStartupConsumers(t *testing.T) {
	mainCases := map[string]func(*config.Config){
		"chain-table":       func(c *config.Config) { c.GeneralSettings.ChainParametersByEpoch = nil },
		"epoch-grace":       func(c *config.Config) { c.GeneralSettings.EpochChangeGracePeriodByEpoch = nil },
		"process-epoch":     func(c *config.Config) { c.GeneralSettings.ProcessConfigsByEpoch = nil },
		"epoch-start-epoch": func(c *config.Config) { c.GeneralSettings.EpochStartConfigsByEpoch = nil },
		"consensus-epoch":   func(c *config.Config) { c.GeneralSettings.ConsensusConfigsByEpoch = nil },
		"process-round":     func(c *config.Config) { c.GeneralSettings.ProcessConfigsByRound = nil },
		"epoch-start-round": func(c *config.Config) { c.GeneralSettings.EpochStartConfigsByRound = nil },
		"consensus-round":   func(c *config.Config) { c.GeneralSettings.ConsensusConfigsByRound = nil },
		"antiflood-round":   func(c *config.Config) { c.Antiflood.ConfigsByRound = nil },
		"version-boundary": func(c *config.Config) {
			for i := range c.Versions.VersionsByEpochs {
				if c.Versions.VersionsByEpochs[i].Version == "3" {
					c.Versions.VersionsByEpochs[i].StartRound++
				}
			}
		},
		"missing-chain-genesis": func(c *config.Config) {
			kept := make([]config.ChainParametersByEpochConfig, 0)
			for _, p := range c.GeneralSettings.ChainParametersByEpoch {
				if p.EnableEpoch != 0 {
					kept = append(kept, p)
				}
			}
			c.GeneralSettings.ChainParametersByEpoch = kept
		},
		"duplicate-chain-epoch": func(c *config.Config) {
			c.GeneralSettings.ChainParametersByEpoch = append(c.GeneralSettings.ChainParametersByEpoch, c.GeneralSettings.ChainParametersByEpoch[0])
		},
		"pre-supernova-duration-change": func(c *config.Config) {
			p := c.GeneralSettings.ChainParametersByEpoch[0]
			p.EnableEpoch = 1
			p.RoundDuration = 1000
			c.GeneralSettings.ChainParametersByEpoch = append(c.GeneralSettings.ChainParametersByEpoch, p)
		},
		"duplicate-version-epoch": func(c *config.Config) {
			c.Versions.VersionsByEpochs = append(c.Versions.VersionsByEpochs, c.Versions.VersionsByEpochs[0])
		},
	}
	for name, mutate := range mainCases {
		t.Run(name, func(t *testing.T) {
			paths, overlay := qualDRWALoadedFiles(t)
			cfg, err := common.LoadMainConfig(paths.MainConfig)
			require.NoError(t, err)
			mutate(cfg)
			qualDRWAEncodeLoaded(t, paths.MainConfig, cfg)
			_, err = LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true, RegisterMetaESDTPath: true})
			require.Error(t, err)
		})
	}
	for _, name := range []string{"economics-gas", "shard-rating", "meta-rating"} {
		t.Run(name, func(t *testing.T) {
			paths, overlay := qualDRWALoadedFiles(t)
			if name == "economics-gas" {
				cfg, err := common.LoadEconomicsConfig(paths.Economics)
				require.NoError(t, err)
				cfg.FeeSettings.GasLimitSettings = nil
				qualDRWAEncodeLoaded(t, paths.Economics, cfg)
			} else {
				cfg, err := common.LoadRatingsConfig(paths.Ratings)
				require.NoError(t, err)
				if name == "shard-rating" {
					cfg.ShardChain.RatingStepsByEpoch = nil
				} else {
					cfg.MetaChain.RatingStepsByEpoch = nil
				}
				qualDRWAEncodeLoaded(t, paths.Ratings, cfg)
			}
			_, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true, RegisterMetaESDTPath: true})
			require.Error(t, err)
		})
	}
}

func TestQualDRWALoadedConfigurationPrerequisiteDenials(t *testing.T) {
	for _, field := range []string{"DynamicESDTEnableEpoch", "ESDTEnableEpoch", "MetaESDTSetEnableEpoch",
		"GlobalMintBurnDisableEpoch", "NFTStopCreateEnableEpoch", "SetGuardianEnableEpoch",
		"EGLDInMultiTransferEnableEpoch", "ManagedCryptoAPIsEnableEpoch", "SCProcessorV2EnableEpoch",
		"RelayedTransactionsV3EnableEpoch", "RelayedTransactionsV3FixESDTTransferEnableEpoch",
		"FixRelayedBaseCostEnableEpoch", "FixRelayedMoveBalanceToNonPayableSCEnableEpoch"} {
		t.Run(field, func(t *testing.T) {
			paths, overlay := qualDRWALoadedFiles(t)
			qualDRWAReplaceLoaded(t, paths.Epoch, "\n    "+field+" = 1", "\n    "+field+" = 4")
			_, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true, RegisterMetaESDTPath: true})
			require.Error(t, err, "first enforcement epoch is 3; native flag polarity must deny")
		})
	}
}

func TestQualDRWALoadedConfigurationMalformedAndAbsent(t *testing.T) {
	for _, fault := range []string{"missing-epoch", "negative-epoch", "overflow-epoch", "bad-toml", "missing-main", "missing-round", "malformed-round", "enforcement-before-supernova"} {
		t.Run(fault, func(t *testing.T) {
			paths, overlay := qualDRWALoadedFiles(t)
			switch fault {
			case "missing-epoch":
				require.NoError(t, os.WriteFile(overlay, []byte("# absent\n"), 0600))
			case "negative-epoch":
				require.NoError(t, os.WriteFile(overlay, []byte("DRWAEnforcementEnableEpoch = -1\n"), 0600))
			case "overflow-epoch":
				require.NoError(t, os.WriteFile(overlay, []byte("DRWAEnforcementEnableEpoch = 4294967296\n"), 0600))
			case "bad-toml":
				require.NoError(t, os.WriteFile(overlay, []byte("[\n"), 0600))
			case "missing-main":
				paths.MainConfig = filepath.Join(t.TempDir(), "absent.toml")
			case "missing-round":
				require.NoError(t, os.WriteFile(paths.RoundActivation, []byte("# absent\n"), 0600))
			case "malformed-round":
				qualDRWAReplaceLoaded(t, paths.RoundActivation, "Round = \"440\"", "Round = \"wrong\"")
			case "enforcement-before-supernova":
				require.NoError(t, os.WriteFile(overlay, []byte("DRWAEnforcementEnableEpoch = 1\n"), 0600))
			}
			_, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true, RegisterMetaESDTPath: true})
			require.Error(t, err)
		})
	}
	var absent *DRWAConfigurationCandidate
	require.False(t, absent.Enabled(3, 440))
	require.Error(t, absent.CheckEnforcedBlock(3, 440))
	require.False(t, (&DRWAConfigurationCandidate{}).Enabled(3, 440))
}
