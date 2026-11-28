package enablers_test

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
)

// Static configuration readback, not an activation, live-start or admission
// test. The optional directory must be an independently hash-matched public
// snapshot; the default is the stock source fixture used by ordinary CI.
func TestQualSP219W01PublicEpochRoundLoader(t *testing.T) {
	dir := os.Getenv("DRWA_W01_PUBLIC_CONFIG_DIR")
	if dir == "" {
		dir = "../../cmd/node/config"
	}
	path := filepath.Join(dir, "enableEpochs.toml")
	decoded, err := toml.LoadFile(path)
	require.NoError(t, err)
	cfg, err := common.LoadEpochConfig(path)
	require.NoError(t, err)
	epochs, err := enablers.NewEnableEpochsHandler(cfg.EnableEpochs, &epochNotifier.EpochNotifierStub{})
	require.NoError(t, err)
	fields := []struct {
		name string
		flag core.EnableEpochFlag
	}{
		{"SupernovaEnableEpoch", common.SupernovaFlag},
		{"DynamicESDTEnableEpoch", common.DynamicESDTFlag},
		{"ESDTEnableEpoch", common.ESDTFlag},
		{"MetaESDTSetEnableEpoch", common.MetaESDTSetFlag},
		{"GlobalMintBurnDisableEpoch", common.GlobalMintBurnFlag},
		{"NFTStopCreateEnableEpoch", common.NFTStopCreateFlag},
		{"SetGuardianEnableEpoch", common.SetGuardianFlag},
		{"EGLDInMultiTransferEnableEpoch", common.EGLDInESDTMultiTransferFlag},
		{"ESDTMetadataContinuousCleanupEnableEpoch", common.ESDTMetadataContinuousCleanupFlag},
		{"SCProcessorV2EnableEpoch", common.SCProcessorV2Flag},
		{"RelayedTransactionsV3EnableEpoch", common.RelayedTransactionsV3Flag},
		{"RelayedTransactionsV3FixESDTTransferEnableEpoch", common.RelayedTransactionsV3FixESDTTransferFlag},
		{"FixRelayedBaseCostEnableEpoch", common.FixRelayedBaseCostFlag},
		{"FixRelayedMoveBalanceToNonPayableSCEnableEpoch", common.FixRelayedMoveBalanceToNonPayableSCFlag},
		{"ManagedCryptoAPIsEnableEpoch", common.ManagedCryptoAPIsFlag},
		{"ESDTMultiTransferEnableEpoch", common.ESDTNFTImprovementV1Flag},
		{"BuiltInFunctionsEnableEpoch", common.BuiltInFunctionsFlag},
		{"FixDataTrieLeafValidationEnableEpoch", common.FixDataTrieLeafValidationFlag},
		{"FixCorrectSmallIntAndGasLimitsEnableEpoch", common.FixCorrectSmallIntAndGasLimitsFlag},
		{"OutputRollbackOnDestContextEnableEpoch", common.OutputRollbackOnDestContextFlag},
		{"KeepReturnDataOnAsyncTransferCallbackEnableEpoch", common.KeepReturnDataOnAsyncTransferCallbackFlag},
	}
	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			want, ok := decoded.Get("EnableEpochs." + field.name).(int64)
			require.True(t, ok, "public field must be explicit")
			require.True(t, epochs.IsFlagDefined(field.flag))
			require.Equal(t, uint32(want), epochs.GetActivationEpoch(field.flag))
		})
	}
	roundPath := filepath.Join(dir, "enableRounds.toml")
	roundRaw, err := toml.LoadFile(roundPath)
	require.NoError(t, err)
	roundString, ok := roundRaw.Get("RoundActivations.SupernovaEnableRound.Round").(string)
	require.True(t, ok)
	wantRound, err := strconv.ParseUint(roundString, 10, 64)
	require.NoError(t, err)
	roundConfig, err := common.LoadRoundConfig(roundPath)
	require.NoError(t, err)
	rounds, err := enablers.NewEnableRoundsHandler(*roundConfig, &epochNotifier.RoundNotifierStub{})
	require.NoError(t, err)
	require.Equal(t, wantRound, rounds.GetActivationRound(common.SupernovaRoundFlag))
}

// The stock distribution configuration is parsed only; no role, provider,
// network, key file or runtime startup is constructed.
func TestQualSP219W01StockNativeLoaders(t *testing.T) {
	dir := "../../cmd/node/config"
	_, err := common.LoadMainConfig(filepath.Join(dir, "config.toml"))
	require.NoError(t, err)
	_, err = common.LoadApiConfig(filepath.Join(dir, "api.toml"))
	require.NoError(t, err)
	_, err = common.LoadEconomicsConfig(filepath.Join(dir, "economics.toml"))
	require.NoError(t, err)
	_, err = common.LoadSystemSmartContractsConfig(filepath.Join(dir, "systemSmartContractsConfig.toml"))
	require.NoError(t, err)
	_, err = common.LoadRatingsConfig(filepath.Join(dir, "ratings.toml"))
	require.NoError(t, err)
	_, err = common.LoadPreferencesConfig(filepath.Join(dir, "prefs.toml"))
	require.NoError(t, err)
	_, err = common.LoadExternalConfig(filepath.Join(dir, "external.toml"))
	require.NoError(t, err)
	for _, file := range []string{"p2p.toml", "fullArchiveP2P.toml"} {
		_, err = common.LoadP2PConfig(filepath.Join(dir, file))
		require.NoError(t, err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "gasSchedules", "gasSchedule*.toml"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, file := range files {
		costs, err := common.LoadGasScheduleConfig(file)
		require.NoError(t, err)
		require.NotEmpty(t, costs)
	}
}

// Three additional transitive predicates in revision05, beyond the fourteen
// direct E05 epoch flags and four G11 field tests. Synthetic values test only
// the pure loader/handler binding, never node admission or execution.
func TestQualSP219W01TransitiveFieldBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epochs.toml")
	require.NoError(t, os.WriteFile(path, []byte(`[EnableEpochs]
ManagedCryptoAPIsEnableEpoch = 11
ESDTMultiTransferEnableEpoch = 23
BuiltInFunctionsEnableEpoch = 37
`), 0600))
	cfg, err := common.LoadEpochConfig(path)
	require.NoError(t, err)
	handler, err := enablers.NewEnableEpochsHandler(cfg.EnableEpochs, &epochNotifier.EpochNotifierStub{})
	require.NoError(t, err)
	for _, tc := range []struct {
		flag core.EnableEpochFlag
		at   uint32
	}{{common.ManagedCryptoAPIsFlag, 11}, {common.ESDTNFTImprovementV1Flag, 23}, {common.BuiltInFunctionsFlag, 37}} {
		require.Equal(t, tc.at, handler.GetActivationEpoch(tc.flag))
		require.False(t, handler.IsFlagEnabledInEpoch(tc.flag, tc.at-1))
		require.True(t, handler.IsFlagEnabledInEpoch(tc.flag, tc.at))
		require.True(t, handler.IsFlagEnabledInEpoch(tc.flag, tc.at+1))
	}
}
