//go:build !race

package process

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	chainCore "github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"

	chainCommon "github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/genesis/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

// These are characterization tests for the pre-bootstrap implementation.
// They deliberately document current behavior; they are not acceptance tests
// for the replacement lifecycle.

func TestCharacterization_DRWAEnabledWithBlankKeyModelFailsBeforeCallerValidation(t *testing.T) {
	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
	arg.DRWAConfig = config.DRWAConfig{
		Enabled:           true,
		AuthorizedCallers: characterizationAuthorizedCallers(),
	}

	err := setupDRWAAuthorizedCallers(arg)

	require.EqualError(t, err,
		`invalid DRWA key management model "": expected "multisig_3of5_contract"`)
}

func TestCharacterization_GenesisSurfacesBlankKeyModelAtDRWACallerProvisioning(t *testing.T) {
	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
	arg.DRWAConfig = config.DRWAConfig{Enabled: true}
	arg.EpochConfig.EnableEpochs.DRWAEnforcementEnableEpoch = 3

	creator, err := NewGenesisBlockCreator(arg)
	require.NoError(t, err)

	_, err = creator.CreateGenesisBlocks()
	require.Error(t, err)
	require.ErrorContains(t, err,
		`invalid DRWA key management model "": expected "multisig_3of5_contract"`)
	require.ErrorContains(t, err,
		"while provisioning DRWA authorized callers")
}

func TestCharacterization_DRWAEnabledOnlyFailsEveryNodeRoleAtShardZeroProvisioning(t *testing.T) {
	for _, selfShardID := range []uint32{0, 1, chainCore.MetachainShardId} {
		t.Run(fmt.Sprintf("self-shard-%d", selfShardID), func(t *testing.T) {
			arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
			arg.ShardCoordinator = &mock.ShardCoordinatorMock{NumOfShards: 2, SelfShardId: selfShardID}
			arg.Core.(*mock.CoreComponentsMock).Chain = "L"
			arg.DRWAConfig = config.DRWAConfig{Enabled: true}

			creator, err := NewGenesisBlockCreator(arg)
			require.NoError(t, err)
			_, err = creator.CreateGenesisBlocks()
			require.ErrorContains(t, err, `invalid DRWA key management model "": expected "multisig_3of5_contract"`)
			require.ErrorContains(t, err, "while provisioning DRWA authorized callers")
			require.ErrorContains(t, err, "while generating genesis block for shard 0")
		})
	}
}

func TestCharacterization_ChainIDDoesNotRelaxDRWAProvisioning(t *testing.T) {
	for _, chainID := range []string{"L", "D", "T", "1", "sovereign-example"} {
		t.Run(chainID, func(t *testing.T) {
			arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
			arg.Core.(*mock.CoreComponentsMock).Chain = chainID
			arg.DRWAConfig = config.DRWAConfig{Enabled: true}

			require.EqualError(t, setupDRWAAuthorizedCallers(arg),
				`invalid DRWA key management model "": expected "multisig_3of5_contract"`)
		})
	}
}

func TestCharacterization_CheckedOutNetworkProfilesReachExpectedActivationBoundary(t *testing.T) {
	profiles := []struct {
		name          string
		expectedError string
	}{
		{name: "mx-chain-ldevnet-config"},
		{
			name:          "mx-chain-devnet-config",
			expectedError: "DRWA enforcement is enabled at genesis but DRWA caller provisioning is disabled",
		},
		{
			name:          "mx-chain-testnet-config",
			expectedError: "DRWA enforcement is enabled at genesis but DRWA caller provisioning is disabled",
		},
		{
			name:          "mx-chain-mainnet-config",
			expectedError: "DRWA enforcement is enabled at genesis but DRWA caller provisioning is disabled",
		},
	}

	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			profileRoot, err := filepath.Abs(filepath.Join("..", "..", "..", profile.name))
			require.NoError(t, err)
			if _, statErr := os.Stat(profileRoot); os.IsNotExist(statErr) {
				t.Skip("cross-repository profile is not present in this checkout")
			}

			mainConfig, err := chainCommon.LoadMainConfig(filepath.Join(profileRoot, "config.toml"))
			require.NoError(t, err)
			epochConfig, err := chainCommon.LoadEpochConfig(filepath.Join(profileRoot, "enableEpochs.toml"))
			require.NoError(t, err)

			arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
			arg.DRWAConfig = mainConfig.DRWA
			arg.EpochConfig = *epochConfig

			activationErr := validateDRWAActivationConfig(arg)
			if profile.expectedError == "" {
				require.NoError(t, activationErr)
				return
			}
			require.EqualError(t, activationErr, profile.expectedError)
		})
	}
}

func TestCharacterization_DRWAEnabledRequiresEveryStaticCallerAddress(t *testing.T) {
	for _, missingDomain := range []string{
		"auth_admin",
		"policy_registry",
		"asset_manager",
		"identity_registry",
		"attestation",
		"recovery_admin",
	} {
		t.Run(missingDomain, func(t *testing.T) {
			arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
			arg.DRWAConfig = config.DRWAConfig{
				Enabled:            true,
				KeyManagementModel: drwaKeyManagementModelMultisig3of5Contract,
				AuthorizedCallers:  characterizationAuthorizedCallers(),
			}

			switch missingDomain {
			case "auth_admin":
				arg.DRWAConfig.AuthorizedCallers.AuthAdmin = ""
			case "policy_registry":
				arg.DRWAConfig.AuthorizedCallers.PolicyRegistry = ""
			case "asset_manager":
				arg.DRWAConfig.AuthorizedCallers.AssetManager = ""
			case "identity_registry":
				arg.DRWAConfig.AuthorizedCallers.IdentityRegistry = ""
			case "attestation":
				arg.DRWAConfig.AuthorizedCallers.Attestation = ""
			case "recovery_admin":
				arg.DRWAConfig.AuthorizedCallers.RecoveryAdmin = ""
			}

			err := setupDRWAAuthorizedCallers(arg)
			require.ErrorContains(t, err, "missing DRWA authorized caller for domain "+missingDomain)
		})
	}
}

func TestCharacterization_ModelLiteralAcceptsAddressesWithoutContractOrQuorumEvidence(t *testing.T) {
	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
	// This deliberately removes the only genesis-contract catalogue input.
	// setupDRWAAuthorizedCallers still accepts the records because the current
	// implementation checks only the exact model string and address syntax.
	arg.SmartContractParser = nil
	arg.DRWAConfig = config.DRWAConfig{
		Enabled:            true,
		KeyManagementModel: drwaKeyManagementModelMultisig3of5Contract,
		AuthorizedCallers:  characterizationAuthorizedCallers(),
	}

	require.NoError(t, setupDRWAAuthorizedCallers(arg))

	systemAccount, err := arg.Accounts.LoadAccount(chainCore.SystemAccountAddress)
	require.NoError(t, err)
	userAccount := systemAccount.(vmcommon.UserAccountHandler)
	configured := []struct {
		domain string
		value  string
	}{
		{"auth_admin", arg.DRWAConfig.AuthorizedCallers.AuthAdmin},
		{"policy_registry", arg.DRWAConfig.AuthorizedCallers.PolicyRegistry},
		{"asset_manager", arg.DRWAConfig.AuthorizedCallers.AssetManager},
		{"identity_registry", arg.DRWAConfig.AuthorizedCallers.IdentityRegistry},
		{"attestation", arg.DRWAConfig.AuthorizedCallers.Attestation},
		{"recovery_admin", arg.DRWAConfig.AuthorizedCallers.RecoveryAdmin},
	}
	for _, item := range configured {
		raw, _, retrieveErr := userAccount.AccountDataHandler().RetrieveValue([]byte("drwa:auth:" + item.domain))
		require.NoError(t, retrieveErr)

		record := struct {
			Version uint64 `json:"version"`
			Address []byte `json:"address"`
		}{}
		require.NoError(t, json.Unmarshal(raw, &record))
		expected, normalizeErr := hooks.NormalizeDRWAAuthorizedCallerAddress(item.value)
		require.NoError(t, normalizeErr)
		require.Equal(t, uint64(1), record.Version)
		require.Equal(t, expected, record.Address)
	}
}

func TestCharacterization_DelayedEnforcementDoesNotProvisionAnyCaller(t *testing.T) {
	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
	arg.DRWAConfig = config.DRWAConfig{Enabled: false}
	arg.EpochConfig.EnableEpochs.DRWAEnforcementEnableEpoch = 3

	// This is the ldevnet shape: delayed epoch activation does not require
	// caller provisioning at genesis. It is deliberately characterized here;
	// it must not be mistaken for a completed provisioning lifecycle.
	require.NoError(t, validateDRWAActivationConfig(arg))
	require.NoError(t, setupDRWAAuthorizedCallers(arg))

	systemAccount, err := arg.Accounts.LoadAccount(chainCore.SystemAccountAddress)
	require.NoError(t, err)
	userAccount := systemAccount.(vmcommon.UserAccountHandler)
	for _, domain := range []string{
		"auth_admin",
		"policy_registry",
		"asset_manager",
		"identity_registry",
		"attestation",
		"recovery_admin",
	} {
		raw, _, retrieveErr := userAccount.AccountDataHandler().RetrieveValue([]byte("drwa:auth:" + domain))
		require.ErrorIs(t, retrieveErr, state.ErrNilTrie)
		require.Empty(t, raw)
	}
}

func TestCharacterization_GenesisEpochEnforcementRejectsDisabledProvisioning(t *testing.T) {
	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
	arg.DRWAConfig = config.DRWAConfig{Enabled: false}
	arg.EpochConfig.EnableEpochs.DRWAEnforcementEnableEpoch = 0

	require.EqualError(t, validateDRWAActivationConfig(arg),
		"DRWA enforcement is enabled at genesis but DRWA caller provisioning is disabled")
}

func TestCharacterization_MockTwoShardGenesisSucceedsWithLdevnetDRWAFlags(t *testing.T) {
	arg := createMockArgument(t, "testdata/genesisTest1.json", &mock.InitialNodesHandlerStub{}, big.NewInt(22000))
	arg.Core.(*mock.CoreComponentsMock).Chain = "L"
	arg.DRWAConfig = config.DRWAConfig{Enabled: false}
	arg.EpochConfig.EnableEpochs.DRWAEnforcementEnableEpoch = 3

	creator, err := NewGenesisBlockCreator(arg)
	require.NoError(t, err)
	blocks, err := creator.CreateGenesisBlocks()
	require.NoError(t, err)
	require.Len(t, blocks, 3)
}

func characterizationAuthorizedCallers() config.DRWAAuthorizedCallersConfig {
	return config.DRWAAuthorizedCallersConfig{
		AuthAdmin:        "0x1111111111111111111111111111111111111111111111111111111111111111",
		PolicyRegistry:   "0x2222222222222222222222222222222222222222222222222222222222222222",
		AssetManager:     "0x3333333333333333333333333333333333333333333333333333333333333333",
		IdentityRegistry: "0x4444444444444444444444444444444444444444444444444444444444444444",
		Attestation:      "0x5555555555555555555555555555555555555555555555555555555555555555",
		RecoveryAdmin:    "0x6666666666666666666666666666666666666666666666666666666666666666",
	}
}
