package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"

	nativeCore "github.com/multiversx/mx-chain-core-go/core"
	hashFactory "github.com/multiversx/mx-chain-core-go/hashing/factory"
	marshalFactory "github.com/multiversx/mx-chain-core-go/marshal/factory"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	converterFactory "github.com/multiversx/mx-chain-go/common/factory"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/config"
	coreFactory "github.com/multiversx/mx-chain-go/factory/core"
	"github.com/multiversx/mx-chain-go/genesis"
	"github.com/multiversx/mx-chain-go/genesis/parsing"
	"github.com/stretchr/testify/require"
)

// N01/M1/M3/M7: the prepared PUBLIC candidate is the input, rather than a
// separately edited stock template. Values/geometry are experimental under R7.
// Only public filenames relocate into test-owned storage. No key is copied.
func qualDRWADevelopmentCandidateInputs(t *testing.T) string {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "evidence", "sp1_t09_configuration_candidate_03"))
	require.NoError(t, err)
	var inventory struct {
		Files []struct{ Path, SHA256 string }
	}
	body, err := os.ReadFile(filepath.Join(source, "CANDIDATE.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(body, &inventory))
	root := t.TempDir()
	for _, item := range inventory.Files {
		require.NotEmpty(t, item.Path)
		require.False(t, filepath.IsAbs(item.Path))
		raw, err := os.ReadFile(filepath.Join(source, item.Path))
		require.NoError(t, err)
		require.Equal(t, item.SHA256, fmt.Sprintf("%x", sha256.Sum256(raw)))
		destination := filepath.Join(root, item.Path)
		require.NoError(t, os.MkdirAll(filepath.Dir(destination), 0700))
		require.NoError(t, os.WriteFile(destination, raw, 0600))
	}
	// The prepared generator's absolute public WASM locators are relocated only
	// after their exact byte identity check; the referenced code remains unchanged.
	path := filepath.Join(root, "genesisSmartContracts.json")
	var contracts []map[string]interface{}
	require.NoError(t, nativeCore.LoadJsonFile(&contracts, path))
	for _, contract := range contracts {
		filename, ok := contract["filename"].(string)
		require.True(t, ok)
		require.Equal(t, filepath.Join(source, "genesisContracts"), filepath.Dir(filename))
		contract["filename"] = filepath.Join(root, "genesisContracts", filepath.Base(filename))
	}
	raw, err := json.Marshal(contracts)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0600))
	return root
}

// A composed offline consumed-input check. Native runtime startup, key custody,
// authentic genesis execution and first-enforcement integration remain separate.
// In particular this helper never calls NodeRunner.Start or creates a listener.
func qualDRWADevelopmentAdmissionInputs(t *testing.T, root string) (*config.Configs, *coreFactory.DRWAConfigurationCandidate, error) {
	t.Helper()
	cfgs, err := qualDRWANativeStartup(t, root)
	if err != nil {
		return nil, nil, err
	}
	if err = checkHardwareRequirements(cfgs.GeneralConfig.HardwareRequirements); err != nil {
		return cfgs, nil, err
	}
	converter, err := converterFactory.NewPubkeyConverter(cfgs.GeneralConfig.AddressPubkeyConverter)
	if err != nil {
		return cfgs, nil, err
	}
	hasher, err := hashFactory.NewHasher(cfgs.GeneralConfig.Hasher.Type)
	if err != nil {
		return cfgs, nil, err
	}
	marshaller, err := marshalFactory.NewMarshalizer(cfgs.GeneralConfig.Marshalizer.Type)
	if err != nil {
		return cfgs, nil, err
	}
	supply, present := new(big.Int).SetString(cfgs.EconomicsConfig.GlobalSettings.GenesisTotalSupply, 10)
	require.True(t, present)
	keys := signing.NewKeyGenerator(ed25519.NewEd25519())
	_, err = parsing.NewAccountsParser(genesis.AccountsParserArgs{
		GenesisFilePath: cfgs.ConfigurationPathsHolder.Genesis,
		EntireSupply:    supply, MinterAddress: cfgs.EconomicsConfig.GlobalSettings.GenesisMintingSenderAddress,
		PubkeyConverter: converter, KeyGenerator: keys, Hasher: hasher, Marshalizer: marshaller,
	})
	if err != nil {
		return cfgs, nil, err
	}
	_, err = parsing.NewSmartContractsParser(cfgs.ConfigurationPathsHolder.SmartContracts, converter, keys)
	if err != nil {
		return cfgs, nil, err
	}
	epochs := forking.NewGenericEpochNotifier()
	t.Cleanup(epochs.UnRegisterAll)
	gas, err := forking.NewGasScheduleNotifier(forking.ArgsNewGasScheduleNotifier{
		GasScheduleConfig: cfgs.EpochConfig.GasSchedule, ConfigDir: cfgs.ConfigurationPathsHolder.GasScheduleDirectoryName,
		EpochNotifier: epochs, WasmVMChangeLocker: &sync.RWMutex{},
	})
	if err != nil {
		return cfgs, nil, err
	}
	t.Cleanup(gas.UnRegisterAll)
	candidate, err := qualDRWANativeStartupCandidate(t, root, cfgs)
	return cfgs, candidate, err
}

func TestQualDRWADevelopmentAdmissionInputs(t *testing.T) {
	root := qualDRWADevelopmentCandidateInputs(t)
	cfgs, candidate, err := qualDRWADevelopmentAdmissionInputs(t, root)
	require.NoError(t, err)
	require.NotNil(t, cfgs)
	require.NoError(t, candidate.CheckEnforcedBlock(3, 440)) // experimental candidate coordinates
	require.Error(t, candidate.CheckEnforcedBlock(3, 439))
	require.Error(t, candidate.CheckEnforcedBlock(2, 440))
	epochs, rounds := candidate.ActivationInventory()
	require.Equal(t, uint32(1), epochs["SCProcessorV2EnableEpoch"])
	require.Equal(t, uint32(2), epochs["SupernovaEnableEpoch"])
	require.Equal(t, uint64(440), rounds["SupernovaEnableRound"])
	t.Log("N01 composed CLI/preferences/effective config/hardware/genesis-file/gas/admission inputs; runtime and competent acceptance remain unexecuted")
}

func TestQualDRWADevelopmentAdmissionMissingTransitiveInputs(t *testing.T) {
	for _, missing := range []string{"genesis.json", "genesisSmartContracts.json", "genesisContracts/dns.wasm", "genesisContracts/delegation.wasm", "gasSchedules/gasScheduleV9.toml"} {
		t.Run(missing, func(t *testing.T) {
			root := qualDRWADevelopmentCandidateInputs(t)
			require.NoError(t, os.Remove(filepath.Join(root, missing)))
			_, candidate, err := qualDRWADevelopmentAdmissionInputs(t, root)
			require.ErrorIs(t, err, os.ErrNotExist)
			require.Nil(t, candidate, "late consumed-input failure must precede the dependent candidate")
		})
	}
}
