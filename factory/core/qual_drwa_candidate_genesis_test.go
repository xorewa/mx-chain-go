package core

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	nativeCore "github.com/multiversx/mx-chain-core-go/core"
	hashFactory "github.com/multiversx/mx-chain-core-go/hashing/factory"
	marshalFactory "github.com/multiversx/mx-chain-core-go/marshal/factory"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/chainparametersnotifier"
	converterFactory "github.com/multiversx/mx-chain-go/common/factory"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/epochStart/notifier"
	"github.com/multiversx/mx-chain-go/genesis"
	"github.com/multiversx/mx-chain-go/genesis/data"
	"github.com/multiversx/mx-chain-go/genesis/parsing"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/stretchr/testify/require"
)

// Native startup-input adoption only (T09 M1/M7/M8 and genesis model01).
// No node/core Create, genesis execution, WASM call or deployment occurs.
func qualDRWACandidateGenesisPath(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "evidence", "sp1_t09_configuration_candidate_03", name))
	require.NoError(t, err)
	return p
}

func qualDRWACandidateGenesisArgs(t *testing.T) genesis.AccountsParserArgs {
	t.Helper()
	cfg, err := common.LoadMainConfig(qualDRWACandidateGenesisPath(t, "config.toml"))
	require.NoError(t, err)
	economics, err := common.LoadEconomicsConfig(qualDRWACandidateGenesisPath(t, "economics.toml"))
	require.NoError(t, err)
	total, ok := new(big.Int).SetString(economics.GlobalSettings.GenesisTotalSupply, 10)
	require.True(t, ok)
	require.Equal(t, "20000000000000000000000000", total.String())
	converter, err := converterFactory.NewPubkeyConverter(cfg.AddressPubkeyConverter)
	require.NoError(t, err)
	hasher, err := hashFactory.NewHasher(cfg.Hasher.Type)
	require.NoError(t, err)
	marshaller, err := marshalFactory.NewMarshalizer(cfg.Marshalizer.Type)
	require.NoError(t, err)
	return genesis.AccountsParserArgs{GenesisFilePath: qualDRWACandidateGenesisPath(t, "genesis.json"),
		EntireSupply: total, MinterAddress: economics.GlobalSettings.GenesisMintingSenderAddress,
		PubkeyConverter: converter, KeyGenerator: signing.NewKeyGenerator(ed25519.NewEd25519()),
		Hasher: hasher, Marshalizer: marshaller}
}

func qualDRWACandidateGenesisJSON(t *testing.T, value interface{}) string {
	t.Helper()
	body, err := json.Marshal(value)
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "genesis.json")
	require.NoError(t, os.WriteFile(p, body, 0600))
	return p
}

func TestQualDRWACandidateGenesisNativeAccountsAndTopology(t *testing.T) {
	args := qualDRWACandidateGenesisArgs(t)
	parser, err := parsing.NewAccountsParser(args)
	require.NoError(t, err)
	accounts := parser.InitialAccounts()
	require.Len(t, accounts, 36)
	total := new(big.Int)
	for _, a := range accounts {
		require.Len(t, a.AddressBytes(), 32)
		require.False(t, nativeCore.IsSmartContractAddress(a.AddressBytes()))
		require.NoError(t, args.KeyGenerator.CheckPublicKeyValid(a.AddressBytes()))
		parts := new(big.Int).Add(a.GetBalanceValue(), a.GetStakingValue())
		parts.Add(parts, a.GetDelegationHandler().GetValue())
		require.Equal(t, a.GetSupply(), parts)
		total.Add(total, a.GetSupply())
	}
	require.Equal(t, args.EntireSupply, total)
	cfg, err := common.LoadMainConfig(qualDRWACandidateGenesisPath(t, "config.toml"))
	require.NoError(t, err)
	validator, err := converterFactory.NewPubkeyConverter(cfg.ValidatorPubkeyConverter)
	require.NoError(t, err)
	holder, err := sharding.NewChainParametersHolder(sharding.ArgsChainParametersHolder{
		ChainParameters:         cfg.GeneralSettings.ChainParametersByEpoch,
		EpochStartEventNotifier: notifier.NewEpochStartSubscriptionHandler(),
		ChainParametersNotifier: chainparametersnotifier.NewChainParametersNotifier()})
	require.NoError(t, err)
	var nodes config.NodesConfig
	require.NoError(t, nativeCore.LoadJsonFile(&nodes, qualDRWACandidateGenesisPath(t, "nodesSetup.json")))
	setup, err := sharding.NewNodesSetup(nodes, holder, args.PubkeyConverter, validator, cfg.GeneralSettings.GenesisMaxNumberOfShards)
	require.NoError(t, err)
	require.Equal(t, uint32(3), setup.NumberOfShards())
	require.Len(t, setup.InitialNodes, 36)
	coordinator, err := sharding.NewMultiShardCoordinator(setup.NumberOfShards(), 0)
	require.NoError(t, err)
	split, err := parser.InitialAccountsSplitOnAddressesShards(coordinator)
	require.NoError(t, err)
	seen := make(map[string]bool)
	for shard, list := range split {
		for _, account := range list {
			require.Equal(t, shard, coordinator.ComputeId(account.AddressBytes()))
			require.False(t, seen[string(account.AddressBytes())])
			seen[string(account.AddressBytes())] = true
		}
	}
	require.Len(t, seen, 36)
}

func TestQualDRWACandidateGenesisNativeAccountDenials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]*data.InitialAccount) []*data.InitialAccount
		want   error
	}{
		{"conservation", func(a []*data.InitialAccount) []*data.InitialAccount {
			a[0].Balance.Add(a[0].Balance, big.NewInt(1))
			return a
		}, genesis.ErrSupplyMismatch},
		{"negative_balance", func(a []*data.InitialAccount) []*data.InitialAccount { a[0].Balance.SetInt64(-1); return a }, genesis.ErrInvalidBalance},
		{"negative_stake", func(a []*data.InitialAccount) []*data.InitialAccount { a[0].StakingValue.SetInt64(-1); return a }, genesis.ErrInvalidStakingBalance},
		{"negative_delegation", func(a []*data.InitialAccount) []*data.InitialAccount {
			a[0].Delegation.Address = a[0].Address // Isolate amount check from native address check.
			a[0].Delegation.Value.SetInt64(-1)
			return a
		}, genesis.ErrInvalidDelegationValue},
		{"zero_supply", func(a []*data.InitialAccount) []*data.InitialAccount { a[0].Supply.SetInt64(0); return a }, genesis.ErrInvalidSupply},
		{"invalid_address", func(a []*data.InitialAccount) []*data.InitialAccount { a[0].Address = "wrong"; return a }, genesis.ErrInvalidAddress},
		{"duplicate", func(a []*data.InitialAccount) []*data.InitialAccount { return append(a, a[0]) }, genesis.ErrDuplicateAddress},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := qualDRWACandidateGenesisArgs(t)
			var accounts []*data.InitialAccount
			require.NoError(t, nativeCore.LoadJsonFile(&accounts, args.GenesisFilePath))
			args.GenesisFilePath = qualDRWACandidateGenesisJSON(t, tc.mutate(accounts))
			_, err := parsing.NewAccountsParser(args)
			require.ErrorIs(t, err, tc.want)
		})
	}
	t.Run("entire_supply", func(t *testing.T) {
		args := qualDRWACandidateGenesisArgs(t)
		args.EntireSupply.Add(args.EntireSupply, big.NewInt(1))
		_, err := parsing.NewAccountsParser(args)
		require.ErrorIs(t, err, genesis.ErrEntireSupplyMismatch)
	})
	t.Run("malformed_amount", func(t *testing.T) {
		args := qualDRWACandidateGenesisArgs(t)
		var accounts []map[string]interface{}
		require.NoError(t, nativeCore.LoadJsonFile(&accounts, args.GenesisFilePath))
		accounts[0]["supply"] = "wrong"
		args.GenesisFilePath = qualDRWACandidateGenesisJSON(t, accounts)
		_, err := parsing.NewAccountsParser(args)
		require.ErrorIs(t, err, genesis.ErrInvalidSupplyString)
	})
	t.Run("native_key_width", func(t *testing.T) {
		args := qualDRWACandidateGenesisArgs(t)
		converter, err := converterFactory.NewPubkeyConverter(config.PubkeyConfig{Length: 30, Type: "bech32", Hrp: "erd"})
		require.NoError(t, err)
		// Synthetic hostile converter/key mismatch, not a supported profile.
		args.PubkeyConverter = converter
		args.MinterAddress, err = converter.Encode(bytes.Repeat([]byte{1}, 30))
		require.NoError(t, err)
		var accounts []*data.InitialAccount
		require.NoError(t, nativeCore.LoadJsonFile(&accounts, args.GenesisFilePath))
		accounts[0].Address = args.MinterAddress
		args.GenesisFilePath = qualDRWACandidateGenesisJSON(t, accounts[:1])
		_, err = parsing.NewAccountsParser(args)
		require.ErrorIs(t, err, genesis.ErrInvalidPubKey)
	})
}

func TestQualDRWACandidateGenesisKeyCheckIsNotSignature(t *testing.T) {
	args := qualDRWACandidateGenesisArgs(t)
	var accounts []*data.InitialAccount
	require.NoError(t, nativeCore.LoadJsonFile(&accounts, args.GenesisFilePath))
	point := make([]byte, 32)
	point[0] = 1 // Independent small-order identity encoding, not a usable signer.
	address, err := args.PubkeyConverter.Encode(point)
	require.NoError(t, err)
	accounts[0].Address = address
	args.GenesisFilePath = qualDRWACandidateGenesisJSON(t, accounts)
	_, err = parsing.NewAccountsParser(args)
	require.NoError(t, err, "native parser checks width; this is not signing authority")
	key, err := args.KeyGenerator.PublicKeyFromByteArray(point)
	require.NoError(t, err)
	require.ErrorIs(t, (&singlesig.Ed25519Signer{}).Verify(key, nil, nil), crypto.ErrInvalidPublicKey)
}

func TestQualDRWACandidateGenesisNativeContractFiles(t *testing.T) {
	args := qualDRWACandidateGenesisArgs(t)
	parser, err := parsing.NewSmartContractsParser(qualDRWACandidateGenesisPath(t, "genesisSmartContracts.json"), args.PubkeyConverter, args.KeyGenerator)
	require.NoError(t, err)
	require.Len(t, parser.InitialSmartContracts(), 2)
	for _, name := range []string{"delegation.wasm", "dns.wasm"} {
		body, err := os.ReadFile(qualDRWACandidateGenesisPath(t, filepath.Join("genesisContracts", name)))
		require.NoError(t, err)
		original, err := os.ReadFile(filepath.Join("..", "..", "cmd", "node", "config", "genesisContracts", name))
		require.NoError(t, err)
		require.Equal(t, original, body)
		require.Equal(t, []byte{0, 97, 115, 109, 1, 0, 0, 0}, body[:8])
	}
	for _, tc := range []struct {
		name  string
		field string
		value interface{}
		want  error
	}{
		{"empty_owner", "owner", "", genesis.ErrEmptyOwnerAddress},
		{"invalid_owner", "owner", "wrong", genesis.ErrInvalidOwnerAddress},
		{"empty_vm", "vm-type", "", genesis.ErrEmptyVmType},
		{"malformed_vm", "vm-type", "wrong", genesis.ErrInvalidVmType},
		{"missing_file", "filename", filepath.Join(t.TempDir(), "absent.wasm"), os.ErrNotExist},
		{"directory", "filename", t.TempDir(), genesis.ErrFilenameIsDirectory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var contracts []map[string]interface{}
			require.NoError(t, nativeCore.LoadJsonFile(&contracts, qualDRWACandidateGenesisPath(t, "genesisSmartContracts.json")))
			contracts[0][tc.field] = tc.value
			_, err := parsing.NewSmartContractsParser(qualDRWACandidateGenesisJSON(t, contracts), args.PubkeyConverter, args.KeyGenerator)
			require.ErrorIs(t, err, tc.want)
		})
	}
	t.Run("duplicate_dns", func(t *testing.T) {
		var contracts []map[string]interface{}
		require.NoError(t, nativeCore.LoadJsonFile(&contracts, qualDRWACandidateGenesisPath(t, "genesisSmartContracts.json")))
		contracts = append(contracts, contracts[1])
		_, err := parsing.NewSmartContractsParser(qualDRWACandidateGenesisJSON(t, contracts), args.PubkeyConverter, args.KeyGenerator)
		require.ErrorIs(t, err, genesis.ErrTooManyDNSContracts)
	})
}
