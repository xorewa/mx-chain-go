package chainSimulator

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	apiBlock "github.com/multiversx/mx-chain-core-go/data/api"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/errors"
	chainSimulatorCommon "github.com/multiversx/mx-chain-go/integrationTests/chainSimulator"
	"github.com/multiversx/mx-chain-go/integrationTests/chainSimulator/staking"
	"github.com/multiversx/mx-chain-go/node/chainSimulator/components/api"
	"github.com/multiversx/mx-chain-go/node/chainSimulator/configs"
	"github.com/multiversx/mx-chain-go/node/chainSimulator/dtos"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
)

const (
	defaultPathToInitialConfig            = "../../cmd/node/config/"
	defaultRoundDurationInMillis          = uint64(6000)
	defaultSupernovaRoundDurationInMillis = uint64(600)
	defaultRoundsPerEpochValue            = uint64(20)
	defaultSupernovaRoundsPerEpochValue   = uint64(40)
	defaultNumOfShards                    = uint32(3)
	defaultMinNodesPerShard               = uint32(1)
	defaultMetaChainMinNodes              = uint32(1)
)

var (
	defaultRoundsPerEpoch = core.OptionalUint64{
		HasValue: true,
		Value:    defaultRoundsPerEpochValue,
	}
	defaultSupernovaRoundsPerEpoch = core.OptionalUint64{
		HasValue: true,
		Value:    defaultSupernovaRoundsPerEpochValue,
	}
)

func TestChainSimulatorCheckSupernova(t *testing.T) {
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 defaultRoundsPerEpoch,
		SupernovaRoundsPerEpoch:        defaultSupernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               3,
		MetaChainMinNodes:              3,
		AlterConfigsFunction: func(cfg *config.Configs) {

		},
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	err = chainSimulator.GenerateBlocksUntilEpochIsReached(2)
	require.Nil(t, err)

	err = chainSimulator.GenerateBlocks(2)
	require.Nil(t, err)

	err = chainSimulator.GenerateBlocks(1) // supernova round activation
	require.Nil(t, err)

	err = chainSimulator.GenerateBlocks(1)
	require.Nil(t, err)

	err = chainSimulator.GenerateBlocks(50)
	require.Nil(t, err)

	time.Sleep(time.Second)

	chainSimulator.Close()
}

func TestNewChainSimulator(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	alterConfigsFunc := func(cfg *config.Configs) {
		cfg.EpochConfig.EnableEpochs.SupernovaEnableEpoch = 999999
		cfg.RoundConfig.RoundActivations = map[string]config.ActivationRoundByName{
			"DisableAsyncCallV1": {
				Round: "9999999",
			},
			"SupernovaEnableRound": {
				Round: "9999999",
			},
		}
	}

	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 defaultRoundsPerEpoch,
		SupernovaRoundsPerEpoch:        defaultSupernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               3,
		MetaChainMinNodes:              3,
		AlterConfigsFunction:           alterConfigsFunc,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	for i := 0; i < 8; i++ {
		err = chainSimulator.ForceChangeOfEpoch()
		require.Nil(t, err)
	}

	err = chainSimulator.GenerateBlocks(50)
	require.Nil(t, err)

	time.Sleep(time.Second)

	chainSimulator.Close()
}

func TestChainSimulator_GenerateBlocksShouldWork(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		BypassBlockSignatureCheck:      true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 defaultRoundsPerEpoch,
		SupernovaRoundsPerEpoch:        defaultSupernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               defaultMinNodesPerShard,
		MetaChainMinNodes:              defaultMetaChainMinNodes,
		InitialRound:                   20000,
		InitialEpoch:                   100,
		InitialNonce:                   100,
		AlterConfigsFunction: func(cfg *config.Configs) {
			// we need to enable this as this test skips a lot of epoch activations events, and it will fail otherwise
			// because the owner of a BLS key coming from genesis is not set
			// (the owner is not set at genesis anymore because we do not enable the staking v2 in that phase)
			cfg.EpochConfig.EnableEpochs.StakingV2EnableEpoch = 0
			cfg.EpochConfig.EnableEpochs.SupernovaEnableEpoch = 99999
		},
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)
	defer chainSimulator.Close()

	time.Sleep(time.Second)

	err = chainSimulator.GenerateBlocks(50)
	require.Nil(t, err)

	heartBeats, err := chainSimulator.GetNodeHandler(0).GetFacadeHandler().GetHeartbeats()
	require.Nil(t, err)
	require.Equal(t, 4, len(heartBeats))

}

func TestChainSimulator_VerifyBlockTimestampSupernova(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	supernovaActivationRound := uint64(220)

	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch: core.OptionalUint64{
			Value:    20,
			HasValue: true,
		},
		SupernovaRoundsPerEpoch: defaultSupernovaRoundsPerEpoch,
		ApiInterface:            api.NewNoApiInterface(),
		MinNodesPerShard:        defaultMinNodesPerShard,
		MetaChainMinNodes:       defaultMetaChainMinNodes,
		InitialRound:            200,
		InitialEpoch:            100,
		InitialNonce:            100,
		AlterConfigsFunction: func(cfg *config.Configs) {
			// we need to enable this as this test skips a lot of epoch activations events, and it will fail otherwise
			// because the owner of a BLS key coming from genesis is not set
			// (the owner is not set at genesis anymore because we do not enable the staking v2 in that phase)
			cfg.EpochConfig.EnableEpochs.StakingV2EnableEpoch = 0
			cfg.EpochConfig.EnableEpochs.SupernovaEnableEpoch = 100
			cfg.RoundConfig.RoundActivations[string(common.SupernovaRoundFlag)] = config.ActivationRoundByName{
				Round: fmt.Sprintf("%d", supernovaActivationRound),
			}
		},
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)
	defer chainSimulator.Close()

	time.Sleep(time.Second)

	err = chainSimulator.GenerateBlocks(30)
	require.Nil(t, err)

	blockBeforeSupernovaRound, err := chainSimulator.GetNodeHandler(0).GetFacadeHandler().GetBlockByRound(supernovaActivationRound-1, apiBlock.BlockQueryOptions{})
	require.Nil(t, err)

	blockS, err := chainSimulator.GetNodeHandler(0).GetFacadeHandler().GetBlockByRound(supernovaActivationRound, apiBlock.BlockQueryOptions{})
	require.Nil(t, err)

	blockAfterSupernovaRound, err := chainSimulator.GetNodeHandler(0).GetFacadeHandler().GetBlockByRound(supernovaActivationRound+1, apiBlock.BlockQueryOptions{})
	require.Nil(t, err)

	diff := blockS.TimestampMs - blockBeforeSupernovaRound.TimestampMs
	require.Equal(t, int64(6000), diff)
	diff = blockAfterSupernovaRound.TimestampMs - blockS.TimestampMs
	require.Equal(t, defaultSupernovaRoundDurationInMillis, uint64(diff))
}

func TestChainSimulator_GenerateBlocksAndEpochChangeShouldWork(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 defaultRoundsPerEpoch,
		SupernovaRoundsPerEpoch:        defaultSupernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               100,
		MetaChainMinNodes:              100,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	facade, err := NewChainSimulatorFacade(chainSimulator)
	require.Nil(t, err)

	genesisBalances := make(map[string]*big.Int)
	for _, stakeWallet := range chainSimulator.initialWalletKeys.StakeWallets {
		initialAccount, errGet := facade.GetExistingAccountFromBech32AddressString(stakeWallet.Address.Bech32)
		require.Nil(t, errGet)

		genesisBalances[stakeWallet.Address.Bech32] = initialAccount.GetBalance()
	}

	time.Sleep(time.Second)

	err = chainSimulator.GenerateBlocks(80)
	require.Nil(t, err)

	numAccountsWithIncreasedBalances := 0
	for _, stakeWallet := range chainSimulator.initialWalletKeys.StakeWallets {
		account, errGet := facade.GetExistingAccountFromBech32AddressString(stakeWallet.Address.Bech32)
		require.Nil(t, errGet)

		if account.GetBalance().Cmp(genesisBalances[stakeWallet.Address.Bech32]) > 0 {
			numAccountsWithIncreasedBalances++
		}
	}

	assert.True(t, numAccountsWithIncreasedBalances > 0)
}

func TestSimulator_TriggerChangeOfEpoch(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    15000,
	}
	supernovaRoundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    150000,
	}
	alterConfigsFunc := func(cfg *config.Configs) {
		cfg.EpochConfig.EnableEpochs.SupernovaEnableEpoch = 999999
		cfg.RoundConfig.RoundActivations = map[string]config.ActivationRoundByName{
			"DisableAsyncCallV1": {
				Round: "9999999",
			},
			"SupernovaEnableRound": {
				Round: "9999999",
			},
		}
	}

	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 roundsPerEpoch,
		SupernovaRoundsPerEpoch:        supernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               100,
		MetaChainMinNodes:              100,
		AlterConfigsFunction:           alterConfigsFunc,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	err = chainSimulator.ForceChangeOfEpoch()
	require.Nil(t, err)

	err = chainSimulator.ForceChangeOfEpoch()
	require.Nil(t, err)

	err = chainSimulator.ForceChangeOfEpoch()
	require.Nil(t, err)

	err = chainSimulator.ForceChangeOfEpoch()
	require.Nil(t, err)

	metaNode := chainSimulator.GetNodeHandler(core.MetachainShardId)
	currentEpoch := metaNode.GetProcessComponents().EpochStartTrigger().Epoch()
	require.Equal(t, uint32(4), currentEpoch)
}

func TestChainSimulator_ChangeRoundsPerEpoch(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    20,
	}
	supernovaRoundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    30,
	}
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 roundsPerEpoch,
		SupernovaRoundsPerEpoch:        supernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               defaultMinNodesPerShard,
		MetaChainMinNodes:              defaultMetaChainMinNodes,
		AlterConfigsFunction: func(cfg *config.Configs) {
			cfg.GeneralConfig.GeneralSettings.ChainParametersByEpoch[0].EnableEpoch = 0
			cfg.GeneralConfig.GeneralSettings.ChainParametersByEpoch[0].RoundsPerEpoch = 10
			cfg.GeneralConfig.GeneralSettings.ChainParametersByEpoch[0].MinRoundsBetweenEpochs = 10

			cfg.EpochConfig.EnableEpochs.AndromedaEnableEpoch = 3
			cfg.GeneralConfig.GeneralSettings.ChainParametersByEpoch[1].EnableEpoch = 3
			cfg.GeneralConfig.GeneralSettings.ChainParametersByEpoch[1].RoundsPerEpoch = 20
			cfg.GeneralConfig.GeneralSettings.ChainParametersByEpoch[1].MinRoundsBetweenEpochs = 10

			cfg.EpochConfig.EnableEpochs.SupernovaEnableEpoch = 5
			cfg.GeneralConfig.GeneralSettings.ChainParametersByEpoch[2].EnableEpoch = 5
			cfg.GeneralConfig.GeneralSettings.ChainParametersByEpoch[2].RoundsPerEpoch = 30
			cfg.GeneralConfig.GeneralSettings.ChainParametersByEpoch[2].MinRoundsBetweenEpochs = 10
		},
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	err = chainSimulator.GenerateBlocks(140)
	require.Nil(t, err)

	expectedEpoch := uint32(7)

	metaNode := chainSimulator.GetNodeHandler(core.MetachainShardId)
	currentEpoch := metaNode.GetProcessComponents().EpochStartTrigger().Epoch()
	require.Equal(t, expectedEpoch, currentEpoch)

	defer chainSimulator.Close()

}

func TestChainSimulator_SetState(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 defaultRoundsPerEpoch,
		SupernovaRoundsPerEpoch:        defaultSupernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               defaultMinNodesPerShard,
		MetaChainMinNodes:              defaultMetaChainMinNodes,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	chainSimulatorCommon.CheckSetState(t, chainSimulator, chainSimulator.GetNodeHandler(0))
}

func TestChainSimulator_SetStateMultiple_SystemAccountReplicatesAcrossShards(t *testing.T) {
	chainSimulator := newDRWASystemAccountChainSimulator(t)
	defer chainSimulator.Close()

	const systemAccount = "erd1lllllllllllllllllllllllllllllllllllllllllllllllllllsckry7t"
	const authKey = "drwa:auth:identity_registry"
	const authValue = "0000000000000000050020ff05831a43c822781252791020a395abdbcc54ed60"

	addressConverter := chainSimulator.GetNodeHandler(core.MetachainShardId).GetCoreComponents().AddressPubKeyConverter()
	systemAccountBytes, err := addressConverter.Decode(systemAccount)
	require.NoError(t, err)
	require.Equal(t, core.SystemAccountAddress, systemAccountBytes)

	err = chainSimulator.SetStateMultiple([]*dtos.AddressState{
		{
			Address: systemAccount,
			Pairs: map[string]string{
				hex.EncodeToString([]byte(authKey)): authValue,
			},
		},
	})
	require.NoError(t, err)

	requireSystemAccountValueOnAllShards(t, chainSimulator, authKey, authValue)
}

func TestChainSimulator_SetKeyValueForAddress_SystemAccountReplicatesAcrossShards(t *testing.T) {
	chainSimulator := newDRWASystemAccountChainSimulator(t)
	defer chainSimulator.Close()

	const systemAccount = "erd1lllllllllllllllllllllllllllllllllllllllllllllllllllsckry7t"
	const authKey = "drwa:auth:identity_registry"
	const authValue = "0000000000000000050020ff05831a43c822781252791020a395abdbcc54ed60"

	addressConverter := chainSimulator.GetNodeHandler(core.MetachainShardId).GetCoreComponents().AddressPubKeyConverter()
	systemAccountBytes, err := addressConverter.Decode(systemAccount)
	require.NoError(t, err)
	require.Equal(t, core.SystemAccountAddress, systemAccountBytes)

	err = chainSimulator.SetKeyValueForAddress(systemAccount, map[string]string{
		hex.EncodeToString([]byte(authKey)): authValue,
	})
	require.NoError(t, err)

	requireSystemAccountValueOnAllShards(t, chainSimulator, authKey, authValue)
}

func TestChainSimulator_setKeyValueSystemAccount_WithSimulatorMutexHeld_ReplicatesAcrossShards(t *testing.T) {
	chainSimulator := newDRWASystemAccountChainSimulator(t)
	defer chainSimulator.Close()

	const authKey = "drwa:auth:identity_registry"
	const authValue = "0000000000000000050020ff05831a43c822781252791020a395abdbcc54ed60"

	chainSimulator.mutex.Lock()
	err := chainSimulator.setKeyValueSystemAccount(map[string]string{
		hex.EncodeToString([]byte(authKey)): authValue,
	})
	chainSimulator.mutex.Unlock()
	require.NoError(t, err)

	requireSystemAccountValueOnAllShards(t, chainSimulator, authKey, authValue)
}

func TestChainSimulator_SystemAccountDirectSaveAccountPersistsAcrossCommit(t *testing.T) {
	chainSimulator := newDRWASystemAccountChainSimulator(t)
	defer chainSimulator.Close()

	const authKey = "drwa:auth:identity_registry"
	const authValueHex = "0000000000000000050020ff05831a43c822781252791020a395abdbcc54ed60"

	authValue, err := hex.DecodeString(authValueHex)
	require.NoError(t, err)

	nodeHandler := chainSimulator.GetNodeHandler(0)
	accountsAdapter := nodeHandler.GetStateComponents().AccountsAdapter()

	account, err := accountsAdapter.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	userAccount, ok := account.(state.UserAccountHandler)
	require.True(t, ok)

	require.NoError(t, userAccount.SaveKeyValue([]byte(authKey), authValue))
	require.NoError(t, accountsAdapter.SaveAccount(userAccount))

	_, err = accountsAdapter.Commit()
	require.NoError(t, err)

	loadedAccountAfterCommit, err := accountsAdapter.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	loadedUserAccountAfterCommit, ok := loadedAccountAfterCommit.(state.UserAccountHandler)
	require.True(t, ok)

	loadedValueAfterCommit, _, err := loadedUserAccountAfterCommit.RetrieveValue([]byte(authKey))
	require.NoError(t, err)
	require.Equal(t, authValue, loadedValueAfterCommit)
}

func TestChainSimulator_SystemAccountSequentialNodeWritesDoNotEraseEarlierShard(t *testing.T) {
	chainSimulator := newDRWASystemAccountChainSimulator(t)
	defer chainSimulator.Close()

	const authKey = "drwa:auth:identity_registry"
	const authValueHex = "0000000000000000050020ff05831a43c822781252791020a395abdbcc54ed60"

	authValue, err := hex.DecodeString(authValueHex)
	require.NoError(t, err)

	writeOnNode := func(shardID uint32) {
		nodeHandler := chainSimulator.GetNodeHandler(shardID)
		accountsAdapter := nodeHandler.GetStateComponents().AccountsAdapter()
		account, loadErr := accountsAdapter.LoadAccount(core.SystemAccountAddress)
		require.NoError(t, loadErr)
		userAccount, ok := account.(state.UserAccountHandler)
		require.True(t, ok)
		require.NoError(t, userAccount.SaveKeyValue([]byte(authKey), authValue))
		require.NoError(t, accountsAdapter.SaveAccount(userAccount))
		_, commitErr := accountsAdapter.Commit()
		require.NoError(t, commitErr)
	}

	for _, shardID := range []uint32{0, 1, 2, core.MetachainShardId} {
		writeOnNode(shardID)

		nodeHandler := chainSimulator.GetNodeHandler(0)
		account, loadErr := nodeHandler.GetStateComponents().AccountsAdapter().GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, loadErr)
		userAccount, ok := account.(state.UserAccountHandler)
		require.True(t, ok)

		value, _, retrieveErr := userAccount.RetrieveValue([]byte(authKey))
		require.NoError(t, retrieveErr)
		require.NotEmpty(t, userAccount.GetRootHash())
		require.Equal(t, authValue, value)
	}
}

func newDRWASystemAccountChainSimulator(t *testing.T) *simulator {
	t.Helper()
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 defaultRoundsPerEpoch,
		SupernovaRoundsPerEpoch:        defaultSupernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               defaultMinNodesPerShard,
		MetaChainMinNodes:              defaultMetaChainMinNodes,
	})
	require.NoError(t, err)
	require.NotNil(t, chainSimulator)

	return chainSimulator
}

func requireSystemAccountValueOnAllShards(t *testing.T, chainSimulator *simulator, key string, expectedValueHex string) {
	t.Helper()

	expectedValue, err := hex.DecodeString(expectedValueHex)
	require.NoError(t, err)

	for _, shardID := range []uint32{0, 1, 2, core.MetachainShardId} {
		nodeHandler := chainSimulator.GetNodeHandler(shardID)
		account, loadErr := nodeHandler.GetStateComponents().AccountsAdapter().LoadAccount(core.SystemAccountAddress)
		require.NoError(t, loadErr, "shard %d should load system account", shardID)
		userAccount, ok := account.(state.UserAccountHandler)
		require.True(t, ok, "shard %d system account should be a user account", shardID)
		require.NotEmpty(t, userAccount.GetRootHash(), "shard %d system account should have a data trie root hash", shardID)

		value, _, retrieveErr := userAccount.RetrieveValue([]byte(key))
		require.NoError(t, retrieveErr, "shard %d should retrieve DRWA authorized caller key", shardID)
		require.Equal(t, expectedValue, value, "shard %d should have replicated DRWA authorized caller value", shardID)
	}
}

func TestChainSimulator_SetEntireState(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 defaultRoundsPerEpoch,
		SupernovaRoundsPerEpoch:        defaultSupernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               defaultMinNodesPerShard,
		MetaChainMinNodes:              defaultMetaChainMinNodes,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	balance := "431271308732096033771131"
	contractAddress := "erd1qqqqqqqqqqqqqpgqmzzm05jeav6d5qvna0q2pmcllelkz8xddz3syjszx5"
	accountState := &dtos.AddressState{
		Address:          contractAddress,
		Nonce:            new(uint64),
		Balance:          balance,
		Code:             "0061736d010000000129086000006000017f60027f7f017f60027f7f0060017f0060037f7f7f017f60037f7f7f0060017f017f0290020b03656e7619626967496e74476574556e7369676e6564417267756d656e74000303656e760f6765744e756d417267756d656e7473000103656e760b7369676e616c4572726f72000303656e76126d42756666657253746f726167654c6f6164000203656e76176d427566666572546f426967496e74556e7369676e6564000203656e76196d42756666657246726f6d426967496e74556e7369676e6564000203656e76136d42756666657253746f7261676553746f7265000203656e760f6d4275666665725365744279746573000503656e760e636865636b4e6f5061796d656e74000003656e7614626967496e7446696e697368556e7369676e6564000403656e7609626967496e744164640006030b0a010104070301000000000503010003060f027f0041a080080b7f0041a080080b074607066d656d6f7279020004696e697400110667657453756d00120361646400130863616c6c4261636b00140a5f5f646174615f656e6403000b5f5f686561705f6261736503010aca010a0e01017f4100100c2200100020000b1901017f419c8008419c800828020041016b220036020020000b1400100120004604400f0b4180800841191002000b16002000100c220010031a2000100c220010041a20000b1401017f100c2202200110051a2000200210061a0b1301017f100c220041998008410310071a20000b1401017f10084101100d100b210010102000100f0b0e0010084100100d1010100e10090b2201037f10084101100d100b210110102202100e220020002001100a20022000100f0b0300010b0b2f0200418080080b1c77726f6e67206e756d626572206f6620617267756d656e747373756d00419c80080b049cffffff",
		CodeHash:         "n9EviPlHS6EV+3Xp0YqP28T0IUfeAFRFBIRC1Jw6pyU=",
		RootHash:         "76cr5Jhn6HmBcDUMIzikEpqFgZxIrOzgNkTHNatXzC4=",
		CodeMetadata:     "BQY=",
		Owner:            "erd1ss6u80ruas2phpmr82r42xnkd6rxy40g9jl69frppl4qez9w2jpsqj8x97",
		DeveloperRewards: "5401004999998",
		Pairs: map[string]string{
			"73756d": "0a",
		},
	}

	chainSimulatorCommon.CheckSetEntireState(t, chainSimulator, chainSimulator.GetNodeHandler(1), accountState)
}

func TestChainSimulator_SetEntireStateWithRemoval(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 defaultRoundsPerEpoch,
		SupernovaRoundsPerEpoch:        defaultSupernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               defaultMinNodesPerShard,
		MetaChainMinNodes:              defaultMetaChainMinNodes,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	balance := "431271308732096033771131"
	contractAddress := "erd1qqqqqqqqqqqqqpgqmzzm05jeav6d5qvna0q2pmcllelkz8xddz3syjszx5"
	accountState := &dtos.AddressState{
		Address:          contractAddress,
		Nonce:            new(uint64),
		Balance:          balance,
		Code:             "0061736d010000000129086000006000017f60027f7f017f60027f7f0060017f0060037f7f7f017f60037f7f7f0060017f017f0290020b03656e7619626967496e74476574556e7369676e6564417267756d656e74000303656e760f6765744e756d417267756d656e7473000103656e760b7369676e616c4572726f72000303656e76126d42756666657253746f726167654c6f6164000203656e76176d427566666572546f426967496e74556e7369676e6564000203656e76196d42756666657246726f6d426967496e74556e7369676e6564000203656e76136d42756666657253746f7261676553746f7265000203656e760f6d4275666665725365744279746573000503656e760e636865636b4e6f5061796d656e74000003656e7614626967496e7446696e697368556e7369676e6564000403656e7609626967496e744164640006030b0a010104070301000000000503010003060f027f0041a080080b7f0041a080080b074607066d656d6f7279020004696e697400110667657453756d00120361646400130863616c6c4261636b00140a5f5f646174615f656e6403000b5f5f686561705f6261736503010aca010a0e01017f4100100c2200100020000b1901017f419c8008419c800828020041016b220036020020000b1400100120004604400f0b4180800841191002000b16002000100c220010031a2000100c220010041a20000b1401017f100c2202200110051a2000200210061a0b1301017f100c220041998008410310071a20000b1401017f10084101100d100b210010102000100f0b0e0010084100100d1010100e10090b2201037f10084101100d100b210110102202100e220020002001100a20022000100f0b0300010b0b2f0200418080080b1c77726f6e67206e756d626572206f6620617267756d656e747373756d00419c80080b049cffffff",
		CodeHash:         "n9EviPlHS6EV+3Xp0YqP28T0IUfeAFRFBIRC1Jw6pyU=",
		RootHash:         "eqIumOaMn7G5cNSViK3XHZIW/C392ehfHxOZkHGp+Gc=", // root hash with auto balancing enabled
		CodeMetadata:     "BQY=",
		Owner:            "erd1ss6u80ruas2phpmr82r42xnkd6rxy40g9jl69frppl4qez9w2jpsqj8x97",
		DeveloperRewards: "5401004999998",
		Pairs: map[string]string{
			"73756d": "0a",
		},
	}
	chainSimulatorCommon.CheckSetEntireStateWithRemoval(t, chainSimulator, chainSimulator.GetNodeHandler(1), accountState)
}

func TestChainSimulator_GetAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 defaultRoundsPerEpoch,
		SupernovaRoundsPerEpoch:        defaultSupernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               defaultMinNodesPerShard,
		MetaChainMinNodes:              defaultMetaChainMinNodes,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	// the facade's GetAccount method requires that at least one block was produced over the genesis block
	_ = chainSimulator.GenerateBlocks(1)

	defer chainSimulator.Close()

	chainSimulatorCommon.CheckGetAccount(t, chainSimulator)
}

func TestSimulator_SendTransactions(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 defaultRoundsPerEpoch,
		SupernovaRoundsPerEpoch:        defaultSupernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               defaultMinNodesPerShard,
		MetaChainMinNodes:              defaultMetaChainMinNodes,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	chainSimulatorCommon.CheckGenerateTransactions(t, chainSimulator)
}

func TestSimulator_MoveBalanceCheckReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 defaultRoundsPerEpoch,
		SupernovaRoundsPerEpoch:        defaultSupernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               defaultMinNodesPerShard,
		MetaChainMinNodes:              defaultMetaChainMinNodes,
		AlterConfigsFunction: func(cfg *config.Configs) {
			cfg.EpochConfig.EnableEpochs.StakingV2EnableEpoch = 0
			cfg.EpochConfig.EnableEpochs.SupernovaEnableEpoch = uint32(2)
			cfg.RoundConfig.RoundActivations[string(common.SupernovaRoundFlag)] = config.ActivationRoundByName{
				Round: "46",
			}
		},
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	wallet0, err := chainSimulator.GenerateAndMintWalletAddress(0, chainSimulatorCommon.OneEGLD)
	require.Nil(t, err)
	err = chainSimulator.GenerateBlocks(1)
	require.Nil(t, err)

	ftx := &transaction.Transaction{
		Nonce:     0,
		Value:     big.NewInt(1),
		SndAddr:   wallet0.Bytes,
		RcvAddr:   wallet0.Bytes,
		Data:      []byte(""),
		GasLimit:  100_000,
		GasPrice:  1_000_000_000,
		ChainID:   []byte(configs.ChainID),
		Version:   1,
		Signature: []byte("010101"),
	}

	checkReceipts := func(te *testing.T, aB *apiBlock.Block, value string) {
		called := false
		for _, mb := range aB.MiniBlocks {
			if mb.Type == block.ReceiptBlock.String() {
				called = true
				require.Equal(te, 1, len(mb.Receipts))
				require.Equal(te, value, mb.Receipts[0].Value.String())
			}
		}
		require.True(te, called)
	}

	apiTx, err := chainSimulator.SendTxAndGenerateBlockTilTxIsExecuted(ftx, 10)
	require.Nil(t, err)
	require.NotNil(t, apiTx)

	blockWithTxs, err := chainSimulator.GetNodeHandler(0).GetFacadeHandler().GetBlockByNonce(apiTx.BlockNonce, apiBlock.BlockQueryOptions{
		WithTransactions: true,
		WithLogs:         true,
	})
	require.Nil(t, err)
	require.Equal(t, 2, len(blockWithTxs.MiniBlocks))
	checkReceipts(t, blockWithTxs, "50000000000000")

	err = chainSimulator.GenerateBlocks(50)
	require.Nil(t, err)

	ftx.Nonce++
	apiTx, err = chainSimulator.SendTxAndGenerateBlockTilTxIsExecuted(ftx, 10)
	require.Nil(t, err)
	require.NotNil(t, apiTx)

	blockWithTxs, err = chainSimulator.GetNodeHandler(0).GetFacadeHandler().GetBlockByNonce(apiTx.BlockNonce, apiBlock.BlockQueryOptions{
		WithTransactions: true,
		WithLogs:         true,
	})
	require.Nil(t, err)
	require.Equal(t, 2, len(blockWithTxs.MiniBlocks))
	checkReceipts(t, blockWithTxs, "500000000000")
}

func TestSimulator_SentMoveBalanceNoGasForFee(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 defaultRoundsPerEpoch,
		SupernovaRoundsPerEpoch:        defaultSupernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               defaultMinNodesPerShard,
		MetaChainMinNodes:              defaultMetaChainMinNodes,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	wallet0, err := chainSimulator.GenerateAndMintWalletAddress(0, big.NewInt(0))
	require.Nil(t, err)

	ftx := &transaction.Transaction{
		Nonce:     0,
		Value:     big.NewInt(0),
		SndAddr:   wallet0.Bytes,
		RcvAddr:   wallet0.Bytes,
		Data:      []byte(""),
		GasLimit:  50_000,
		GasPrice:  1_000_000_000,
		ChainID:   []byte(configs.ChainID),
		Version:   1,
		Signature: []byte("010101"),
	}
	_, err = chainSimulator.sendTx(ftx)
	require.True(t, strings.Contains(err.Error(), errors.ErrInsufficientFunds.Error()))
}

func TestSimulator_SendMoveBalanceTxBeforeAndAfterSupernovaWithMoreGasLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		BypassCreateBlockTimeCheck:     true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch:                 defaultRoundsPerEpoch,
		SupernovaRoundsPerEpoch:        defaultSupernovaRoundsPerEpoch,
		ApiInterface:                   api.NewNoApiInterface(),
		MinNodesPerShard:               defaultMinNodesPerShard,
		MetaChainMinNodes:              defaultMetaChainMinNodes,
		CreateBlockMaxTimePercent:      0.25,
		AlterConfigsFunction: func(cfg *config.Configs) {
			cfg.EpochConfig.EnableEpochs.SupernovaEnableEpoch = 2
		},
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	chainSimulatorCommon.GenerateMoveBalanceTxsInShardsWithMoreGasLimit(t, chainSimulator)

	err = chainSimulator.GenerateBlocksUntilEpochIsReached(3)
	require.Nil(t, err)

	chainSimulatorCommon.GenerateMoveBalanceTxsInShardsWithMoreGasLimit(t, chainSimulator)
}

func TestChainSimulator_VerifyEconomicsMetricsSupernova(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	supernovaActivationRound := uint64(46)
	supernovaActivationEpoch := uint64(2)

	cs, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            defaultPathToInitialConfig,
		NumOfShards:                    defaultNumOfShards,
		RoundDurationInMillis:          defaultRoundDurationInMillis,
		SupernovaRoundDurationInMillis: defaultSupernovaRoundDurationInMillis,
		RoundsPerEpoch: core.OptionalUint64{
			Value:    20,
			HasValue: true,
		},
		SupernovaRoundsPerEpoch: defaultSupernovaRoundsPerEpoch,
		ApiInterface:            api.NewNoApiInterface(),
		MinNodesPerShard:        defaultMinNodesPerShard,
		MetaChainMinNodes:       defaultMetaChainMinNodes,
		AlterConfigsFunction: func(cfg *config.Configs) {
			cfg.EpochConfig.EnableEpochs.StakingV2EnableEpoch = 0
			cfg.EpochConfig.EnableEpochs.SupernovaEnableEpoch = uint32(supernovaActivationEpoch)
			cfg.RoundConfig.RoundActivations[string(common.SupernovaRoundFlag)] = config.ActivationRoundByName{
				Round: fmt.Sprintf("%d", supernovaActivationRound),
			}
		},
	})
	require.Nil(t, err)
	require.NotNil(t, cs)
	defer cs.Close()

	require.Nil(t, cs.GenerateBlocksUntilEpochIsReached(int32(supernovaActivationEpoch)))

	mintValue := big.NewInt(0).Mul(chainSimulatorCommon.OneEGLD, big.NewInt(3000*5))
	wallet1, err := cs.GenerateAndMintWalletAddress(0, mintValue)
	require.Nil(t, err)

	_, blsKeys, err := GenerateBlsPrivateKeys(1)
	require.Nil(t, err)

	err = cs.GenerateBlocks(1)
	require.Nil(t, err)

	nonce := uint64(0)
	for currentEpoch := supernovaActivationEpoch + 1; currentEpoch < supernovaActivationEpoch+4; currentEpoch++ {
		dataFieldTx1 := fmt.Sprintf("stake@01@%s@%s", blsKeys[0], staking.MockBLSSignature)
		tx1Value := big.NewInt(0).Mul(big.NewInt(2501), chainSimulatorCommon.OneEGLD)
		tx1 := chainSimulatorCommon.GenerateTransaction(wallet1.Bytes, nonce, vm.ValidatorSCAddress, tx1Value, dataFieldTx1, staking.GasLimitForStakeOperation)

		results, err := cs.SendTxsAndGenerateBlocksTilAreExecuted([]*transaction.Transaction{tx1}, staking.MaxNumOfBlockToGenerateWhenExecutingTx)
		require.Nil(t, err)
		require.Equal(t, 1, len(results))
		require.NotNil(t, results)

		require.Nil(t, cs.GenerateBlocksUntilEpochIsReached(int32(currentEpoch)))
		checkMetrics(t, cs, core.MetachainShardId, currentEpoch)
		checkMetrics(t, cs, 0, currentEpoch)

		nonce++
	}
}

func checkMetrics(t *testing.T, cs ChainSimulator, shardID uint32, expectedEpoch uint64) {
	res, err := cs.GetNodeHandler(shardID).GetFacadeHandler().StatusMetrics().EconomicsMetrics()
	require.Nil(t, err)

	expectedMetrics := map[string]struct{}{
		common.MetricTotalSupply:           {},
		common.MetricInflation:             {},
		common.MetricEpochForEconomicsData: {},
		common.MetricTotalFees:             {},
		common.MetricDevRewardsInEpoch:     {},
	}

	for foundMetric, metricValue := range res {
		require.Contains(t, expectedMetrics, foundMetric)

		switch metricVal := metricValue.(type) {
		case string:
			require.Greater(t, len(metricVal), 1)
		case uint64:
			require.Equal(t, expectedEpoch, metricValue)
		default:
			require.Fail(t, "metric value is not a string or uint64")
		}

		delete(expectedMetrics, foundMetric)

	}

	require.Empty(t, expectedMetrics, "should've found all expected metrics in the result from facade")
}
