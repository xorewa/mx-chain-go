package core

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	nativeCore "github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/ordering"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	historyFactory "github.com/multiversx/mx-chain-go/dblookupext/factory"
	"github.com/multiversx/mx-chain-go/genesis"
	"github.com/multiversx/mx-chain-go/genesis/parsing"
	genesisProcess "github.com/multiversx/mx-chain-go/genesis/process"
	"github.com/multiversx/mx-chain-go/process/transactionLog"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

// T09-M33/M34/M35: native genesis and installed code over the public candidate.
// The native genesis pipeline creates and executes its internal transactions;
// no transaction is submitted, node launched or DRWA root/role provisioned.
// SS-02 applies: the capture excludes this executing-WASM root in race mode.
// Returned roots bind native state; they are not independent root-byte oracles.
func TestQualDRWACandidateExecutingNativeGenesis(t *testing.T) {
	var sharedGenesisTime uint64
	comparisonHeaders := make(map[uint32][]byte)
	for _, shard := range []uint32{0, 1, 2, nativeCore.MetachainShardId} {
		t.Run(fmt.Sprint(shard), func(t *testing.T) {
			firstRole := len(comparisonHeaders) == 0
			dataArgs := qualDRWACandidateDataArgs(t, 0, shard)
			stateHandler, dataHandler := qualDRWACandidateStateComponents(t, dataArgs)
			coreHandler := dataArgs.Core
			parser, err := parsing.NewAccountsParser(qualDRWACandidateGenesisArgs(t))
			require.NoError(t, err)
			contracts, err := parsing.NewSmartContractsParser(
				qualDRWACandidateGenesisPath(t, "genesisSmartContracts.json"),
				coreHandler.AddressPubKeyConverter(), dataArgs.Crypto.TxSignKeyGen())
			require.NoError(t, err)
			systemPath := filepath.Join(t.TempDir(), "systemSmartContractsConfig.toml")
			systemBody := []byte("[StakingSystemSCConfig]\n    GenesisNodePrice = \"2500000000000000000000\" #2.5K eGLD\n    MinStakeValue = \"100000000000000000000\" #100 eGLD\n    MinUnstakeTokensValue = \"10000000000000000000\" #10eGLD\n    UnBondPeriod = 250           # period as number of rounds\n    UnBondPeriodSupernova = 2500 # period as number of rounds\n    UnBondPeriodInEpochs = 3\n    MinStepValue = \"100000000000000000000\"\n    NumRoundsWithoutBleed = 100\n    MaximumPercentageToBleed = 0.5\n    BleedPercentagePerRound = 0.00001\n    MaxNumberOfNodesForStake = 64\n    UnJailValue = \"2500000000000000000\" #0.1% of genesis node price\n    ActivateBLSPubKeyMessageVerification = true\n    StakeLimitPercentage = 1.0 #fraction of value 1 - 100%, for the time being no stake limit\n    NodeLimitPercentage = 0.1 #fraction of value 0.1 - 10%\n\n[ESDTSystemSCConfig]\n    BaseIssuingCost = \"5000000000000000000\" #5 eGLD\n    OwnerAddress = \"erd1fpkcgel4gcmh8zqqdt043yfcn5tyx8373kg6q2qmkxzu4dqamc0swts65c\"\n\n[GovernanceSystemSCConfig]\n    OwnerAddress = \"erd1vxy22x0fj4zv6hktmydg8vpfh6euv02cz4yg0aaws6rrad5a5awqgqky80\" #should use a multisign contract instead of a wallet address\n    MaxVotingDelayPeriodInEpochs = 30\n    [GovernanceSystemSCConfig.V1]\n        NumNodes           = 500\n        ProposalCost       = \"5000000000000000000\" #5 eGLD\n        MinQuorum          = 400\n        MinPassThreshold   = 300\n        MinVetoThreshold   = 50\n    [GovernanceSystemSCConfig.Active]\n        ProposalCost       = \"1000000000000000000000\" #1000 eGLD\n        LostProposalFee    = \"10000000000000000000\"   #10 eGLD\n        MinQuorum          = 0.2  #fraction of value 0.2  - 20%\n        MinPassThreshold   = 0.5  #fraction of value 0.5  - 50%\n        MinVetoThreshold   = 0.33 #fraction of value 0.33 - 33%\n\n[DelegationManagerSystemSCConfig]\n    MinCreationDeposit = \"1250000000000000000000\" #1.25K eGLD\n    MinStakeAmount = \"1000000000000000000\" #1 eGLD\n    ConfigChangeAddress = \"erd1vxy22x0fj4zv6hktmydg8vpfh6euv02cz4yg0aaws6rrad5a5awqgqky80\" #should use a multisign contract instead of a wallet address\n\n[DelegationSystemSCConfig]\n    MinServiceFee  = 0\n    MaxServiceFee  = 10000\n\n# Changing this config is not backwards compatible\n[SoftAuctionConfig]\n    TopUpStep = \"10000000000000000000\" # 10 EGLD\n    MinTopUp = \"1000000000000000000\" # 1 EGLD should be minimum\n    MaxTopUp = \"32000000000000000000000000\" # 32 mil EGLD\n    MaxNumberOfIterations = 100000 # 100k max number of iterations for soft auction config\n")
			require.Equal(t, "7076576029de787f201bf6528189db51994983518c3de9300d6f95c09954ec97", fmt.Sprintf("%x", sha256.Sum256(systemBody)))
			require.NoError(t, os.WriteFile(systemPath, systemBody, 0600))
			systemConfig, err := common.LoadSystemSmartContractsConfig(systemPath)
			require.NoError(t, err)
			epochConfig, err := common.LoadEpochConfig(qualDRWACandidateGenesisPath(t, "enableEpochs.toml"))
			require.NoError(t, err)
			roundConfig, err := common.LoadRoundConfig(qualDRWACandidateGenesisPath(t, "enableRounds.toml"))
			require.NoError(t, err)
			economicsConfig, err := common.LoadEconomicsConfig(qualDRWACandidateGenesisPath(t, "economics.toml"))
			require.NoError(t, err)
			builtInArgs, _, _, _ := qualDRWACandidateBuiltInArgs(t, shard)
			logStore, err := dataHandler.StorageService().GetStorer(dataRetriever.TxLogsUnit)
			require.NoError(t, err)
			logs, err := transactionLog.NewTxLogProcessor(transactionLog.ArgTxLogProcessor{
				Storer: logStore, Marshalizer: coreHandler.InternalMarshalizer(),
				SaveInStorageEnabled: dataArgs.Config.LogsAndEvents.SaveInStorageEnabled || dataArgs.Config.DbLookupExtensions.Enabled,
			})
			require.NoError(t, err)
			historyCreator, err := historyFactory.NewHistoryRepositoryFactory(&historyFactory.ArgsHistoryRepositoryFactory{
				SelfShardID: shard, Config: dataArgs.Config.DbLookupExtensions, Store: dataHandler.StorageService(),
				Marshalizer: coreHandler.InternalMarshalizer(), Hasher: coreHandler.Hasher(),
				Uint64ByteSliceConverter: coreHandler.Uint64ByteSliceConverter(), DataPool: dataHandler.Datapool(),
			})
			require.NoError(t, err)
			history, err := historyCreator.Create()
			require.NoError(t, err)
			args := genesisProcess.ArgsGenesisBlockCreator{
				GenesisTime:  uint64(coreHandler.GenesisNodesSetup().GetStartTime()),
				GenesisEpoch: dataArgs.Config.EpochStartConfig.GenesisEpoch,
				Data:         dataHandler, Core: coreHandler, Accounts: stateHandler.AccountsAdapter(),
				AccountsProposal: stateHandler.AccountsAdapterProposal(), ValidatorAccounts: stateHandler.PeerAccounts(),
				InitialNodesSetup: coreHandler.GenesisNodesSetup(), Economics: coreHandler.EconomicsData(),
				ShardCoordinator: dataArgs.ShardCoordinator, AccountsParser: parser, SmartContractParser: contracts,
				GasSchedule: builtInArgs.GasSchedule, TxLogsProcessor: logs, VirtualMachineConfig: dataArgs.Config.VirtualMachine.Execution,
				HardForkConfig: dataArgs.Config.Hardfork, TrieStorageManagers: stateHandler.TrieStorageManagers(),
				SystemSCConfig: *systemConfig, RoundConfig: *roundConfig, EpochConfig: *epochConfig,
				FeeSettings: economicsConfig.FeeSettings, HeaderVersionConfigs: dataArgs.Config.Versions,
				TxCacheSelectionConfig: dataArgs.Config.TxCacheSelection, WorkingDir: t.TempDir(),
				BlockSignKeyGen: dataArgs.Crypto.BlockSignKeyGen(), HistoryRepository: history,
				TxExecutionOrderHandler: ordering.NewOrderedCollection(), GenesisString: dataArgs.Config.GeneralSettings.GenesisString,
			}
			require.False(t, args.HardForkConfig.AfterHardFork)
			require.Zero(t, args.GenesisEpoch)
			// Candidate startTime=0 uses the local clock. Hold one observed
			// native timestamp equal across these independent test executions;
			// this does not select or admit a deployment genesis timestamp.
			if firstRole {
				sharedGenesisTime = args.GenesisTime
			}
			args.GenesisTime = sharedGenesisTime
			before, err := args.Accounts.RootHash()
			require.NoError(t, err)
			for _, price := range []string{"0", "-1"} {
				invalid := args
				invalid.SystemSCConfig.StakingSystemSCConfig.GenesisNodePrice = price
				creator, err := genesisProcess.NewGenesisBlockCreator(invalid)
				require.ErrorIs(t, err, genesis.ErrInvalidInitialNodePrice)
				require.Nil(t, creator)
				after, err := args.Accounts.RootHash()
				require.NoError(t, err)
				require.Equal(t, before, after)
			}
			creator, err := genesisProcess.NewGenesisBlockCreator(args)
			require.NoError(t, err)
			headers, err := creator.CreateGenesisBlocks()
			require.NoError(t, err)
			require.Len(t, headers, 4)
			for _, expectedShard := range []uint32{0, 1, 2, nativeCore.MetachainShardId} {
				header := headers[expectedShard]
				require.NotNil(t, header)
				require.Equal(t, expectedShard, header.GetShardID())
				require.Zero(t, header.GetNonce())
				require.Zero(t, header.GetRound())
				require.Zero(t, header.GetEpoch())
				require.Equal(t, args.GenesisTime, header.GetTimeStamp())
				require.Equal(t, []byte(coreHandler.ChainID()), header.GetChainID())
				require.NotEmpty(t, header.GetRootHash())
				encoded, err := coreHandler.InternalMarshalizer().Marshal(header)
				require.NoError(t, err)
				if firstRole {
					comparisonHeaders[expectedShard] = append([]byte(nil), encoded...)
				} else {
					require.Equal(t, comparisonHeaders[expectedShard], encoded,
						"independent role %d differs for genesis shard %d", shard, expectedShard)
				}
				hash := coreHandler.Hasher().Compute(string(encoded))
				unit := dataRetriever.BlockHeaderUnit
				if expectedShard == nativeCore.MetachainShardId {
					unit = dataRetriever.MetaBlockUnit
				}
				stored, err := dataHandler.StorageService().Get(unit, hash)
				require.NoError(t, err)
				require.Equal(t, encoded, stored)
			}
			root, err := args.Accounts.RootHash()
			require.NoError(t, err)
			require.Equal(t, headers[shard].GetRootHash(), root)
			split, err := parser.InitialAccountsSplitOnAddressesShards(dataArgs.ShardCoordinator)
			require.NoError(t, err)
			if shard != nativeCore.MetachainShardId {
				require.NotEmpty(t, split[shard], "local balance checks must execute")
			}
			for _, initial := range split[shard] {
				account, err := args.Accounts.GetExistingAccount(initial.AddressBytes())
				require.NoError(t, err)
				user, ok := account.(state.UserAccountHandler)
				require.True(t, ok)
				require.Zero(t, user.GetBalance().Cmp(initial.GetBalanceValue()))
			}
			localContracts := 0
			for _, contract := range contracts.InitialSmartContracts() {
				inputCode, err := os.ReadFile(contract.GetFilename())
				require.NoError(t, err)
				for _, address := range contract.AddressesBytes() {
					if dataArgs.ShardCoordinator.ComputeId(address) != shard {
						continue
					}
					account, err := args.Accounts.GetExistingAccount(address)
					require.NoError(t, err)
					user, ok := account.(state.UserAccountHandler)
					require.True(t, ok)
					require.NotEmpty(t, user.GetCodeHash())
					require.Equal(t, inputCode, args.Accounts.GetCode(user.GetCodeHash()))
					localContracts++
				}
			}
			if shard != nativeCore.MetachainShardId {
				require.Positive(t, localContracts, "native installed code checks must execute")
			}
			meta, ok := headers[nativeCore.MetachainShardId].(*block.MetaBlock)
			require.True(t, ok)
			require.Equal(t, coreHandler.EconomicsData().GenesisTotalSupply(), meta.EpochStart.Economics.TotalSupply)
			require.Positive(t, meta.EpochStart.Economics.NodePrice.Sign())
			require.Equal(t, systemConfig.StakingSystemSCConfig.GenesisNodePrice, meta.EpochStart.Economics.NodePrice.String())
			index := creator.GetIndexingData()[nativeCore.MetachainShardId]
			require.NotNil(t, index)
			require.Len(t, index.StakingTxs, 36)
			require.NotEmpty(t, index.DeploySystemScTxs)
		})
	}
}
