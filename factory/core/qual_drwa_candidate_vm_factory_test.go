package core

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core/versioning"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	hasherFactory "github.com/multiversx/mx-chain-core-go/hashing/factory"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/chainparametersnotifier"
	converterFactory "github.com/multiversx/mx-chain-go/common/factory"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/epochStart/notifier"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/economics"
	nativeFactory "github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/process/factory/shard"
	"github.com/multiversx/mx-chain-go/process/smartContract/builtInFunctions"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/multiversx/mx-chain-vm-go/vmhost"
	"github.com/stretchr/testify/require"
)

// T09 M12: loaded constructor inputs only. Existing account/guardian doubles
// and a blockchain-hook double supply no authenticated state or execution.
func qualDRWACandidateEconomicsArgs(t *testing.T, args builtInFunctions.ArgsCreateBuiltInFunctionContainer, cfg *config.Config) economics.ArgsNewEconomicsData {
	t.Helper()
	economicConfig, err := common.LoadEconomicsConfig(qualDRWACandidateGenesisPath(t, "economics.toml"))
	require.NoError(t, err)
	converter, err := converterFactory.NewPubkeyConverter(cfg.AddressPubkeyConverter)
	require.NoError(t, err)
	epochStart := notifier.NewEpochStartSubscriptionHandler()
	parameters, err := sharding.NewChainParametersHolder(sharding.ArgsChainParametersHolder{
		EpochStartEventNotifier: epochStart, ChainParameters: cfg.GeneralSettings.ChainParametersByEpoch,
		ChainParametersNotifier: chainparametersnotifier.NewChainParametersNotifier(),
	})
	require.NoError(t, err)
	epochStart.NotifyAll(&block.Header{Epoch: args.EnableEpochsHandler.(common.EnableEpochsHandler).GetCurrentEpoch()})
	return economics.ArgsNewEconomicsData{
		Economics: economicConfig, ChainParamsHandler: parameters,
		EpochNotifier: args.EpochNotifier.(process.EpochNotifier), EnableEpochsHandler: args.EnableEpochsHandler.(common.EnableEpochsHandler),
		TxVersionChecker: versioning.NewTxVersionChecker(cfg.GeneralSettings.MinTransactionVersion),
		PubkeyConverter:  converter, ShardCoordinator: args.ShardCoordinator,
	}
}

func qualDRWACandidateVMFactoryArgs(t *testing.T, shardID, epoch uint32, query bool) shard.ArgVMContainerFactory {
	t.Helper()
	args, cfg, _, vmLocker := qualDRWACandidateBuiltInArgs(t, shardID)
	args.EpochNotifier.(interface{ CheckEpoch(data.HeaderHandler) }).CheckEpoch(&block.Header{Epoch: epoch, Round: 440})
	builtins, err := builtInFunctions.CreateBuiltInFunctionsFactory(args)
	require.NoError(t, err)
	economicArgs := qualDRWACandidateEconomicsArgs(t, args, cfg)
	economicData, err := economics.NewEconomicsData(economicArgs)
	require.NoError(t, err)
	hasher, err := hasherFactory.NewHasher(cfg.Hasher.Type)
	require.NoError(t, err)
	parser, err := parsers.NewESDTTransferParser(args.Marshalizer)
	require.NoError(t, err)
	vmConfig := cfg.VirtualMachine.Execution
	if query {
		vmConfig = cfg.VirtualMachine.Querying.VirtualMachineConfig
	}
	hook := &testscommon.BlockChainHookStub{
		GetUserAccountCalled: func([]byte) (vmcommon.UserAccountHandler, error) {
			t.Fatal("constructor/allowlist lookup attempted account access")
			return nil, nil
		},
		ProcessBuiltInFunctionCalled: func(*vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
			t.Fatal("constructor/allowlist lookup attempted native effect")
			return nil, nil
		},
	}
	return shard.ArgVMContainerFactory{
		Config: vmConfig, BlockGasLimit: economicData.MaxGasLimitPerBlock(shardID),
		GasSchedule: args.GasSchedule, EpochNotifier: args.EpochNotifier.(process.EpochNotifier),
		EnableEpochsHandler: args.EnableEpochsHandler.(common.EnableEpochsHandler), WasmVMChangeLocker: vmLocker,
		ESDTTransferParser: parser, BuiltInFunctions: builtins.BuiltInFunctionContainer(),
		BlockChainHook: hook, Hasher: hasher, PubKeyConverter: economicArgs.PubkeyConverter,
	}
}

func TestQualDRWACandidateVMSubfactoryInputs(t *testing.T) {
	for _, query := range []bool{false, true} {
		for _, shardID := range []uint32{0, 1, 2} {
			for _, epoch := range []uint32{0, 3} {
				t.Run(fmt.Sprintf("query_%t_shard_%d_epoch_%d", query, shardID, epoch), func(t *testing.T) {
					args := qualDRWACandidateVMFactoryArgs(t, shardID, epoch, query)
					// Literal candidate proposal values, not accepted production limits.
					wantGas := uint64(1500000000)
					if epoch == 3 {
						wantGas = 600000000
					}
					require.Equal(t, wantGas, args.BlockGasLimit)
					require.Equal(t, []config.WasmVMVersionByEpoch{{StartEpoch: 0, Version: "v1.5"}}, args.Config.WasmVMVersions)
					require.Equal(t, []string{"erd1qqqqqqqqqqqqqpgqr46jrxr6r2unaqh75ugd308dwx5vgnhwh47qtvepe3"}, args.Config.TransferAndExecuteByUserAddresses)
					factory, err := shard.NewVMContainerFactory(args)
					require.NoError(t, err)
					container, err := factory.Create() // No node factory or SC execution.
					require.NoError(t, err)
					t.Cleanup(func() { require.NoError(t, factory.Close()) })
					require.Equal(t, 1, container.Len())
					require.Equal(t, [][]byte{nativeFactory.WasmVirtualMachine}, container.Keys())
					machine, err := container.Get(nativeFactory.WasmVirtualMachine)
					require.NoError(t, err)
					require.Equal(t, "v1.5", machine.GetVersion())
					host := machine.(vmhost.VMHost)
					allowed, err := args.PubKeyConverter.Decode(args.Config.TransferAndExecuteByUserAddresses[0])
					require.NoError(t, err)
					outsider := make([]byte, 32)
					outsider[0] = 1
					host.Runtime().InitStateFromContractCallInput(&vmcommon.ContractCallInput{
						VMInput: vmcommon.VMInput{CallerAddr: outsider, CallValue: big.NewInt(0)}, RecipientAddr: allowed,
					})
					require.True(t, host.IsAllowedToExecute("managedMultiTransferESDTNFTExecuteByUser"))
					require.False(t, host.IsAllowedToExecute("not-a-native-opcode"))
					host.Runtime().InitStateFromContractCallInput(&vmcommon.ContractCallInput{
						VMInput: vmcommon.VMInput{CallerAddr: allowed, CallValue: big.NewInt(0)}, RecipientAddr: outsider,
					})
					require.False(t, host.IsAllowedToExecute("managedMultiTransferESDTNFTExecuteByUser"), "caller alone cannot authorize the context")
				})
			}
		}
	}
}

func TestQualDRWACandidateVMSubfactoryDenials(t *testing.T) {
	for _, fault := range []string{"empty_opcode_addresses", "malformed_opcode_address"} {
		t.Run(fault, func(t *testing.T) {
			args := qualDRWACandidateVMFactoryArgs(t, 0, 0, false)
			args.Config.TransferAndExecuteByUserAddresses = nil
			if fault == "malformed_opcode_address" {
				args.Config.TransferAndExecuteByUserAddresses = []string{"wrong"}
			}
			factory, err := shard.NewVMContainerFactory(args)
			require.Error(t, err)
			require.Nil(t, factory)
			if fault == "empty_opcode_addresses" {
				require.ErrorIs(t, err, process.ErrTransferAndExecuteByUserAddressesAreNil)
			}
		})
	}
	for _, index := range []int{0, 2} {
		t.Run(fmt.Sprintf("malformed_economics_epoch_%d", index), func(t *testing.T) {
			args, cfg, _, _ := qualDRWACandidateBuiltInArgs(t, 0)
			economicArgs := qualDRWACandidateEconomicsArgs(t, args, cfg)
			economicArgs.Economics.FeeSettings.GasLimitSettings[index].MaxGasLimitPerBlock = "wrong"
			_, err := economics.NewEconomicsData(economicArgs)
			require.ErrorIs(t, err, process.ErrInvalidMaxGasLimitPerBlock)
		})
	}
	t.Run("zero_future_epoch_duration", func(t *testing.T) {
		args, cfg, _, _ := qualDRWACandidateBuiltInArgs(t, 0)
		cfg.GeneralSettings.ChainParametersByEpoch[1].RoundDuration = 0
		economicArgs := qualDRWACandidateEconomicsArgs(t, args, cfg)
		_, err := economics.NewEconomicsData(economicArgs)
		require.ErrorIs(t, err, process.ErrZeroDurationForEpoch, "future configuration is validated before its activation")
	})
}
