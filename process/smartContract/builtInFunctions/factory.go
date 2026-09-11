package builtInFunctions

import (
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	logger "github.com/multiversx/mx-chain-logger-go"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmcommonBuiltInFunctions "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
)

var log = logger.GetOrCreate("process/smartcontract/builtInFunctions")

// ArgsCreateBuiltInFunctionContainer defines the argument structure to create new built in function container
type ArgsCreateBuiltInFunctionContainer struct {
	GasSchedule                  core.GasScheduleNotifier
	MapDNSAddresses              map[string]struct{}
	MapDNSV2Addresses            map[string]struct{}
	EnableUserNameChange         bool
	Marshalizer                  marshal.Marshalizer
	Accounts                     state.AccountsAdapter
	ShardCoordinator             sharding.Coordinator
	EpochNotifier                vmcommon.EpochNotifier
	EnableEpochsHandler          vmcommon.EnableEpochsHandler
	GuardedAccountHandler        vmcommon.GuardedAccountHandler
	AutomaticCrawlerAddresses    [][]byte
	MaxNumNodesInTransferRole    uint32
	DRWANetworkDomain            [32]byte
	DRWACEBEpoch                 uint32
	DRWASettlementLifetimeRounds uint64
}

// CreateBuiltInFunctionsFactory creates a container that will hold all the available built in functions
func CreateBuiltInFunctionsFactory(args ArgsCreateBuiltInFunctionContainer) (vmcommon.BuiltInFunctionFactory, error) {
	if check.IfNil(args.GasSchedule) {
		return nil, process.ErrNilGasSchedule
	}
	if check.IfNil(args.Marshalizer) {
		return nil, process.ErrNilMarshalizer
	}
	if check.IfNil(args.Accounts) {
		return nil, process.ErrNilAccountsAdapter
	}
	if args.MapDNSAddresses == nil || args.MapDNSV2Addresses == nil {
		return nil, process.ErrNilDnsAddresses
	}
	if check.IfNil(args.ShardCoordinator) {
		return nil, process.ErrNilShardCoordinator
	}
	if check.IfNil(args.EpochNotifier) {
		return nil, process.ErrNilEpochNotifier
	}
	if check.IfNil(args.EnableEpochsHandler) {
		return nil, process.ErrNilEnableEpochsHandler
	}
	if check.IfNil(args.GuardedAccountHandler) {
		return nil, process.ErrNilGuardedAccountHandler
	}

	vmcommonAccounts, ok := args.Accounts.(vmcommon.AccountsAdapter)
	if !ok {
		return nil, process.ErrWrongTypeAssertion
	}

	crawlerAllowedAddress, err := GetAllowedAddress(
		args.ShardCoordinator,
		args.AutomaticCrawlerAddresses)
	if err != nil {
		return nil, err
	}
	drwaGasScheduleCatalog, err := sealDRWAConfiguredGasScheduleCatalog(args.GasSchedule)
	if err != nil {
		return nil, err
	}

	log.Debug("createBuiltInFunctionsFactory",
		"shardId", args.ShardCoordinator.SelfId(),
		"crawlerAllowedAddress", crawlerAllowedAddress,
	)

	modifiedArgs := vmcommonBuiltInFunctions.ArgsCreateBuiltInFunctionContainer{
		GasMap:                           args.GasSchedule.LatestGasSchedule(),
		MapDNSAddresses:                  args.MapDNSAddresses,
		MapDNSV2Addresses:                args.MapDNSV2Addresses,
		EnableUserNameChange:             args.EnableUserNameChange,
		Marshalizer:                      args.Marshalizer,
		Accounts:                         vmcommonAccounts,
		ShardCoordinator:                 args.ShardCoordinator,
		EnableEpochsHandler:              args.EnableEpochsHandler,
		GuardedAccountHandler:            args.GuardedAccountHandler,
		ConfigAddress:                    crawlerAllowedAddress,
		MaxNumOfAddressesForTransferRole: args.MaxNumNodesInTransferRole,
	}

	bContainerFactory, err := vmcommonBuiltInFunctions.NewBuiltInFunctionsCreator(modifiedArgs)
	if err != nil {
		return nil, err
	}

	guardedFactory := &drwaGuardedBuiltInFunctionFactory{
		delegate:                     bContainerFactory,
		accounts:                     vmcommonAccounts,
		enableEpochsHandler:          args.EnableEpochsHandler,
		drwaNetworkDomain:            args.DRWANetworkDomain,
		drwaGasScheduleCatalog:       drwaGasScheduleCatalog,
		gasScheduleNotifier:          args.GasSchedule,
		drwaCEBEpoch:                 args.DRWACEBEpoch,
		drwaSettlementLifetimeRounds: args.DRWASettlementLifetimeRounds,
		shardCoordinator:             args.ShardCoordinator,
	}
	if drwaGasScheduleCatalog != nil {
		currentIdentity, identityErr := guardedFactory.DRWACurrentGasScheduleIdentity()
		if identityErr != nil {
			return nil, identityErr
		}
		catalogIdentity, identityErr := drwaGasScheduleCatalog.Identity()
		if identityErr != nil {
			return nil, identityErr
		}
		log.Info("NON_NORMATIVE_DRWA_PROTOTYPE gas schedule catalog sealed",
			"shardId", args.ShardCoordinator.SelfId(),
			"catalogIdentity", fmt.Sprintf("%x", catalogIdentity),
			"currentIdentity", fmt.Sprintf("%x", currentIdentity),
		)
	}
	err = guardedFactory.CreateBuiltInFunctionContainer()
	if err != nil {
		return nil, err
	}

	args.GasSchedule.RegisterNotifyHandler(bContainerFactory)

	return guardedFactory, nil
}

// GetAllowedAddress returns the allowed crawler address on the current shard
func GetAllowedAddress(coordinator sharding.Coordinator, addresses [][]byte) ([]byte, error) {
	if check.IfNil(coordinator) {
		return nil, process.ErrNilShardCoordinator
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("%w for shard %d, provided count is %d", process.ErrNilCrawlerAllowedAddress, coordinator.SelfId(), len(addresses))
	}

	if coordinator.SelfId() == core.MetachainShardId {
		return core.SystemAccountAddress, nil
	}

	for _, address := range addresses {
		allowedAddressShardId := coordinator.ComputeId(address)
		if allowedAddressShardId == coordinator.SelfId() {
			return address, nil
		}
	}

	return nil, fmt.Errorf("%w for shard %d, provided count is %d", process.ErrNilCrawlerAllowedAddress, coordinator.SelfId(), len(addresses))
}
