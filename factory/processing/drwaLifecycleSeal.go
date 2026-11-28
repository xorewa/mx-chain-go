package processing

import (
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"

	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/state"
)

// installDRWALifecycleSeal creates the lifecycle seal owner of an execution
// shard on a DRWA deployment: its protected call is added to the processing
// built-in container only, and it becomes the seal check of the destination
// of protected admin legs, whichever binding source is installed there later.
// installDRWAShardRegistry calls it with the destination it has just
// installed. On any other node nothing is created.
func (pcf *processComponentsFactory) installDRWALifecycleSeal(
	accounts state.AccountsAdapter,
	builtIns vmcommon.BuiltInFunctionContainer,
	adminEffects *drwa.AdminEffectFunction,
) (*drwa.LifecycleSeal, error) {
	if !pcf.isDRWADeployment() {
		return nil, nil
	}

	coordinator := pcf.bootstrapComponents.ShardCoordinator()
	seal, err := drwa.NewLifecycleSeal(drwa.ArgsLifecycleSeal{
		Accounts:    accounts,
		Marshaller:  pcf.coreData.InternalMarshalizer(),
		Hasher:      pcf.coreData.Hasher(),
		Shard:       coordinator.SelfId(),
		Shards:      coordinator.NumberOfShards(),
		RecordBytes: pcf.drwaInitialProgrammeStartup.Limits.RecordBytes,
	})
	if err != nil {
		return nil, err
	}
	err = adminEffects.SetSealGate(seal)
	if err != nil {
		return nil, err
	}
	err = builtIns.Add(drwa.LifecycleSealFunctionName, seal.Function())
	if err != nil {
		return nil, err
	}

	return seal, nil
}

// installDRWALifecycleSealOrigin creates the metachain node's owner of the
// setup seal's replication over the node's funding owner, and installs it as
// the owner of the setup family on the node's convergence host. Replication
// has no caller until the row that owns the setup ingress calls it (SP2-38).
func (pcf *processComponentsFactory) installDRWALifecycleSealOrigin(
	accounts state.AccountsAdapter,
	host *drwa.ConvergenceHost,
	funding *drwa.CarrierFunding,
) (*drwa.LifecycleSealOrigin, error) {
	seal, err := drwa.NewLifecycleSealOrigin(drwa.ArgsLifecycleSealOrigin{
		Accounts:    accounts,
		Marshaller:  pcf.coreData.InternalMarshalizer(),
		Hasher:      pcf.coreData.Hasher(),
		Funding:     funding,
		Shards:      pcf.bootstrapComponents.ShardCoordinator().NumberOfShards(),
		RecordBytes: pcf.drwaInitialProgrammeStartup.Limits.RecordBytes,
	})
	if err != nil {
		return nil, err
	}
	err = host.SetFamilyOwner(drwa.ConvergenceFamilySetup, seal)
	if err != nil {
		return nil, err
	}

	return seal, nil
}
