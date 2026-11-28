package processing

import (
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"

	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/state"
)

// installDRWAShardRegistry creates the registry projection of the processing
// store of an execution shard on a DRWA deployment. It becomes the registry
// source of the shard classifier, its delta call and the destination of
// protected admin legs are added to the processing built-in container only,
// and it is returned as the block processor's classification handler. On any other node nothing is created and the
// returned handler is nil.
func (pcf *processComponentsFactory) installDRWAShardRegistry(
	accounts state.AccountsAdapter,
	builtIns vmcommon.BuiltInFunctionContainer,
) (process.DRWAClassificationHandler, error) {
	if !pcf.isDRWADeployment() {
		return nil, nil
	}
	if pcf.drwaShardClassification != nil || pcf.drwaShardRegistrySource != nil {
		// The classifier of this node was already created without this source.
		return nil, drwa.ErrInvalidRegistryDelta
	}

	registry, err := drwa.NewShardRegistry(accounts, pcf.bootstrapComponents.ShardCoordinator().SelfId())
	if err != nil {
		return nil, err
	}
	err = builtIns.Add(drwa.RegistryDeltaFunctionName, registry.DeltaFunction())
	if err != nil {
		return nil, err
	}
	// The destination of protected admin legs classifies by this registry and
	// lives in the same container.
	_, err = pcf.installDRWAAdminEffects(accounts, builtIns, registry)
	if err != nil {
		return nil, err
	}
	pcf.drwaShardRegistrySource = registry

	return registry, nil
}
