package processing

import (
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"

	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/state"
)

// drwaDomain returns the network domain of the deployment identity this node
// has open, or nil when none is open.
func (pcf *processComponentsFactory) drwaDomain() []byte {
	owner := &pcf.drwaIdentityOwner
	owner.mutex.Lock()
	unit := owner.unit
	owner.mutex.Unlock()
	return unit.Domain()
}

// drwaAdminEffectFunctionOf returns the destination of protected admin legs
// installed in a processing built-in container, or nil when it has none. The
// row that owns the shard's local bindings installs its binding source on it.
func drwaAdminEffectFunctionOf(builtIns vmcommon.BuiltInFunctionContainer) *drwa.AdminEffectFunction {
	installed, err := builtIns.Get(drwa.AdminEffectFunctionName)
	if err != nil {
		return nil
	}
	function, _ := installed.(*drwa.AdminEffectFunction)
	return function
}

// installDRWAAdminEffects adds the destination of protected admin legs to the
// processing built-in container of an execution shard on a DRWA deployment.
// installDRWAShardRegistry calls it with the registry it has just created.
// On any other node nothing is created. No binding
// source is installed here: the row that owns the shard's local bindings adds
// it (AdminEffectFunction.SetBindingSource), so until then every leg is
// refused.
func (pcf *processComponentsFactory) installDRWAAdminEffects(
	accounts state.AccountsAdapter,
	builtIns vmcommon.BuiltInFunctionContainer,
	registry drwa.TokenClassifier,
) (*drwa.AdminEffectFunction, error) {
	if !pcf.isDRWADeployment() {
		return nil, nil
	}

	coordinator := pcf.bootstrapComponents.ShardCoordinator()
	function, err := drwa.NewAdminEffectFunction(drwa.ArgsAdminEffectFunction{
		Accounts:    accounts,
		Marshaller:  pcf.coreData.InternalMarshalizer(),
		Hasher:      pcf.coreData.Hasher(),
		Classifier:  registry,
		BuiltIns:    builtIns,
		Shard:       coordinator.SelfId(),
		ShardOf:     coordinator.ComputeId,
		Domain:      pcf.drwaDomain,
		RecordBytes: pcf.drwaInitialProgrammeStartup.Limits.RecordBytes,
	})
	if err != nil {
		return nil, err
	}
	err = builtIns.Add(drwa.AdminEffectFunctionName, function)
	if err != nil {
		return nil, err
	}

	return function, nil
}
