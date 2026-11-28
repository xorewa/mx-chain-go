package processing

import (
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"

	factoryCore "github.com/multiversx/mx-chain-go/factory/core"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/drwa"
	processFactory "github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	nativeValidation "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
)

// isDRWADeployment is true only for a node started on an admitted DRWA
// deployment: the resolved enforcement configuration and the initial-programme
// startup whose genesis provisions the registry. Every other node keeps the
// native factories unchanged.
func (pcf *processComponentsFactory) isDRWADeployment() bool {
	return pcf.drwaConfigurationCandidate != nil && pcf.drwaInitialProgrammeStartup != nil
}

// newDRWAMetaClassification creates the classifier owner of the metachain
// processing stores. It reads no state: the first block execution reconstructs
// the registry projection from the committed store.
func (pcf *processComponentsFactory) newDRWAMetaClassification() (*drwa.MetaClassification, error) {
	if !pcf.isDRWADeployment() {
		return nil, nil
	}
	if pcf.drwaMetaClassification != nil {
		return nil, vm.ErrDRWAExecution
	}
	owner, err := drwa.NewMetaClassification(drwa.ArgsMetaClassification{
		Accounts:     pcf.state.AccountsAdapter(),
		PeerAccounts: pcf.state.PeerAccounts(),
		Coordinator:  pcf.bootstrapComponents.ShardCoordinator(),
	})
	if err != nil {
		return nil, err
	}
	pcf.drwaMetaClassification = owner
	return owner, nil
}

// createProcessingVMMeta creates the metachain processing VM factory and
// container. On a DRWA deployment it first creates the classifier owner of the
// processing stores, installs its candidate in the System VM and its
// admission in the hook, and binds the owner to the created System VM. On any
// other node the owner is nil and the factory and container are the native
// ones.
func (pcf *processComponentsFactory) createProcessingVMMeta(
	builtInFuncs vmcommon.BuiltInFunctionContainer,
	nftStorageHandler vmcommon.SimpleESDTNFTStorageHandler,
	globalSettingsHandler vmcommon.ESDTGlobalSettingsHandler,
	epochStartTrigger process.EpochStartTriggerHandler,
	headerTimeEnabledAt func(uint32, uint64) bool,
) (process.VirtualMachinesContainerFactory, process.VirtualMachinesContainer, *drwa.MetaClassification, error) {
	owner, err := pcf.newDRWAMetaClassification()
	if err != nil {
		return nil, nil, nil, err
	}

	vmFactory, err := pcf.createVMFactoryMetaWithClassifier(
		pcf.state.AccountsAdapter(),
		pcf.state.PeerAccounts(),
		builtInFuncs,
		pcf.config.SmartContractsStorage,
		nftStorageHandler,
		globalSettingsHandler,
		epochStartTrigger,
		headerTimeEnabledAt,
		drwaClassifierOf(owner),
		drwaTokenClassifierOf(owner),
	)
	if err != nil {
		return nil, nil, nil, err
	}

	vmContainer, err := vmFactory.Create()
	if err != nil {
		return nil, nil, nil, err
	}

	err = pcf.bindDRWAMetaClassification(owner, vmContainer, vmFactory.BlockChainHookImpl())
	if err != nil {
		return nil, nil, nil, err
	}

	return vmFactory, vmContainer, owner, nil
}

// drwaClassifierOf converts the optional owner into the VM factory argument
// without ever producing a typed nil.
func drwaClassifierOf(owner *drwa.MetaClassification) vm.DRWATokenClassifier {
	if owner == nil {
		return nil
	}
	return owner.Classifier()
}

// bindDRWAMetaClassification gives the owner the installed System VM, its
// block-chain hook and the provider instances of the transaction pool.
func (pcf *processComponentsFactory) bindDRWAMetaClassification(owner *drwa.MetaClassification,
	container process.VirtualMachinesContainer, hook process.BlockChainHookWithAccountsAdapter) error {
	if owner == nil {
		return nil
	}
	if check.IfNil(container) || check.IfNil(hook) {
		return vm.ErrDRWAExecution
	}
	systemVM, err := container.Get(processFactory.SystemVirtualMachine)
	if err != nil {
		return err
	}
	headers, err := drwaHeaderTimeSource(hook, pcf.state.AccountsAdapter())
	if err != nil {
		return err
	}
	source := pcf.drwaNativeValidationSource
	if source == nil {
		// No receipt-producing pool is configured: the reserved registration
		// requests then never reach the native-call path.
		source = &nativeValidation.NativeValidationSource{}
	}
	return owner.BindNative(systemVM, headers, source)
}

// drwaReadOnlyClassifier serves the metachain VMs that never commit. The same
// object classifies the System-SC calls and the built-in calls of that VM.
func (pcf *processComponentsFactory) drwaReadOnlyClassifier(user, validator state.AccountsAdapter) (vm.DRWATokenClassifier, drwa.TokenClassifier) {
	if pcf.drwaMetaClassification == nil || pcf.bootstrapComponents.ShardCoordinator().SelfId() != core.MetachainShardId {
		return nil, nil
	}
	classifier := pcf.drwaMetaClassification.ReadOnlyClassifier(user, validator)
	return classifier, classifier
}

// drwaClassificationHandlerOf is the block processor argument.
func drwaClassificationHandlerOf(owner *drwa.MetaClassification) process.DRWAClassificationHandler {
	if owner == nil {
		return nil
	}
	return owner
}

// drwaTokenClassifierOf is the built-in classifier of the metachain
// processing store: the installed candidate, through its owner.
func drwaTokenClassifierOf(owner *drwa.MetaClassification) drwa.TokenClassifier {
	if owner == nil {
		return nil
	}
	return owner
}

// drwaShardTokenClassifier is the execution-shard classifier. Its registry
// source is the finalized-registry import (tracker row SP2-22); until that
// producer exists the source is nil and every classification is unresolved.
func (pcf *processComponentsFactory) drwaShardTokenClassifier() drwa.TokenClassifier {
	if !pcf.isDRWADeployment() || pcf.bootstrapComponents.ShardCoordinator().SelfId() == core.MetachainShardId {
		return nil
	}
	if pcf.drwaShardClassification == nil {
		pcf.drwaShardClassification = drwa.NewShardClassification(pcf.drwaShardRegistrySource)
	}
	return pcf.drwaShardClassification
}

// setDRWABuiltInAdmission completes the hook arguments of a DRWA deployment:
// the admission of built-in calls by the given classifier and the enforcement
// predicate of the resolved configuration. A nil classifier changes nothing.
func (pcf *processComponentsFactory) setDRWABuiltInAdmission(argsHook *hooks.ArgBlockChainHook, classifier drwa.TokenClassifier) {
	admission, enforcedAt := drwaBuiltInAdmission(pcf.drwaConfigurationCandidate, classifier)
	if admission != nil {
		argsHook.DRWABuiltInAdmission, argsHook.DRWABuiltInEnforcedAt = admission, enforcedAt
	}
}

// drwaBuiltInAdmission returns nothing without a classifier. A classifier
// without a resolved configuration is enforced at every coordinate.
func drwaBuiltInAdmission(candidate *factoryCore.DRWAConfigurationCandidate, classifier drwa.TokenClassifier) (hooks.DRWABuiltInAdmission, func(uint32, uint64) bool) {
	admission := drwa.NewBuiltInAdmission(classifier)
	if admission == nil {
		return nil, nil
	}
	if candidate == nil {
		return admission, func(uint32, uint64) bool { return true }
	}
	return admission, candidate.Enabled
}
