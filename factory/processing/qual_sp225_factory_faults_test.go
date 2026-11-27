package processing

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/process/factory/containers"
	"github.com/multiversx/mx-chain-go/process/factory/interceptorscontainer"
	nativeValidation "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/testscommon"
	dataMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	"github.com/multiversx/mx-chain-go/vm"
)

// SP2-25: failures while the processing factory installs the classifier stop
// the construction; none leaves a node with a half-installed classifier.

func qualSP225CreateMeta(pcf *processComponentsFactory) error {
	_, _, _, err := pcf.createProcessingVMMeta(vmBuiltins.NewBuiltInFunctionContainer(), &testscommon.SimpleNFTStorageHandlerStub{},
		&testscommon.ESDTGlobalSettingsHandlerStub{}, &testscommon.EpochStartTriggerStub{}, nil)
	return err
}

func TestQualSP225ProcessingVMMetaConstructionFailures(t *testing.T) {
	store, peer := integrationtests.CreateInMemoryShardAccountsDB(), integrationtests.CreateInMemoryShardAccountsDB()

	t.Run("owner_cannot_be_created_off_the_metachain", func(t *testing.T) {
		pcf := qualSP225Factory(t, 0, true, store, peer)
		owner, err := pcf.newDRWAMetaClassification()
		require.ErrorIs(t, err, drwa.ErrInvalidRegistryRegistration)
		require.Nil(t, owner)
		require.ErrorIs(t, qualSP225CreateMeta(pcf), drwa.ErrInvalidRegistryRegistration)
	})
	t.Run("native_factory_error_is_returned", func(t *testing.T) {
		pcf := qualSP225Factory(t, core.MetachainShardId, false, store, nil)
		require.ErrorIs(t, qualSP225CreateMeta(pcf), vm.ErrNilValidatorAccountsDB)
	})
	t.Run("native_container_error_is_returned", func(t *testing.T) {
		pcf := qualSP225Factory(t, core.MetachainShardId, true, store, peer)
		pcf.systemSCConfig = &config.SystemSmartContractsConfig{}
		require.Error(t, qualSP225CreateMeta(pcf))
	})
	t.Run("deployment_without_a_receipt_pool_source", func(t *testing.T) {
		pcf := qualSP225Factory(t, core.MetachainShardId, true, store, peer)
		require.Nil(t, pcf.drwaNativeValidationSource)
		factory, container, owner, err := pcf.createProcessingVMMeta(vmBuiltins.NewBuiltInFunctionContainer(), &testscommon.SimpleNFTStorageHandlerStub{},
			&testscommon.ESDTGlobalSettingsHandlerStub{}, &testscommon.EpochStartTriggerStub{}, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = factory.BlockChainHookImpl().Close() })
		require.NotNil(t, container)
		require.NotNil(t, owner)
		require.Same(t, owner, drwaClassificationHandlerOf(owner))
		require.Same(t, owner, drwaTokenClassifierOf(owner))

		// Binding: an empty container, a hook without the header-time view.
		other, err := drwa.NewMetaClassification(drwa.ArgsMetaClassification{Accounts: store, PeerAccounts: peer,
			Coordinator: pcf.bootstrapComponents.ShardCoordinator()})
		require.NoError(t, err)
		require.Error(t, pcf.bindDRWAMetaClassification(other, containers.NewVirtualMachinesContainer(), factory.BlockChainHookImpl()))
		require.ErrorIs(t, pcf.bindDRWAMetaClassification(other, container, &testscommon.BlockChainHookStub{}), vm.ErrDRWAExecution)
	})
}

type qualSP225ReceiptPool struct {
	dataRetriever.ShardedDataCacherNotifier
	configured []*nativeValidation.NativeValidationSource
	err        error
}

func (p *qualSP225ReceiptPool) ConfigureNativeValidationSource(source *nativeValidation.NativeValidationSource) error {
	p.configured = append(p.configured, source)
	return p.err
}

// The provider instances given to the transaction pool are the ones the
// classifier owner later verifies receipts against.
func TestQualSP225NativeValidationSourceIsRetainedForTheOwner(t *testing.T) {
	store := integrationtests.CreateInMemoryShardAccountsDB()
	arguments := func(pcf *processComponentsFactory, pool dataRetriever.ShardedDataCacherNotifier) interceptorscontainer.CommonInterceptorsContainerFactoryArgs {
		return interceptorscontainer.CommonInterceptorsContainerFactoryArgs{
			CoreComponents: pcf.coreData, CryptoComponents: pcf.crypto, ShardCoordinator: pcf.bootstrapComponents.ShardCoordinator(),
			DataPool: &dataMock.PoolsHolderStub{TransactionsCalled: func() dataRetriever.ShardedDataCacherNotifier { return pool }},
		}
	}
	identity := &config.DRWADeploymentIdentityConfig{}

	t.Run("no_deployment_identity_keeps_the_native_pool", func(t *testing.T) {
		pcf := qualSP225Factory(t, core.MetachainShardId, true, store, store)
		pool := &qualSP225ReceiptPool{ShardedDataCacherNotifier: testscommon.NewShardedDataStub()}
		require.NoError(t, pcf.configureNativeValidationSource(arguments(pcf, pool)))
		require.Empty(t, pool.configured)
		require.Nil(t, pcf.drwaNativeValidationSource)
	})
	t.Run("configured_source_is_retained", func(t *testing.T) {
		pcf := qualSP225Factory(t, core.MetachainShardId, true, store, store)
		pcf.drwaDeploymentIdentity = identity
		pool := &qualSP225ReceiptPool{ShardedDataCacherNotifier: testscommon.NewShardedDataStub()}
		require.NoError(t, pcf.configureNativeValidationSource(arguments(pcf, pool)))
		require.Len(t, pool.configured, 1)
		require.NotNil(t, pcf.drwaNativeValidationSource)
		require.Equal(t, *pool.configured[0], *pcf.drwaNativeValidationSource)
		require.NotSame(t, pool.configured[0], pcf.drwaNativeValidationSource)
		require.Same(t, pcf.coreData.Hasher(), pcf.drwaNativeValidationSource.Hasher)
	})
	t.Run("refused_configuration_retains_nothing", func(t *testing.T) {
		pcf := qualSP225Factory(t, core.MetachainShardId, true, store, store)
		pcf.drwaDeploymentIdentity = identity
		pool := &qualSP225ReceiptPool{ShardedDataCacherNotifier: testscommon.NewShardedDataStub(), err: vm.ErrDRWAExecution}
		require.ErrorIs(t, pcf.configureNativeValidationSource(arguments(pcf, pool)), vm.ErrDRWAExecution)
		require.Nil(t, pcf.drwaNativeValidationSource)
	})
	t.Run("incomplete_dependencies_are_refused", func(t *testing.T) {
		pcf := qualSP225Factory(t, core.MetachainShardId, true, store, store)
		pcf.drwaDeploymentIdentity = identity
		plain := testscommon.NewShardedDataStub()
		for name, args := range map[string]interceptorscontainer.CommonInterceptorsContainerFactoryArgs{
			"no_components":             {},
			"no_transaction_pool":       arguments(pcf, nil),
			"pool_without_receipt_seam": arguments(pcf, plain),
		} {
			require.ErrorIs(t, pcf.configureNativeValidationSource(args), vm.ErrDRWAExecution, name)
		}
		require.Nil(t, pcf.drwaNativeValidationSource)
	})
}
