package api_test

import (
	"fmt"
	"testing"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/factory/api"
	"github.com/multiversx/mx-chain-go/factory/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/shardingMocks"
	stateMocks "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
)

// SP2-25: the API query factory asks the process components for the DRWA
// query classification and installs it in the query VM and its hook. Inert
// stubs; no query is executed.

type qualSP225QueryClassifier struct {
	validatedUser, validatedPeer state.AccountsAdapter
	validations                  int
}

func (c *qualSP225QueryClassifier) ValidateAccounts(user, validator state.AccountsAdapter) error {
	c.validatedUser, c.validatedPeer = user, validator
	c.validations++
	return nil
}
func (c *qualSP225QueryClassifier) WithTokenClassification(_ state.AccountsAdapter, _ []byte,
	execute func(bool) (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	return execute(false)
}
func (c *qualSP225QueryClassifier) IsInterfaceNil() bool { return c == nil }

type qualSP225QueryAdmission struct{}

func (qualSP225QueryAdmission) AdmitBuiltIn(vmcommon.BuiltinFunction, *vmcommon.ContractCallInput) error {
	return nil
}
func (qualSP225QueryAdmission) IsInterfaceNil() bool { return false }

type qualSP225QueryComponents struct {
	*mock.ProcessComponentsMock
	classifier vm.DRWATokenClassifier
	admission  hooks.DRWABuiltInAdmission
	enforcedAt func(uint32, uint64) bool
	user, peer state.AccountsAdapter
	calls      int
}

func (c *qualSP225QueryComponents) DRWAQueryClassification(user, validator state.AccountsAdapter) (vm.DRWATokenClassifier,
	hooks.DRWABuiltInAdmission, func(uint32, uint64) bool) {
	c.calls++
	c.user, c.peer = user, validator
	return c.classifier, c.admission, c.enforcedAt
}

func TestQualSP225QueryFactoryInstallsDRWAClassification(t *testing.T) {
	always := func(uint32, uint64) bool { return true }
	components := func(shard uint32) *qualSP225QueryComponents {
		return &qualSP225QueryComponents{ProcessComponentsMock: &mock.ProcessComponentsMock{
			ShardCoord:   &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return shard }},
			EpochTrigger: &testscommon.EpochStartTriggerStub{}, RoundHandlerField: &testscommon.RoundHandlerMock{},
			NodesCoord: &shardingMocks.NodesCoordinatorMock{},
		}}
	}

	t.Run("metachain_query_vm_is_classified_on_its_own_adapter", func(t *testing.T) {
		args := createMockSCQueryElementArgs()
		args.CoreComponents.(*mock.CoreComponentsMock).EnableRoundsHandlerField = &testscommon.EnableRoundsHandlerStub{}
		peer := &stateMocks.AccountsStub{}
		args.StateComponents.(*mock.StateComponentsHolderStub).PeerAccountsCalled = func() state.AccountsAdapter { return peer }
		shared := args.StateComponents.AccountsAdapterAPI()
		classifier := &qualSP225QueryClassifier{}
		source := components(common.MetachainShardId)
		source.classifier, source.admission, source.enforcedAt = classifier, qualSP225QueryAdmission{}, always
		args.ProcessComponents = source
		_, _, err := api.CreateScQueryElement(args)
		t.Logf("query element construction on the inert fixture: %v", err)
		require.Equal(t, 1, source.calls)
		require.NotNil(t, source.user)
		require.Equal(t, 1, classifier.validations, "the System VM context validated the classifier")
		require.Same(t, source.user, classifier.validatedUser, "the classified VM reads the hook's adapter")
		require.NotSame(t, shared, classifier.validatedUser)
		require.Same(t, peer, source.peer)
		require.Same(t, peer, classifier.validatedPeer)
	})
	t.Run("metachain_without_drwa_is_the_native_factory", func(t *testing.T) {
		native, classified := createMockSCQueryElementArgs(), createMockSCQueryElementArgs()
		native.ProcessComponents = components(common.MetachainShardId).ProcessComponentsMock
		source := components(common.MetachainShardId)
		classified.ProcessComponents = source
		_, _, nativeErr := api.CreateScQueryElement(native)
		_, _, classifiedErr := api.CreateScQueryElement(classified)
		require.Equal(t, fmt.Sprint(nativeErr), fmt.Sprint(classifiedErr))
		require.Equal(t, 1, source.calls)
	})
	t.Run("shard_query_hook_receives_the_admission", func(t *testing.T) {
		native, classified := createMockSCQueryElementArgs(), createMockSCQueryElementArgs()
		native.ProcessComponents = components(0).ProcessComponentsMock
		source := components(0)
		source.admission, source.enforcedAt = qualSP225QueryAdmission{}, always
		classified.ProcessComponents = source
		_, _, nativeErr := api.CreateScQueryElement(native)
		_, _, classifiedErr := api.CreateScQueryElement(classified)
		require.Equal(t, fmt.Sprint(nativeErr), fmt.Sprint(classifiedErr))
		require.Equal(t, 1, source.calls)

		incomplete := createMockSCQueryElementArgs()
		broken := components(0)
		broken.admission = qualSP225QueryAdmission{}
		incomplete.ProcessComponents = broken
		_, _, err := api.CreateScQueryElement(incomplete)
		require.ErrorIs(t, err, hooks.ErrInvalidDRWABuiltInAdmission, "an admission without its enforcement predicate is refused")
	})
}
