package processing

import (
	"bytes"
	"errors"
	"math/big"
	"reflect"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/guardianMocks"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	"github.com/multiversx/mx-chain-go/vm"
)

// SP2-25, tracker carry "regulated restrictions on shard built-in routes land
// here": the production shard VM factory puts the classification in front of
// the built-in dispatch. Real account store, the real pinned built-in
// functions, the real hook created by createVMFactoryShard. The registry source
// stands for the finalized-registry import, which has no production producer
// yet (SP2-22); without it the classification is unresolved. Inert fixtures.

type qualSP225RegistrySource struct {
	regulated map[string]bool
	err       error
	asked     int
}

func (s *qualSP225RegistrySource) ClassifyToken(tokenID []byte) (bool, error) {
	s.asked++
	if s.err != nil {
		return false, s.err
	}
	return s.regulated[string(tokenID)], nil
}
func (s *qualSP225RegistrySource) IsInterfaceNil() bool { return s == nil }

type qualSP225Shard struct {
	pcf     *processComponentsFactory
	store   *state.AccountsDB
	hook    *hooks.BlockChainHookImpl
	source  *qualSP225RegistrySource
	sender  []byte
	another []byte
}

func qualSP225TokenKey(token string) []byte {
	return []byte(core.ProtectedKeyPrefix + core.ESDTKeyIdentifier + token)
}

// qualSP225ShardStore holds one account with a fungible balance of both tokens
// and the local mint role for both.
func qualSP225ShardStore(t *testing.T, sender []byte) *state.AccountsDB {
	t.Helper()
	db := integrationtests.CreateInMemoryShardAccountsDB()
	marshaller := &marshal.GogoProtoMarshalizer{}
	account, err := db.LoadAccount(sender)
	require.NoError(t, err)
	user := account.(state.UserAccountHandler)
	for _, token := range []string{qualSP225Regulated, qualSP225Ordinary} {
		balance, marshalErr := marshaller.Marshal(&esdt.ESDigitalToken{Type: uint32(core.Fungible), Value: big.NewInt(100)})
		require.NoError(t, marshalErr)
		require.NoError(t, user.SaveKeyValue(qualSP225TokenKey(token), balance))
		roles, marshalErr := marshaller.Marshal(&esdt.ESDTRoles{Roles: [][]byte{[]byte(core.ESDTRoleLocalMint), []byte(core.ESDTRoleLocalBurn)}})
		require.NoError(t, marshalErr)
		require.NoError(t, user.SaveKeyValue([]byte(core.ProtectedKeyPrefix+core.ESDTRoleIdentifier+core.ESDTKeyIdentifier+token), roles))
	}
	require.NoError(t, db.SaveAccount(user))
	_, err = db.Commit()
	require.NoError(t, err)
	return db
}

func qualSP225BuiltIns(t *testing.T, pcf *processComponentsFactory, store *state.AccountsDB) vmcommon.BuiltInFunctionFactory {
	t.Helper()
	gas := make(map[string]map[string]uint64)
	for name, value := range map[string]interface{}{"BaseOperationCost": vmcommon.BaseOperationCost{}, "BuiltInCost": vmcommon.BuiltInCost{}} {
		gas[name] = make(map[string]uint64)
		typ := reflect.TypeOf(value)
		for i := 0; i < typ.NumField(); i++ {
			gas[name][typ.Field(i).Name] = 7
		}
	}
	creator, err := vmBuiltins.NewBuiltInFunctionsCreator(vmBuiltins.ArgsCreateBuiltInFunctionContainer{
		Accounts: store, Marshalizer: &marshal.GogoProtoMarshalizer{}, ShardCoordinator: pcf.bootstrapComponents.ShardCoordinator(),
		MapDNSAddresses: map[string]struct{}{}, MapDNSV2Addresses: map[string]struct{}{}, GasMap: gas,
		EnableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(vmBuiltins.SaveToSystemAccountFlag, vmBuiltins.SendAlwaysFlag,
			vmBuiltins.ESDTNFTImprovementV1Flag, vmBuiltins.EGLDInESDTMultiTransferFlag, vmBuiltins.CheckTransferFlag, vmBuiltins.CheckCorrectTokenIDForTransferRoleFlag),
		GuardedAccountHandler: &guardianMocks.GuardedAccountHandlerStub{}, MaxNumOfAddressesForTransferRole: 100, ConfigAddress: bytes.Repeat([]byte{9}, 32),
	})
	require.NoError(t, err)
	require.NoError(t, creator.CreateBuiltInFunctionContainer())
	return creator
}

// qualSP225ShardNode builds the hook through the production shard VM factory.
// source nil is the production state of this row; withSource false builds the
// node without DRWA.
func qualSP225ShardNode(t *testing.T, deployment bool, source *qualSP225RegistrySource) *qualSP225Shard {
	t.Helper()
	sender, another := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	store := qualSP225ShardStore(t, sender)
	pcf := qualSP225Factory(t, 0, deployment, store, integrationtests.CreateInMemoryShardAccountsDB())
	if source != nil {
		pcf.drwaShardRegistrySource = source
	}
	builtIns := qualSP225BuiltIns(t, pcf, store)
	factory, err := pcf.createVMFactoryShard(store, &testscommon.MissingTrieNodesNotifierStub{}, builtIns.BuiltInFunctionContainer(),
		&testscommon.ESDTTransferParserStub{}, &sync.RWMutex{}, pcf.config.SmartContractsStorage, builtIns.NFTStorageHandler(),
		builtIns.ESDTGlobalSettingsHandler(), &testscommon.EpochStartTriggerStub{})
	require.NoError(t, err)
	hook := factory.BlockChainHookImpl().(*hooks.BlockChainHookImpl)
	t.Cleanup(func() { _ = hook.Close() })
	require.NoError(t, builtIns.SetPayableHandler(hook))
	require.NoError(t, hook.SetCurrentHeader(&block.Header{Epoch: 12, Round: 440, Nonce: 5}))
	return &qualSP225Shard{pcf: pcf, store: store, hook: hook, source: source, sender: sender, another: another}
}

func (n *qualSP225Shard) call(function string, recipient []byte, arguments ...[]byte) *vmcommon.ContractCallInput {
	return &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(n.sender), CallValue: big.NewInt(0),
		GasProvided: 1000000, Arguments: arguments}, RecipientAddr: bytes.Clone(recipient), Function: function}
}

func (n *qualSP225Shard) balance(t *testing.T, address []byte, token string) int64 {
	t.Helper()
	account, err := n.store.GetExistingAccount(address)
	if errors.Is(err, state.ErrAccNotFound) {
		return 0
	}
	require.NoError(t, err)
	raw, _, err := account.(state.UserAccountHandler).RetrieveValue(qualSP225TokenKey(token))
	require.NoError(t, err)
	if len(raw) == 0 {
		return 0
	}
	value := &esdt.ESDigitalToken{}
	require.NoError(t, (&marshal.GogoProtoMarshalizer{}).Unmarshal(value, raw))
	return value.Value.Int64()
}

// The routes of this test: one transfer route and two supply routes.
func (n *qualSP225Shard) routes(token string) map[string]*vmcommon.ContractCallInput {
	return map[string]*vmcommon.ContractCallInput{
		"transfer":       n.call(core.BuiltInFunctionESDTTransfer, n.another, []byte(token), big.NewInt(10).Bytes()),
		"multi_transfer": n.call(core.BuiltInFunctionMultiESDTNFTTransfer, n.sender, n.another, []byte{1}, []byte(token), []byte{0}, big.NewInt(10).Bytes()),
		"local_mint":     n.call(core.BuiltInFunctionESDTLocalMint, n.sender, []byte(token), big.NewInt(10).Bytes()),
		"local_burn":     n.call(core.BuiltInFunctionESDTLocalBurn, n.sender, []byte(token), big.NewInt(10).Bytes()),
	}
}

func TestQualSP225InstalledShardRoutes(t *testing.T) {
	resolved := func() *qualSP225RegistrySource {
		return &qualSP225RegistrySource{regulated: map[string]bool{qualSP225Regulated: true}}
	}
	for route := range (&qualSP225Shard{}).routes(qualSP225Ordinary) {
		t.Run(route+"/regulated_is_denied_before_any_effect", func(t *testing.T) {
			node := qualSP225ShardNode(t, true, resolved())
			output, err := node.hook.ProcessBuiltInFunction(node.routes(qualSP225Regulated)[route])
			require.ErrorIs(t, err, drwa.ErrRegulatedTokenOperation)
			require.NotErrorIs(t, err, vm.ErrDRWAExecution)
			require.Nil(t, output)
			require.Zero(t, node.store.JournalLen())
			require.EqualValues(t, 100, node.balance(t, node.sender, qualSP225Regulated))
			require.Zero(t, node.balance(t, node.another, qualSP225Regulated))
		})
		t.Run(route+"/unresolved_is_never_ordinary", func(t *testing.T) {
			for name, source := range map[string]*qualSP225RegistrySource{
				"no_registry_source": nil, "source_read_failure": {err: errors.New("inert registry read failure")},
			} {
				node := qualSP225ShardNode(t, true, source)
				for _, token := range []string{qualSP225Ordinary, qualSP225Regulated} {
					output, err := node.hook.ProcessBuiltInFunction(node.routes(token)[route])
					require.ErrorIs(t, err, vm.ErrDRWAExecution, name)
					require.Nil(t, output)
					require.Zero(t, node.store.JournalLen())
					require.EqualValues(t, 100, node.balance(t, node.sender, token))
				}
				if source == nil {
					_, err := node.hook.ProcessBuiltInFunction(node.routes(qualSP225Ordinary)[route])
					require.ErrorIs(t, err, drwa.ErrClassificationUnresolved)
				}
			}
		})
		t.Run(route+"/ordinary_equals_the_node_without_drwa", func(t *testing.T) {
			// INV-0: same pre-state, same call; complete output, error, gas
			// and committed state delta are equal.
			enabled, native := qualSP225ShardNode(t, true, resolved()), qualSP225ShardNode(t, false, nil)
			for _, token := range []string{qualSP225Ordinary, "UNKNOWN-abcdef"} {
				expected, nativeErr := native.hook.ProcessBuiltInFunction(native.routes(token)[route])
				actual, enabledErr := enabled.hook.ProcessBuiltInFunction(enabled.routes(token)[route])
				require.Equal(t, nativeErr, enabledErr, token)
				require.Equal(t, expected, actual, token)
			}
			require.Positive(t, enabled.source.asked)
			nativeRoot, err := native.store.Commit()
			require.NoError(t, err)
			enabledRoot, err := enabled.store.Commit()
			require.NoError(t, err)
			require.Equal(t, nativeRoot, enabledRoot)
			if route == "transfer" || route == "multi_transfer" {
				require.EqualValues(t, 90, enabled.balance(t, enabled.sender, qualSP225Ordinary), "the ordinary effect really happened")
				require.EqualValues(t, 10, enabled.balance(t, enabled.another, qualSP225Ordinary))
			}
		})
		t.Run(route+"/before_enforcement_is_native", func(t *testing.T) {
			enabled, native := qualSP225ShardNode(t, true, nil), qualSP225ShardNode(t, false, nil)
			for _, header := range []*block.Header{{Epoch: 11, Round: 440}, {Epoch: 12, Round: 439}} {
				require.NoError(t, enabled.hook.SetCurrentHeader(header))
				require.NoError(t, native.hook.SetCurrentHeader(header))
				expected, nativeErr := native.hook.ProcessBuiltInFunction(native.routes(qualSP225Regulated)[route])
				actual, enabledErr := enabled.hook.ProcessBuiltInFunction(enabled.routes(qualSP225Regulated)[route])
				require.Equal(t, nativeErr, enabledErr)
				require.Equal(t, expected, actual)
			}
		})
	}
}

// A node without the DRWA deployment has no classifier and no admission.
func TestQualSP225FactoryWithoutDRWAIsNative(t *testing.T) {
	for _, shard := range []uint32{0, core.MetachainShardId} {
		store := integrationtests.CreateInMemoryShardAccountsDB()
		pcf := qualSP225Factory(t, shard, false, store, integrationtests.CreateInMemoryShardAccountsDB())
		require.False(t, pcf.isDRWADeployment())
		owner, err := pcf.newDRWAMetaClassification()
		require.NoError(t, err)
		require.Nil(t, owner)
		require.Nil(t, drwaClassifierOf(owner))
		require.Nil(t, drwaTokenClassifierOf(owner))
		require.Nil(t, drwaClassificationHandlerOf(owner))
		require.Nil(t, pcf.drwaShardTokenClassifier())
		classifier, tokens := pcf.drwaReadOnlyClassifier(store, store)
		require.Nil(t, classifier)
		require.Nil(t, tokens)
		require.NoError(t, pcf.bindDRWAMetaClassification(nil, nil, nil))
		args := hooks.ArgBlockChainHook{}
		pcf.setDRWABuiltInAdmission(&args, nil)
		require.Nil(t, args.DRWABuiltInAdmission)
		require.Nil(t, args.DRWABuiltInEnforcedAt)
	}

	// Only one half of the deployment is not a deployment.
	store := integrationtests.CreateInMemoryShardAccountsDB()
	half := qualSP225Factory(t, 0, true, store, store)
	half.drwaInitialProgrammeStartup = nil
	require.False(t, half.isDRWADeployment())
	require.Nil(t, half.drwaShardTokenClassifier())
}

func TestQualSP225FactoryDeploymentWiring(t *testing.T) {
	store, peer := integrationtests.CreateInMemoryShardAccountsDB(), integrationtests.CreateInMemoryShardAccountsDB()
	meta := qualSP225Factory(t, core.MetachainShardId, true, store, peer)
	require.True(t, meta.isDRWADeployment())
	require.Nil(t, meta.drwaShardTokenClassifier(), "the metachain uses its own candidate")
	owner, err := meta.newDRWAMetaClassification()
	require.NoError(t, err)
	require.NotNil(t, owner)
	_, err = meta.newDRWAMetaClassification()
	require.ErrorIs(t, err, vm.ErrDRWAExecution, "one owner per node")
	require.ErrorIs(t, meta.bindDRWAMetaClassification(owner, nil, nil), vm.ErrDRWAExecution)

	shard := qualSP225Factory(t, 1, true, store, peer)
	classifier := shard.drwaShardTokenClassifier()
	require.NotNil(t, classifier)
	require.Same(t, classifier, shard.drwaShardTokenClassifier())
	_, err = classifier.ClassifyToken([]byte(qualSP225Ordinary))
	require.ErrorIs(t, err, drwa.ErrClassificationUnresolved, "no production registry source exists yet")
	args := hooks.ArgBlockChainHook{}
	shard.setDRWABuiltInAdmission(&args, classifier)
	require.NotNil(t, args.DRWABuiltInAdmission)
	require.True(t, args.DRWABuiltInEnforcedAt(12, 440))
	require.False(t, args.DRWABuiltInEnforcedAt(11, 440))
	require.False(t, args.DRWABuiltInEnforcedAt(12, 439))
	readOnly, tokens := shard.drwaReadOnlyClassifier(store, peer)
	require.Nil(t, readOnly)
	require.Nil(t, tokens)

	unconfigured, always := drwaBuiltInAdmission(nil, classifier)
	require.NotNil(t, unconfigured)
	require.True(t, always(0, 0), "a classifier without a resolved configuration is enforced everywhere")
	none, never := drwaBuiltInAdmission(shard.drwaConfigurationCandidate, nil)
	require.Nil(t, none)
	require.Nil(t, never)

	// The API query path of a shard receives the same admission.
	managed := &managedProcessComponents{processComponents: &processComponents{
		drwaShardClassification: shard.drwaShardClassification, drwaConfigurationCandidate: shard.drwaConfigurationCandidate}}
	metaClassifier, admission, enforcedAt := managed.DRWAQueryClassification(store, peer)
	require.Nil(t, metaClassifier)
	require.NotNil(t, admission)
	require.True(t, enforcedAt(12, 440))
}

// AN-03: the burn-role, type, role and transfer-role fan-out that the ESDT
// System SC sends to the shards is classified before its first effect too. On
// this public dispatch a regulated identifier is refused and an unresolved one
// is never applied; an ordinary one is the native result.
func TestQualSP225InstalledShardSystemFanOutIsClassifiedFirst(t *testing.T) {
	fanOut := map[string][][]byte{
		vmcommon.BuiltInFunctionESDTSetBurnRoleForAll:         nil,
		vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll:       nil,
		core.ESDTSetTokenType:                                 {[]byte(core.FungibleESDT)},
		core.BuiltInFunctionSetESDTRole:                       {[]byte(core.ESDTRoleLocalMint)},
		core.BuiltInFunctionUnSetESDTRole:                     {[]byte(core.ESDTRoleLocalMint)},
		vmcommon.BuiltInFunctionESDTTransferRoleAddAddress:    {bytes.Repeat([]byte{4}, 32)},
		core.BuiltInFunctionESDTFreeze:                        nil,
		core.BuiltInFunctionESDTPause:                         nil,
		core.BuiltInFunctionESDTSetLimitedTransfer:            nil,
		vmcommon.BuiltInFunctionESDTTransferRoleDeleteAddress: {bytes.Repeat([]byte{4}, 32)},
	}
	systemCall := func(n *qualSP225Shard, function, token string) *vmcommon.ContractCallInput {
		input := n.call(function, n.sender, append([][]byte{[]byte(token)}, fanOut[function]...)...)
		input.CallerAddr = bytes.Clone(core.ESDTSCAddress)
		if function != core.BuiltInFunctionSetESDTRole && function != core.BuiltInFunctionUnSetESDTRole && function != core.BuiltInFunctionESDTFreeze {
			input.RecipientAddr = bytes.Clone(core.SystemAccountAddress)
		}
		return input
	}
	for function := range fanOut {
		t.Run(function, func(t *testing.T) {
			regulatedSource := &qualSP225RegistrySource{regulated: map[string]bool{qualSP225Regulated: true}}
			enabled, native, unresolved := qualSP225ShardNode(t, true, regulatedSource), qualSP225ShardNode(t, false, nil), qualSP225ShardNode(t, true, nil)

			output, err := enabled.hook.ProcessBuiltInFunction(systemCall(enabled, function, qualSP225Regulated))
			require.ErrorIs(t, err, drwa.ErrRegulatedTokenOperation)
			require.Nil(t, output)
			require.Zero(t, enabled.store.JournalLen())

			output, err = unresolved.hook.ProcessBuiltInFunction(systemCall(unresolved, function, qualSP225Ordinary))
			require.ErrorIs(t, err, vm.ErrDRWAExecution)
			require.Nil(t, output)
			require.Zero(t, unresolved.store.JournalLen())

			expected, nativeErr := native.hook.ProcessBuiltInFunction(systemCall(native, function, qualSP225Ordinary))
			actual, enabledErr := enabled.hook.ProcessBuiltInFunction(systemCall(enabled, function, qualSP225Ordinary))
			require.Equal(t, nativeErr, enabledErr)
			require.Equal(t, expected, actual)
			nativeRoot, err := native.store.Commit()
			require.NoError(t, err)
			enabledRoot, err := enabled.store.Commit()
			require.NoError(t, err)
			require.Equal(t, nativeRoot, enabledRoot)
		})
	}
}
