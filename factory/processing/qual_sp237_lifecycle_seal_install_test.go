package processing

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/batch"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/config"
	factoryMock "github.com/multiversx/mx-chain-go/factory/mock"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	consensusMock "github.com/multiversx/mx-chain-go/testscommon/consensus"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	"github.com/multiversx/mx-chain-go/testscommon/processMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
)

// SP2-37 through the node's own construction: the lifecycle seal owner of an
// execution shard on a DRWA deployment is in the processing built-in
// container, behind the real blockchain hook, and is the seal check of the
// destination of protected admin legs; the metachain node of such a
// deployment has the replication owner, installed as the owner of the setup
// family on its convergence host. Every record and binding is framed here
// with the node's own marshaller, independently of the product's codec.

const (
	qualSP237LifecyclePrefix = core.ProtectedKeyPrefix + "DRWA@lifecycle@"
	qualSP237PointerPrefix   = core.ProtectedKeyPrefix + "DRWA@currentCEB@"
	qualSP237AckPrefix       = core.ProtectedKeyPrefix + "DRWA@convergenceAck@"
)

func qualSP237Frame(t *testing.T, n *qualSP222Shard, fields ...[]byte) []byte {
	t.Helper()
	raw, err := n.pcf.coreData.InternalMarshalizer().Marshal(batch.New(fields...))
	require.NoError(t, err)
	return raw
}

func qualSP237Put(t *testing.T, n *qualSP222Shard, key, value []byte) {
	t.Helper()
	system, err := n.store.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	require.NoError(t, system.(state.UserAccountHandler).SaveKeyValue(key, value))
	require.NoError(t, n.store.SaveAccount(system))
	_, err = n.store.Commit()
	require.NoError(t, err)
}

func qualSP237Value(t *testing.T, n *qualSP222Shard, key []byte) []byte {
	t.Helper()
	system, err := n.store.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	value, _, err := system.(state.UserAccountHandler).RetrieveValue(key)
	require.NoError(t, err)
	return value
}

func qualSP237Seal(arguments ...[]byte) *vmcommon.ContractCallInput {
	return &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress),
		CallValue: big.NewInt(0), GasProvided: 500, CallType: vmData.AsynchronousCall, Arguments: arguments,
		CurrentTxHash: []byte("seal result hash")}, RecipientAddr: qualSP232System(),
		Function: drwa.LifecycleSealFunctionName}
}

func TestQualSP237SealThroughTheInstalledHook(t *testing.T) {
	native := qualSP222ShardNode(t, false)
	_, err := native.builtIns.Get(drwa.LifecycleSealFunctionName)
	require.Error(t, err, "an ordinary node has no seal call")
	seal, err := native.pcf.installDRWALifecycleSeal(native.store, native.builtIns, nil)
	require.NoError(t, err)
	require.Nil(t, seal, "and gets no seal owner")
	_, err = native.hook.ProcessBuiltInFunction(qualSP237Seal([]byte(qualSP222Fresh), make([]byte, 8), []byte("OPEN")))
	require.Error(t, err)
	require.Zero(t, native.store.JournalLen())

	n := qualSP222ShardNode(t, true)
	require.NoError(t, n.handler.BeginExecution())
	_, err = n.builtIns.Get(drwa.LifecycleSealFunctionName)
	require.NoError(t, err, "the registry installation of a DRWA shard node installs the seal call")
	destination := drwaAdminEffectFunctionOf(n.builtIns)
	require.NotNil(t, destination)
	// The seal check is already on the destination: one per destination.
	_, err = n.pcf.installDRWALifecycleSeal(n.store, n.builtIns, destination)
	require.ErrorIs(t, err, drwa.ErrInvalidAdminEffect)
	_, err = n.pcf.installDRWALifecycleSeal(nil, n.builtIns, destination)
	require.ErrorIs(t, err, drwa.ErrLifecycleSeal, "the store is required")

	// The token becomes a member by the metachain's delta, and the shard holds
	// its lifecycle record and current CEB as the activation replication
	// leaves them.
	token, epoch := []byte(qualSP222Fresh), binary.BigEndian.AppendUint64(nil, 1)
	delta := qualSP237Seal(token, make([]byte, 8))
	delta.Function = drwa.RegistryDeltaFunctionName
	_, err = n.hook.ProcessBuiltInFunction(delta)
	require.NoError(t, err)
	_, err = n.store.Commit()
	require.NoError(t, err)
	require.NoError(t, n.handler.Committed())
	hasher := n.pcf.coreData.Hasher()
	ceb := hasher.Compute("the current CEB")
	record := func(phase string) []byte { return qualSP237Frame(t, n, token, epoch, []byte(phase)) }
	lifecycleKey := append([]byte(qualSP237LifecyclePrefix), qualSP237Frame(t, n, token)...)
	qualSP237Put(t, n, lifecycleKey, record("SETUP"))
	qualSP237Put(t, n, append([]byte(qualSP237PointerPrefix), qualSP237Frame(t, n, token)...), qualSP237Frame(t, n, epoch, ceb))

	shards := n.pcf.bootstrapComponents.ShardCoordinator().NumberOfShards()
	ids := make([][]byte, shards)
	for shard := uint32(0); shard < shards; shard++ {
		ids[shard] = binary.BigEndian.AppendUint32(nil, shard)
	}
	set := qualSP237Frame(t, n, ids...)
	binding := qualSP237Frame(t, n, []byte("SETUP_LIFECYCLE"), hasher.Compute(string(qualSP237Frame(t, n, []byte("SETUP_LIFECYCLE"), token, epoch, ceb))),
		ceb, []byte("SETUP_SEALED"), token, epoch, hasher.Compute(string(record("SETUP_SEALED"))), hasher.Compute("dependencies"),
		hasher.Compute(string(set)), set, qualSP237Frame(t, n, token, epoch, ceb), hasher.Compute(string(record("SETUP"))))

	refused := func(label string, input *vmcommon.ContractCallInput) {
		t.Helper()
		root, rootErr := n.store.RootHash()
		require.NoError(t, rootErr)
		output, callErr := n.hook.ProcessBuiltInFunction(input)
		require.ErrorIs(t, callErr, drwa.ErrLifecycleSeal, label)
		require.Nil(t, output, label)
		after, rootErr := n.store.RootHash()
		require.NoError(t, rootErr)
		require.Equal(t, root, after, label)
	}
	// Copied into a user transaction, the same bytes are no seal.
	user := qualSP237Seal(token, epoch, []byte("SETUP_SEALED"), binding)
	user.CallerAddr, user.CallType = bytes.Clone(n.sender), vmData.DirectCall
	refused("user transaction", user)
	refused("OPEN before the seal", qualSP237Seal(token, epoch, []byte("OPEN")))
	altered := bytes.Clone(binding)
	altered[len(altered)-1] ^= 1
	refused("altered binding", qualSP237Seal(token, epoch, []byte("SETUP_SEALED"), altered))

	// The real hook hands the metachain's call to the owner: sealed, and
	// acknowledged in the same call.
	output, err := n.hook.ProcessBuiltInFunction(qualSP237Seal(token, epoch, []byte("SETUP_SEALED"), binding))
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, output.ReturnCode)
	require.Equal(t, uint64(500), output.GasRemaining)
	require.Equal(t, record("SETUP_SEALED"), qualSP237Value(t, n, lifecycleKey))
	require.Equal(t, hasher.Compute(string(qualSP237Frame(t, n, binding, binary.BigEndian.AppendUint32(nil, 0)))),
		qualSP237Value(t, n, append([]byte(qualSP237AckPrefix), hasher.Compute(string(binding))...)))
	sealed, err := n.store.Commit()
	require.NoError(t, err)
	_, err = n.hook.ProcessBuiltInFunction(qualSP237Seal(token, epoch, []byte("SETUP_SEALED"), binding))
	require.NoError(t, err)
	again, err := n.store.Commit()
	require.NoError(t, err)
	require.Equal(t, sealed, again, "the same seal again writes nothing")
	_, err = n.hook.ProcessBuiltInFunction(qualSP237Seal(token, epoch, []byte("OPEN")))
	require.NoError(t, err)
	require.Equal(t, record("OPEN"), qualSP237Value(t, n, lifecycleKey))

	// A container that already has a function under the seal's name: the
	// registry installation of the node fails as a whole.
	taken := qualSP225BuiltIns(t, n.pcf, n.store).BuiltInFunctionContainer()
	require.NoError(t, taken.Add(drwa.LifecycleSealFunctionName, destination))
	unbuilt := qualSP225Factory(t, 0, true, n.store, integrationtests.CreateInMemoryShardAccountsDB())
	handler, err := unbuilt.installDRWAShardRegistry(n.store, taken)
	require.Error(t, err)
	require.Nil(t, handler)
	require.Nil(t, unbuilt.drwaShardRegistrySource)

	// A container that already has another function under the name.
	other := qualSP225BuiltIns(t, n.pcf, n.store).BuiltInFunctionContainer()
	fresh, err := n.pcf.installDRWAAdminEffects(n.store, other, n.pcf.drwaShardRegistrySource)
	require.NoError(t, err)
	require.NoError(t, other.Add(drwa.LifecycleSealFunctionName, fresh))
	_, err = n.pcf.installDRWALifecycleSeal(n.store, other, fresh)
	require.Error(t, err, "one seal call per container")
}

func TestQualSP237SealOriginExistsOnlyOnTheMetachainOfADRWADeployment(t *testing.T) {
	accounts := &stateMock.AccountsStub{}
	validator := &processMocks.HeaderValidatorMock{}
	limits := config.DRWAInitialProgrammeLimits{RecordBytes: 4096, AggregateBytes: 1 << 16,
		Records: 100, RetainedBytes: 1 << 20, NewRecordsPerEpoch: 10}

	meta, _ := qualSP222Factory(t)
	meta.bootstrapComponents = &qualSP222Bootstrap{coordinator: &testscommon.ShardsCoordinatorMock{CurrentShard: core.MetachainShardId, NoShards: 3}}
	meta.coreData.(*factoryMock.CoreComponentsMock).EnableEpochsHandlerField = enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	meta.config.StateTriesConfig.MaxStateTrieLevelInMemory = 5
	meta.drwaConfigurationCandidate, _, _ = qualS1OverlayCandidate(t, 12)
	meta.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{Limits: limits}
	meta.drwaHeaderProofVerifier = &consensusMock.HeaderSigVerifierMock{}
	owner, err := meta.newDRWAFinalityImport(accounts, validator)
	require.NoError(t, err)
	installed, isMeta := owner.(*drwaMetaFinalityImport)
	require.True(t, isMeta)
	seal := installed.DRWALifecycleSealOrigin()
	require.NotNil(t, seal)
	require.False(t, seal.IsInterfaceNil())

	// It is the owner of the setup family on the node's host: the family is
	// taken, and installing it a second time is refused.
	host := installed.DRWAConvergenceHost()
	require.Error(t, host.SetFamilyOwner(drwa.ConvergenceFamilySetup, seal))
	_, err = meta.installDRWALifecycleSealOrigin(accounts, host, installed.DRWACarrierFunding())
	require.Error(t, err)
	_, err = meta.installDRWALifecycleSealOrigin(accounts, host, nil)
	require.ErrorIs(t, err, drwa.ErrLifecycleSeal, "the funding owner is required")
	// No other family got an owner here.
	require.NoError(t, host.SetFamilyOwner(drwa.ConvergenceFamilyRetirement, seal))

	// An execution shard has no origin.
	shard, _ := qualSP222Factory(t)
	shard.drwaConfigurationCandidate, _, _ = qualS1OverlayCandidate(t, 12)
	shard.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{Limits: limits}
	shard.drwaHeaderProofVerifier = &consensusMock.HeaderSigVerifierMock{}
	owner, err = shard.newDRWAFinalityImport(accounts, validator)
	require.NoError(t, err)
	_, isMeta = owner.(*drwaMetaFinalityImport)
	require.False(t, isMeta)
}
