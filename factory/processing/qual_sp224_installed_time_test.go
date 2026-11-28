package processing

import (
	"math/big"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	factoryMock "github.com/multiversx/mx-chain-go/factory/mock"
	"github.com/multiversx/mx-chain-go/process/drwa"
	drwaTime "github.com/multiversx/mx-chain-go/process/drwa/headertime"
	processFactory "github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	nativeValidation "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	"github.com/multiversx/mx-chain-go/vm"
)

// SP2-24 on the hooks the production VM factories build. The deployment is the
// SP2-25 fixture (enforcement from epoch 12, asynchronous execution from round
// 440) with Supernova enabled from epoch 12, so a V3 header at (12, 440) is the
// first one whose evaluation issues a typed context.

func qualSP224SupernovaFrom12(pcf *processComponentsFactory) {
	base := qualSP225Flags()
	flags := qualSP225Flags()
	flags.IsFlagEnabledInEpochCalled = func(flag core.EnableEpochFlag, epoch uint32) bool {
		if flag == common.SupernovaFlag {
			return epoch >= 12
		}
		return base.IsFlagEnabled(flag)
	}
	pcf.coreData.(*factoryMock.CoreComponentsMock).EnableEpochsHandlerField = flags
}

func qualSP224MetaNode(t *testing.T, deployment bool, user *state.AccountsDB) *qualSP225Node {
	t.Helper()
	peer := integrationtests.CreateInMemoryShardAccountsDB()
	pcf := qualSP225Factory(t, core.MetachainShardId, deployment, user, peer)
	qualSP224SupernovaFrom12(pcf)
	if deployment {
		pcf.drwaNativeValidationSource = &nativeValidation.NativeValidationSource{
			ProtoMarshalizer: &marshal.GogoProtoMarshalizer{}, Hasher: blake2b.NewBlake2b(), ArgsParser: smartContract.NewArgumentParser(),
			EnableEpochsHandler: qualSP225Flags(), ChainID: "inert-chain",
		}
	}
	enabledAt, err := pcf.drwaHeaderTimeEnabledAt()
	require.NoError(t, err)
	factory, container, owner, err := pcf.createProcessingVMMeta(vmBuiltins.NewBuiltInFunctionContainer(),
		&testscommon.SimpleNFTStorageHandlerStub{}, &testscommon.ESDTGlobalSettingsHandlerStub{}, &testscommon.EpochStartTriggerStub{}, enabledAt)
	require.NoError(t, err)
	hook := factory.BlockChainHookImpl().(*hooks.BlockChainHookImpl)
	t.Cleanup(func() { _ = hook.Close() })
	system, err := container.Get(processFactory.SystemVirtualMachine)
	require.NoError(t, err)
	return &qualSP225Node{pcf: pcf, user: user, peer: peer, factory: factory, system: system, hook: hook, owner: owner}
}

func qualSP224ShardNode(t *testing.T, deployment bool, source *qualSP225RegistrySource) *qualSP225Shard {
	t.Helper()
	sender, another := make([]byte, 32), make([]byte, 32)
	for i := range sender {
		sender[i], another[i] = 1, 2
	}
	store := qualSP225ShardStore(t, sender)
	pcf := qualSP225Factory(t, 0, deployment, store, integrationtests.CreateInMemoryShardAccountsDB())
	qualSP224SupernovaFrom12(pcf)
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
	return &qualSP225Shard{pcf: pcf, store: store, hook: hook, source: source, sender: sender, another: another}
}

func qualSP224Header(shard uint32, epoch uint32, round, milliseconds uint64) data.HeaderHandler {
	if shard == core.MetachainShardId {
		return &block.MetaBlockV3{Epoch: epoch, Round: round, Nonce: 5, TimestampMs: milliseconds, ChainID: []byte("SP2-24 fixture")}
	}
	return &block.HeaderV3{Epoch: epoch, ShardID: shard, Round: round, Nonce: 5, TimestampMs: milliseconds, ChainID: []byte("SP2-24 fixture")}
}

// qualSP224Evaluate installs a header exactly as the block processors do
// (process/block beginEvaluatedHeaderTime: the candidate header variant).
func qualSP224Evaluate(t *testing.T, hook *hooks.BlockChainHookImpl, header data.HeaderHandler) (*drwaTime.HeaderTimeContext, func(), error) {
	t.Helper()
	require.NoError(t, hook.SetEpochStartHeader(header))
	install, end, err := hook.BeginDRWAHeaderEvaluationForHeader(header)
	require.NoError(t, err)
	t.Cleanup(end)
	require.NoError(t, install(header))
	context, err := hook.EvaluatedHeaderTimeContext()
	return context, end, err
}

// The one production way to obtain a time source returns the processing hook
// itself and refuses everything else.
func TestQualSP224FactoryTimeSourceIsTheProcessingHook(t *testing.T) {
	user := qualSP225GenesisStore(t)
	node := qualSP224MetaNode(t, true, user)
	source, err := drwaHeaderTimeSource(node.factory.BlockChainHookImpl(), user)
	require.NoError(t, err)
	require.Same(t, node.hook, source, "the source is the hook the block processor installs headers in")
	require.True(t, node.hook.DRWAHeaderTimeBound())

	refused := func(source drwa.HeaderTimeSource, err error) {
		t.Helper()
		require.ErrorIs(t, err, vm.ErrDRWAExecution)
		require.Nil(t, source)
	}
	refused(drwaHeaderTimeSource(nil, user))
	refused(drwaHeaderTimeSource((*hooks.BlockChainHookImpl)(nil), user))
	refused(drwaHeaderTimeSource(&testscommon.BlockChainHookStub{}, user))
	refused(drwaHeaderTimeSource(node.hook, nil))
	refused(drwaHeaderTimeSource(node.hook, node.peer))
	refused(drwaHeaderTimeSource(node.hook, integrationtests.CreateInMemoryShardAccountsDB()))

	// A hook of the same factory code built without the per-header predicate
	// (as the API and simulation paths build it) is not a time source.
	plain := qualSP225Factory(t, core.MetachainShardId, true, user, node.peer)
	qualSP224SupernovaFrom12(plain)
	factory, err := plain.createVMFactoryMeta(user, node.peer, vmBuiltins.NewBuiltInFunctionContainer(), plain.config.SmartContractsStorage,
		&testscommon.SimpleNFTStorageHandlerStub{}, &testscommon.ESDTGlobalSettingsHandlerStub{}, &testscommon.EpochStartTriggerStub{}, nil)
	require.NoError(t, err)
	other := factory.BlockChainHookImpl().(*hooks.BlockChainHookImpl)
	t.Cleanup(func() { _ = other.Close() })
	require.False(t, other.DRWAHeaderTimeBound())
	refused(drwaHeaderTimeSource(other, user))
	require.False(t, (*hooks.BlockChainHookImpl)(nil).DRWAHeaderTimeBound())

	// The deployment cannot be assembled around such a hook either.
	_, _, _, err = plain.createProcessingVMMeta(vmBuiltins.NewBuiltInFunctionContainer(), &testscommon.SimpleNFTStorageHandlerStub{},
		&testscommon.ESDTGlobalSettingsHandlerStub{}, &testscommon.EpochStartTriggerStub{}, nil)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
}

// Activation by header epoch and round at its bounds, on the hooks of both
// production factories: the typed context exists from (12, 440) on and carries
// the header's milliseconds; one step earlier in either coordinate there is no
// context, while the ordinary accessor keeps answering.
func TestQualSP224InstalledActivationBounds(t *testing.T) {
	for _, shard := range []uint32{0, core.MetachainShardId} {
		for _, tc := range []struct {
			name   string
			epoch  uint32
			round  uint64
			active bool
		}{
			{"epoch_before_enforcement", 11, 440, false},
			{"round_before_asynchronous_execution", 12, 439, false},
			{"first_enforced_header", 12, 440, true},
			{"later_round", 12, 441, true},
			{"later_epoch", 13, 440, true},
		} {
			t.Run(map[uint32]string{0: "shard", core.MetachainShardId: "meta"}[shard]+"/"+tc.name, func(t *testing.T) {
				var hook *hooks.BlockChainHookImpl
				if shard == core.MetachainShardId {
					hook = qualSP224MetaNode(t, true, qualSP225GenesisStore(t)).hook
				} else {
					hook = qualSP224ShardNode(t, true, nil).hook
				}
				header := qualSP224Header(shard, tc.epoch, tc.round, 1234567)
				context, end, err := qualSP224Evaluate(t, hook, header)
				if !tc.active {
					require.ErrorIs(t, err, drwaTime.ErrInactiveHeaderTime)
					require.Nil(t, context)
					if tc.epoch >= 12 {
						require.EqualValues(t, 1234567, hook.CurrentTimeStampMs())
					}
					return
				}
				require.NoError(t, err)
				at, epoch, release, err := context.Lease()
				require.NoError(t, err)
				release()
				require.EqualValues(t, 1234567, at)
				require.Equal(t, tc.epoch, epoch)
				_, locus := context.HeaderIdentity()
				require.Equal(t, shard, locus)
				end()
				_, err = context.Milliseconds()
				require.ErrorIs(t, err, drwaTime.ErrInactiveHeaderTime, "the context ends with its block")
				_, err = hook.EvaluatedHeaderTimeContext()
				require.ErrorIs(t, err, drwaTime.ErrInactiveHeaderTime)
			})
		}
	}
}

// INV-0 with the time source installed: with a live typed context and no DRWA
// operation, ordinary built-in calls on the shard give the same output
// (result, gas, logs), error and committed state as (a) the same deployment
// with the header installed by the plain setter and (b) a node without DRWA.
func TestQualSP224OrdinaryShardRoutesWithTimeSourceInstalled(t *testing.T) {
	resolved := func() *qualSP225RegistrySource {
		return &qualSP225RegistrySource{regulated: map[string]bool{qualSP225Regulated: true}}
	}
	for route := range (&qualSP225Shard{}).routes(qualSP225Ordinary) {
		t.Run(route, func(t *testing.T) {
			timed, plain, native := qualSP224ShardNode(t, true, resolved()), qualSP224ShardNode(t, true, resolved()), qualSP224ShardNode(t, false, nil)
			header := func() data.HeaderHandler { return qualSP224Header(0, 12, 440, 1234567) }
			context, _, err := qualSP224Evaluate(t, timed.hook, header())
			require.NoError(t, err)
			for _, other := range []*qualSP225Shard{plain, native} {
				require.NoError(t, other.hook.SetEpochStartHeader(header()))
				require.NoError(t, other.hook.SetCurrentHeader(header()))
				_, err = other.hook.EvaluatedHeaderTimeContext()
				require.Error(t, err)
			}
			for _, token := range []string{qualSP225Ordinary, "UNKNOWN-abcdef"} {
				expected, nativeErr := native.hook.ProcessBuiltInFunction(native.routes(token)[route])
				for name, node := range map[string]*qualSP225Shard{"typed context live": timed, "plain setter": plain} {
					actual, actualErr := node.hook.ProcessBuiltInFunction(node.routes(token)[route])
					require.Equal(t, nativeErr, actualErr, "%s %s", name, token)
					require.Equal(t, expected, actual, "%s %s", name, token)
				}
			}
			_, err = context.Milliseconds()
			require.NoError(t, err, "ordinary calls do not end or replace the block's context")
			nativeRoot, err := native.store.Commit()
			require.NoError(t, err)
			for _, node := range []*qualSP225Shard{timed, plain} {
				root, commitErr := node.store.Commit()
				require.NoError(t, commitErr)
				require.Equal(t, nativeRoot, root)
			}
			if route == "transfer" || route == "multi_transfer" {
				require.EqualValues(t, 90, timed.balance(t, timed.sender, qualSP225Ordinary), "the ordinary effect really happened")
				require.EqualValues(t, 10, timed.balance(t, timed.another, qualSP225Ordinary))
			}
		})
	}
}

// The same for ordinary System-SC calls on the metachain.
func TestQualSP224OrdinaryMetaSystemCallsWithTimeSourceInstalled(t *testing.T) {
	timed := qualSP224MetaNode(t, true, qualSP225GenesisStore(t, qualSP225Regulated))
	plain := qualSP224MetaNode(t, true, qualSP225GenesisStore(t, qualSP225Regulated))
	native := qualSP224MetaNode(t, false, qualSP225GenesisStore(t, qualSP225Regulated))
	header := func() data.HeaderHandler { return qualSP224Header(core.MetachainShardId, 12, 440, 1234567) }
	context, _, err := qualSP224Evaluate(t, timed.hook, header())
	require.NoError(t, err)
	for _, other := range []*qualSP225Node{plain, native} {
		require.NoError(t, other.hook.SetEpochStartHeader(header()))
		require.NoError(t, other.hook.SetCurrentHeader(header()))
	}
	require.NoError(t, timed.owner.BeginExecution())
	require.NoError(t, plain.owner.BeginExecution())

	calls := 0
	run := func(input func() *vmcommon.ContractCallInput) *vmcommon.VMOutput {
		t.Helper()
		calls++
		expected, nativeErr := native.system.RunSmartContractCall(input())
		for name, node := range map[string]*qualSP225Node{"typed context live": timed, "plain setter": plain} {
			actual, actualErr := node.system.RunSmartContractCall(input())
			require.Equal(t, nativeErr, actualErr, name)
			require.Equal(t, expected, actual, name)
		}
		return expected
	}
	issued := run(func() *vmcommon.ContractCallInput {
		input := qualSP225ESDTCall("issue", []byte("OrdinaryToken"), []byte("ORDINARY"), big.NewInt(1000).Bytes(), []byte{2},
			[]byte("canPause"), []byte("true"), []byte("canFreeze"), []byte("true"), []byte("canWipe"), []byte("true"), []byte("canChangeOwner"), []byte("true"))
		input.CallValue = big.NewInt(1000)
		return input
	})
	require.Equal(t, vmcommon.Ok, issued.ReturnCode, issued.ReturnMessage)
	for _, function := range qualSP225PublicMutations {
		run(func() *vmcommon.ContractCallInput { return qualSP225PublicCall(function, qualSP225Ordinary) })
	}
	run(func() *vmcommon.ContractCallInput {
		return qualSP225ESDTCall("getTokenProperties", []byte(qualSP225Ordinary))
	})
	run(func() *vmcommon.ContractCallInput {
		return qualSP225ESDTCall("unknownEndpoint", []byte(qualSP225Ordinary))
	})
	require.Equal(t, len(qualSP225PublicMutations)+3, calls)

	_, err = context.Milliseconds()
	require.NoError(t, err, "ordinary calls do not end or replace the block's context")
	nativeRoot, err := native.user.Commit()
	require.NoError(t, err)
	for _, node := range []*qualSP225Node{timed, plain} {
		root, commitErr := node.user.Commit()
		require.NoError(t, commitErr)
		require.Equal(t, nativeRoot, root, "identical ordinary state delta")
	}
}
