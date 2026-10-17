package drwa

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	dataMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	storageMock "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// The actual native constructor and exclusive account store are used here.
// Numeric values are experimental T05/T18/T42 fixtures, never an admitted
// profile. Existing semantic/proof hosts remain synthetic: these cases prove
// native time dataflow, not lawful G3, funding, canonicality or network finality.
func qualT42Hook(t *testing.T, accounts state.AccountsAdapter, shard uint32, configured bool) (*hooks.BlockChainHookImpl, *testscommon.EpochStartTriggerStub) {
	t.Helper()
	pool := dataMock.NewPoolsHolderMock()
	t.Cleanup(func() { require.NoError(t, pool.Close()) })
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	flags.IsFlagEnabledInEpochCalled = func(flag core.EnableEpochFlag, epoch uint32) bool {
		if flag == common.SupernovaFlag {
			return epoch >= 10
		}
		return true
	}
	flags.GetCurrentEpochCalled = func() uint32 { return 77 }
	coordinator := testscommon.NewMultiShardsCoordinatorMock(3)
	coordinator.CurrentShard = shard
	trigger := &testscommon.EpochStartTriggerStub{}
	args := hooks.ArgBlockChainHook{
		Accounts: accounts, PubkeyConv: testscommon.NewPubkeyConverterMock(32),
		StorageService: &storageMock.ChainStorerStub{}, BlockChain: &testscommon.ChainHandlerStub{},
		ShardCoordinator: coordinator, Marshalizer: &marshal.GogoProtoMarshalizer{},
		Uint64Converter:   &mock.Uint64ByteSliceConverterMock{},
		BuiltInFunctions:  builtInFunctions.NewBuiltInFunctionContainer(),
		NFTStorageHandler: &testscommon.SimpleNFTStorageHandlerStub{}, GlobalSettingsHandler: &testscommon.ESDTGlobalSettingsHandlerStub{},
		DataPool: pool, CompiledSCPool: pool.SmartContracts(), EpochNotifier: &epochNotifier.EpochNotifierStub{},
		EnableEpochsHandler: flags, NilCompiledSCStore: true,
		GasSchedule: testscommon.NewGasScheduleNotifierMock(make(map[string]map[string]uint64)),
		Counter:     &testscommon.BlockChainHookCounterStub{}, MissingTrieNodesNotifier: &testscommon.MissingTrieNodesNotifierStub{},
		EpochStartTrigger: trigger, RoundHandler: &testscommon.RoundHandlerMock{},
	}
	if configured {
		args.Hasher = blake2b.NewBlake2b()
	}
	hook, err := hooks.NewBlockChainHookImpl(args)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, hook.Close()) })
	require.NoError(t, hook.SetEpochStartHeader(qualT42Header(shard, 100)))
	return hook, trigger
}

func qualT42Header(shard uint32, time uint64) data.HeaderHandler {
	if shard == core.MetachainShardId {
		return &block.MetaBlockV3{Epoch: 10, Round: 30, Nonce: 20, TimestampMs: time, ChainID: []byte("T42-fixture")}
	}
	return &block.HeaderV3{Epoch: 10, ShardID: shard, Round: 30, Nonce: 20, TimestampMs: time, ChainID: []byte("T42-fixture")}
}

func qualT42Install(t *testing.T, hook *hooks.BlockChainHookImpl, shard uint32, time uint64) (*HeaderTimeContext, func()) {
	t.Helper()
	install, end, err := hook.BeginDRWAHeaderEvaluation()
	require.NoError(t, err)
	t.Cleanup(end)
	require.NoError(t, install(qualT42Header(shard, time)))
	context, err := hook.EvaluatedHeaderTimeContext()
	require.NoError(t, err)
	return context, end
}

func TestQualDRWAT42NativeLifecycle(t *testing.T) {
	for _, shard := range []uint32{1, core.MetachainShardId} {
		for _, name := range []string{"valid", "zero", "max", "end", "close", "raw_nil", "raw_equal", "ABA", "owned_nil", "mutate_time", "mutate_identity", "fresh_owner", "overlap", "failed_native_install", "legacy", "before_activation", "unconfigured", "raw_only", "meta_prospective_epoch"} {
			t.Run(fmt.Sprintf("%d/%s", shard, name), func(t *testing.T) {
				hook, trigger := qualT42Hook(t, qualRegistrationStore(t, 0), shard, name != "unconfigured")
				header := qualT42Header(shard, 1234567)
				if name == "zero" {
					require.NoError(t, header.SetTimeStamp(0))
				}
				if name == "max" {
					require.NoError(t, header.SetTimeStamp(^uint64(0)))
				}
				_, err := hook.EvaluatedHeaderTimeContext()
				require.Error(t, err)
				if name == "raw_only" {
					require.NoError(t, hook.SetCurrentHeader(header))
					_, err = hook.EvaluatedHeaderTimeContext()
					require.Error(t, err)
					return
				}
				install, end, err := hook.BeginDRWAHeaderEvaluation()
				require.NoError(t, err)
				defer end()
				if name == "legacy" {
					header = &block.Header{Epoch: 10, TimeStamp: 1234}
				}
				if name == "before_activation" {
					require.NoError(t, header.SetEpoch(9))
					require.NoError(t, hook.SetEpochStartHeader(header))
				}
				require.NoError(t, install(header))
				context, err := hook.EvaluatedHeaderTimeContext()
				if name == "legacy" || name == "before_activation" || name == "unconfigured" {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				time, err := context.Milliseconds()
				require.NoError(t, err)
				require.Equal(t, HeaderMilliseconds(header.GetTimeStamp()), time)
				require.Equal(t, header.GetTimeStamp(), hook.CurrentTimeStampMs())
				switch name {
				case "valid", "zero", "max":
					return
				case "close":
					require.NoError(t, hook.Close())
					next, exit, e := hook.BeginDRWAHeaderEvaluation()
					require.Error(t, e)
					require.Nil(t, next)
					require.Nil(t, exit)
				case "end":
					end()
					end()
				case "raw_nil":
					require.ErrorIs(t, hook.SetCurrentHeader(nil), hooks.ErrNilCurrentHeader)
				case "raw_equal":
					require.NoError(t, hook.SetCurrentHeader(header.ShallowClone()))
				case "ABA":
					other := qualT42Header(shard, 7654321)
					require.NoError(t, hook.SetCurrentHeader(other))
					require.NoError(t, hook.SetCurrentHeader(header))
				case "owned_nil":
					require.ErrorIs(t, install(nil), hooks.ErrNilCurrentHeader)
				case "mutate_time":
					require.NoError(t, header.SetTimeStamp(7654321))
				case "mutate_identity":
					require.NoError(t, header.SetChainID([]byte("other-fixture")))
				case "fresh_owner":
					end()
					next, closeNext := qualT42Install(t, hook, shard, 1234567)
					end()
					_, err = next.Milliseconds()
					require.NoError(t, err)
					closeNext()
				case "overlap":
					next, exit, beginErr := hook.BeginDRWAHeaderEvaluation()
					require.ErrorIs(t, beginErr, ErrInactiveHeaderTime)
					require.Nil(t, next)
					require.Nil(t, exit)
					_, err = context.Milliseconds()
					require.NoError(t, err)
					return
				case "failed_native_install":
					failure := errors.New("T42 selected epoch lookup failure")
					trigger.LastCommitedEpochStartHdrCalled = func() (data.HeaderHandler, error) { return nil, failure }
					next := header.ShallowClone()
					require.NoError(t, next.SetEpoch(11))
					require.ErrorIs(t, install(next), failure)
					require.Equal(t, uint64(1234567), hook.CurrentTimeStampMs())
				case "meta_prospective_epoch":
					if shard != core.MetachainShardId {
						return
					}
					end()
					meta := qualT42Header(shard, 1234567).(*block.MetaBlockV3)
					meta.EpochChangeProposed = true
					nativeInstall, exit, e := hook.BeginDRWAHeaderEvaluation()
					require.NoError(t, e)
					defer exit()
					require.NoError(t, nativeInstall(meta))
					current, e := hook.EvaluatedHeaderTimeContext()
					require.NoError(t, e)
					_, epoch, release, e := current.Lease()
					require.NoError(t, e)
					release()
					require.Equal(t, uint32(10), epoch)
					require.Equal(t, uint32(11), hook.CurrentEpoch())
				}
				_, err = context.Milliseconds()
				require.ErrorIs(t, err, ErrInactiveHeaderTime)
				if name != "fresh_owner" && name != "meta_prospective_epoch" {
					_, err = hook.EvaluatedHeaderTimeContext()
					require.Error(t, err)
				}
			})
		}
	}
}

func TestQualDRWAT42NativeConcurrentInvalidation(t *testing.T) {
	hook, _ := qualT42Hook(t, qualRegistrationStore(t, 0), 1, true)
	context, end := qualT42Install(t, hook, 1, 111)
	_, _, release, leaseErr := context.Lease()
	require.NoError(t, leaseErr)
	var wg sync.WaitGroup
	results := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				time, err := context.Milliseconds()
				if err != nil && !errors.Is(err, ErrInactiveHeaderTime) {
					results <- err
					return
				}
				if err == nil && time != 111 {
					results <- errors.New("mixed coordinate")
					return
				}
			}
		}()
	}
	installErr := hook.SetCurrentHeader(qualT42Header(1, 222))
	release()
	end()
	wg.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	require.ErrorIs(t, installErr, ErrInactiveHeaderTime)
	require.Equal(t, uint64(111), hook.CurrentTimeStampMs())
	require.NoError(t, hook.SetCurrentHeader(qualT42Header(1, 222)))
	fresh, exit := qualT42Install(t, hook, 1, 222)
	_, freshErr := fresh.Milliseconds()
	require.NoError(t, freshErr)
	exit()
	_, err := context.Milliseconds()
	require.ErrorIs(t, err, ErrInactiveHeaderTime)
}

func TestQualDRWAT42ScopedNativeConsumer(t *testing.T) {
	for _, time := range []uint64{200, 201} {
		t.Run(fmt.Sprint(time), func(t *testing.T) {
			f := qualScopedNew(t)
			hook, _ := qualT42Hook(t, f.store, core.MetachainShardId, true)
			var bindErr error
			f.records, bindErr = newScopedAdmissionRecords(f.store, f.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"), scopedAdmissionLimits{4096, 100, 1 << 20, 100}, f.mandates, hook)
			require.NoError(t, bindErr)
			context, end := qualT42Install(t, hook, core.MetachainShardId, 100)
			f.context = context
			f.enroll(t)
			f.admit(t)
			end()
			context, _ = qualT42Install(t, hook, core.MetachainShardId, time)
			err := f.records.checkDecision(context, f.d)
			if time == 200 {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			foreign := qualGovernedContext(t, qualHeaderTimeOwner(t), core.MetachainShardId, 100)
			require.ErrorIs(t, f.records.checkDecision(foreign, f.d), ErrInactiveHeaderTime)
		})
	}
}

func TestQualDRWAT42GASNativeConsumer(t *testing.T) {
	for _, time := range []uint64{104, 105, 119, 120} {
		t.Run(fmt.Sprint(time), func(t *testing.T) {
			f := qualGovernedActionNew(t)
			hook, _ := qualT42Hook(t, f.s, core.MetachainShardId, true)
			var bindErr error
			f.g, bindErr = newGovernedActionRecords(f.s, f.o, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, []byte("n"), 4, 2, 2, f.h, hook)
			require.NoError(t, bindErr)
			context, end := qualT42Install(t, hook, core.MetachainShardId, 100)
			f.x = context
			f.initialize(t)
			id := f.propose(t)
			end()
			f.x, end = qualT42Install(t, hook, core.MetachainShardId, 105)
			require.NoError(t, f.g.authorize(f.x, id, []byte("synthetic-full-authorize")))
			end()
			f.x, _ = qualT42Install(t, hook, core.MetachainShardId, time)
			err := f.g.start(f.x, id, []byte("synthetic-current-start"))
			if time >= 105 && time < 120 {
				require.NoError(t, err)
				r, _, _, e := f.g.load(id)
				require.NoError(t, e)
				require.Equal(t, HeaderMilliseconds(time), r.started)
				require.Equal(t, 1, f.h.effects)
			} else {
				require.Error(t, err)
				require.Zero(t, f.h.effects)
				qualAssertContainmentBalance(t, f.s, 100)
			}
		})
	}
}

func TestQualDRWAT42F06NativeConsumer(t *testing.T) {
	for _, name := range []string{"before", "equal", "after", "redrive", "foreign", "missing", "ended", "raw_replace", "nested_apply", "nested_ack", "concurrent_replace", "native_failure", "restart"} {
		t.Run(name, func(t *testing.T) {
			f := qualSourceGrantNew(t)
			hook, _ := qualT42Hook(t, f.store, 1, true)
			var bindErr error
			f.records, bindErr = newSourceGrantRecords(f.store, f.owner, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, 1, f.host, hook)
			require.NoError(t, bindErr)
			context, end := qualT42Install(t, hook, 1, 111)
			f.context = context
			f.install(t)
			end()
			time := uint64(111)
			if name == "equal" {
				time = 112
			}
			if name == "after" {
				time = 113
			}
			f.context, end = qualT42Install(t, hook, 1, time)
			root, err := f.store.RootHash()
			require.NoError(t, err)
			journal := f.store.JournalLen()
			switch name {
			case "foreign":
				f.context = qualGovernedContext(t, qualHeaderTimeOwner(t), 1, 111)
			case "missing":
				f.context = nil
			case "ended":
				end()
			case "raw_replace":
				require.NoError(t, hook.SetCurrentHeader(qualT42Header(1, 111)))
			case "nested_apply", "nested_ack", "concurrent_replace":
				stage := "apply"
				if name == "nested_ack" {
					stage = "ack"
				}
				f.host.hooks[stage] = func() {
					if name == "concurrent_replace" {
						result := make(chan error, 1)
						go func() { result <- hook.SetCurrentHeader(qualT42Header(1, 222)) }()
						require.ErrorIs(t, <-result, ErrInactiveHeaderTime)
					} else {
						require.ErrorIs(t, hook.SetCurrentHeader(qualT42Header(1, 222)), ErrInactiveHeaderTime)
					}
				}
			case "native_failure":
				f.host.faults["apply"] = errors.New("T42 native effect failure")
			case "restart":
				end()
				replacement, _ := qualT42Hook(t, f.store, 1, true)
				f.records.timeSource = replacement
			}
			err = f.consume()
			if name == "before" || name == "redrive" {
				require.NoError(t, err)
				f.assertState(t, "CONSUMED", "", f.host.effect)
				qualAssertContainmentBalance(t, f.store, 97)
				if name == "redrive" {
					end()
					f.context, _ = qualT42Install(t, hook, 1, 113)
					require.NoError(t, f.consume())
					require.Equal(t, 1, f.host.effectCalls)
				}
			} else {
				require.Error(t, err)
				f.assertState(t, "OPEN", "", nil)
				qualAssertContainmentBalance(t, f.store, 100)
				after, e := f.store.RootHash()
				require.NoError(t, e)
				require.Equal(t, root, after)
				require.Equal(t, journal, f.store.JournalLen())
				require.Empty(t, qualRegistryValue(t, f.store, "fixture/source-native-effect"))
			}
		})
	}
}

func TestQualDRWAT42ConstructorSourceOwnership(t *testing.T) {
	f := qualSourceGrantNew(t)
	foreign, _ := qualT42Hook(t, qualRegistrationStore(t, 0), 1, true)
	_, err := newSourceGrantRecords(f.store, f.owner, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, 1, f.host, foreign)
	require.ErrorIs(t, err, errSourceGrant)
	_, err = newSourceGrantRecords(f.store, f.owner, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, 1, f.host, nil)
	require.ErrorIs(t, err, errSourceGrant)
	// Equal header coordinates and identical roots cannot confer account ownership.
	require.NotSame(t, f.store, foreign.GetAccountsAdapter())
}

func TestQualDRWAT42EveryConsumerRejectsEndedNativeContext(t *testing.T) {
	for _, op := range []string{"scoped_install", "scoped_admit", "scoped_withdraw", "scoped_read", "gas_initialize", "gas_propose", "gas_authorize", "gas_start", "gas_cleanup", "f06_install", "f06_consume", "f06_close"} {
		t.Run(op, func(t *testing.T) {
			sf := qualScopedNew(t)
			gf := qualGovernedActionNew(t)
			ff := qualSourceGrantNew(t)
			var store *qualNativeStore
			shard := uint32(core.MetachainShardId)
			switch op[:3] {
			case "sco":
				store = sf.store
			case "gas":
				store = gf.s
			default:
				store = ff.store
				shard = 1
			}
			hook, _ := qualT42Hook(t, store, shard, true)
			context, end := qualT42Install(t, hook, shard, 100)
			end()
			root, e := store.RootHash()
			require.NoError(t, e)
			journal := store.JournalLen()
			var err error
			switch op {
			case "scoped_install", "scoped_admit", "scoped_withdraw", "scoped_read":
				sf.records, err = newScopedAdmissionRecords(store, sf.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"), scopedAdmissionLimits{4096, 100, 1 << 20, 100}, sf.mandates, hook)
				require.NoError(t, err)
				switch op {
				case "scoped_install":
					err = sf.records.install(context, sf.d.owner, sf.d.program, nil, sf.versionBody, sf.mandates.proof("ENROLL", nil, sf.d.authority))
				case "scoped_admit":
					err = sf.records.admit(context, sf.d, sf.mandates.proof("ADMISSION", sf.d.authority, qualScopedHash("ADMISSION", sf.body())))
				case "scoped_withdraw":
					err = sf.records.withdraw(context, sf.d, sf.withdrawProof())
				default:
					err = sf.records.checkDecision(context, sf.d)
				}
			case "gas_initialize", "gas_propose", "gas_authorize", "gas_start", "gas_cleanup":
				gf.g, err = newGovernedActionRecords(store, gf.o, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, []byte("n"), 4, 2, 2, gf.h, hook)
				require.NoError(t, err)
				_, _, id := gf.expected(100)
				switch op {
				case "gas_initialize":
					err = gf.g.initialize(context, gf.p.subject, gf.p.class, gf.p.token)
				case "gas_propose":
					_, err = gf.g.propose(context, gf.p)
				case "gas_authorize":
					err = gf.g.authorize(context, id, []byte("synthetic-full-authorize"))
				case "gas_start":
					err = gf.g.start(context, id, []byte("synthetic-current-start"))
				default:
					err = gf.g.cleanup(context, id, "EXPIRED", []byte("synthetic-no-irreversible-proof"))
				}
			default:
				ff.records, err = newSourceGrantRecords(store, ff.owner, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, 1, ff.host, hook)
				require.NoError(t, err)
				switch op {
				case "f06_install":
					err = ff.records.install(context, ff.p, []byte("synthetic-canonical-proof"))
				case "f06_consume":
					err = ff.records.consume(context, ff.p, []byte("synthetic-canonical-proof"))
				default:
					err = ff.records.closeUnused(context, ff.p, "EXPIRED", []byte("synthetic-canonical-proof"))
				}
			}
			require.ErrorIs(t, err, ErrInactiveHeaderTime)
			after, e := store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, journal, store.JournalLen())
		})
	}
}

func TestQualDRWAT42NativeConsumerReentry(t *testing.T) {
	t.Run("scoped_mandate", func(t *testing.T) {
		f := qualScopedNew(t)
		hook, _ := qualT42Hook(t, f.store, core.MetachainShardId, true)
		var err error
		f.records, err = newScopedAdmissionRecords(f.store, f.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"), scopedAdmissionLimits{4096, 100, 1 << 20, 100}, f.mandates, hook)
		require.NoError(t, err)
		context, _ := qualT42Install(t, hook, core.MetachainShardId, 100)
		root, err := f.store.RootHash()
		require.NoError(t, err)
		f.mandates.hook = func() {
			require.ErrorIs(t, hook.SetCurrentHeader(qualT42Header(core.MetachainShardId, 101)), ErrInactiveHeaderTime)
		}
		err = f.records.install(context, f.d.owner, f.d.program, nil, f.versionBody, f.mandates.proof("ENROLL", nil, f.d.authority))
		require.ErrorIs(t, err, ErrInactiveHeaderTime)
		after, e := f.store.RootHash()
		require.NoError(t, e)
		require.Equal(t, root, after)
	})
	t.Run("gas_native_effect", func(t *testing.T) {
		f := qualGovernedActionNew(t)
		hook, _ := qualT42Hook(t, f.s, core.MetachainShardId, true)
		var err error
		f.g, err = newGovernedActionRecords(f.s, f.o, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, []byte("n"), 4, 2, 2, f.h, hook)
		require.NoError(t, err)
		context, end := qualT42Install(t, hook, core.MetachainShardId, 100)
		f.x = context
		f.initialize(t)
		id := f.propose(t)
		end()
		context, _ = qualT42Install(t, hook, core.MetachainShardId, 105)
		f.x = context
		require.NoError(t, f.g.authorize(context, id, []byte("synthetic-full-authorize")))
		root, err := f.s.RootHash()
		require.NoError(t, err)
		f.h.hooks["apply"] = func() {
			require.ErrorIs(t, hook.SetCurrentHeader(qualT42Header(core.MetachainShardId, 106)), ErrInactiveHeaderTime)
		}
		require.ErrorIs(t, f.g.start(context, id, []byte("synthetic-current-start")), ErrInactiveHeaderTime)
		qualAssertContainmentBalance(t, f.s, 100)
		after, e := f.s.RootHash()
		require.NoError(t, e)
		require.Equal(t, root, after)
	})
}
