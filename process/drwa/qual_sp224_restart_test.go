package drwa

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// qualSP224Reopen commits the store and opens a new accounts database over the
// same persisted data at the committed root, as a restarted node does.
func qualSP224Reopen(t *testing.T, store *qualNativeStore) *qualNativeStore {
	t.Helper()
	root, err := store.Commit()
	require.NoError(t, err)
	cfg, _ := qualContainmentArgs(t, store.backing)
	db, err := state.NewAccountsDB(cfg)
	require.NoError(t, err)
	require.NoError(t, db.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	reopened, err := db.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, reopened)
	return &qualNativeStore{AccountsAdapter: db, backing: store.backing}
}

// SP2-24 restart: the decision depends on the stored record and the header
// only. After the store is reopened and a new hook and a new consumer object
// are built over it (nothing of the old process is kept), the same header time
// gives the same decision as before the restart, at each bound.
func TestQualSP224SameHeaderSameDecisionAfterRestart(t *testing.T) {
	rows := []struct {
		name     string
		before   func(t *testing.T, time uint64) *qualSP224Consumer
		after    func(t *testing.T, time uint64) *qualSP224Consumer
		admitted map[uint64]bool
	}{
		{"f06_source_expiry",
			func(t *testing.T, _ uint64) *qualSP224Consumer { c, _ := qualSP224F06Consumer(t, "consume"); return c },
			func(t *testing.T, _ uint64) *qualSP224Consumer {
				c, f := qualSP224F06Consumer(t, "consume")
				store := qualSP224Reopen(t, f.store)
				hook, _ := qualT42Hook(t, store, 1, true)
				owner, err := NewRollbackContainment(store)
				require.NoError(t, err)
				f.store, f.owner, f.host.store = store, owner, store
				f.records, err = newSourceGrantRecords(store, owner, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, 1, f.host, hook)
				require.NoError(t, err)
				c.hook, c.store = hook, store
				return c
			}, map[uint64]bool{110: true, 111: true, 112: false, 113: false}},
		{"governed_action_start_window",
			func(t *testing.T, _ uint64) *qualSP224Consumer { c, _, _ := qualSP224GASConsumer(t, "start"); return c },
			func(t *testing.T, _ uint64) *qualSP224Consumer {
				c, f, _ := qualSP224GASConsumer(t, "start")
				store := qualSP224Reopen(t, f.s)
				hook, _ := qualT42Hook(t, store, core.MetachainShardId, true)
				owner, err := NewRollbackContainment(store)
				require.NoError(t, err)
				f.s, f.o, f.h.store = store, owner, store
				f.g, err = newGovernedActionRecords(store, owner, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, []byte("n"), 4, 2, 2, f.h, hook)
				require.NoError(t, err)
				c.hook, c.store = hook, store
				return c
			}, map[uint64]bool{104: false, 105: true, 119: true, 120: false}},
		{"scoped_admission_expiry",
			func(t *testing.T, _ uint64) *qualSP224Consumer { c, _ := qualSP224ScopedConsumer(t, "read"); return c },
			func(t *testing.T, _ uint64) *qualSP224Consumer {
				c, f := qualSP224ScopedConsumer(t, "read")
				store := qualSP224Reopen(t, f.store)
				hook, _ := qualT42Hook(t, store, core.MetachainShardId, true)
				boundary, err := NewRollbackContainment(store)
				require.NoError(t, err)
				f.store, f.boundary = store, boundary
				f.records, err = newScopedAdmissionRecords(store, boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"),
					scopedAdmissionLimits{4096, 100, 1 << 20, 100}, f.mandates, hook)
				require.NoError(t, err)
				c.hook, c.store = hook, store
				return c
			}, map[uint64]bool{199: true, 200: true, 201: false}},
		{"registration_intent_expiry",
			func(t *testing.T, time uint64) *qualSP224Consumer {
				return qualSP224RegistrationConsumer(t, "creation", time)
			},
			func(t *testing.T, time uint64) *qualSP224Consumer {
				f := qualRegistrationAdmission(t, core.FungibleESDT)
				f.end()
				id, digest, manager := bytes.Clone(f.owner.id), bytes.Clone(f.owner.digest), bytes.Clone(f.owner.manager)
				store := qualSP224Reopen(t, f.store)
				coordinator := testscommon.NewMultiShardsCoordinatorMock(3)
				coordinator.CurrentShard = core.MetachainShardId
				registry, boundary, err := NewRegistryRegistration(store, coordinator, 2)
				require.NoError(t, err)
				f.owner, err = registry.BindIntent(id, digest, manager, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
				require.NoError(t, err)
				f.store, f.boundary = store, boundary
				f.hook, _ = qualT42Hook(t, store, core.MetachainShardId, true)
				qualSP224SignAdmission(t, f, time)
				return &qualSP224Consumer{hook: f.hook, shard: core.MetachainShardId, store: store, at: 1, ownLookup: true,
					run: func(*HeaderTimeContext) error { return f.register(t, qualRegistrationCreator(t, "TOKEN-abcdef")) }}
			}, map[uint64]bool{1: true, 2: false}},
	}
	for _, row := range rows {
		for time, admitted := range row.admitted {
			t.Run(fmt.Sprintf("%s/%d", row.name, time), func(t *testing.T) {
				before := qualSP224At(t, row.before(t, time), time)
				after := qualSP224At(t, row.after(t, time), time)
				require.Equal(t, before == nil, after == nil, "before the restart: %v, after: %v", before, after)
				require.Equal(t, admitted, after == nil)
			})
		}
	}
}

// After a restart there is no context until a block processor installs one: a
// new hook over the reopened store refuses a consumer until then, and a
// context kept from before the restart is not accepted by the new hook.
func TestQualSP224NoContextSurvivesARestart(t *testing.T) {
	c, f := qualSP224F06Consumer(t, "consume")
	old, _, err := qualSP224Begin(t, c.hook, c.headerAt(111))
	require.NoError(t, err)
	store := qualSP224Reopen(t, f.store)
	hook, _ := qualT42Hook(t, store, 1, true)
	owner, err := NewRollbackContainment(store)
	require.NoError(t, err)
	f.store, f.owner, f.host.store = store, owner, store
	f.records, err = newSourceGrantRecords(store, owner, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, 1, f.host, hook)
	require.NoError(t, err)
	_, err = hook.EvaluatedHeaderTimeContext()
	require.ErrorIs(t, err, ErrInactiveHeaderTime)
	root, journal := qualSP224State(t, store)
	_, err = old.Milliseconds()
	require.NoError(t, err, "the old process's context is still alive in the old hook")
	f.context = old
	require.ErrorIs(t, f.consume(), ErrInactiveHeaderTime)
	f.context = nil
	require.Error(t, f.consume())
	after, afterJournal := qualSP224State(t, store)
	require.Equal(t, root, after)
	require.Equal(t, journal, afterJournal)
	f.assertState(t, "OPEN", "", nil)
}
