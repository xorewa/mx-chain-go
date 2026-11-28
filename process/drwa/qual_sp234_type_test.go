package drwa

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-34 tests on SP2-33's world: real stores, the native built-in container,
// the shard registries, SP2-32's legs and acknowledgements.

// sp234Flagged is the native ESDTSetTokenType built-in of a shard with its
// activation (DynamicESDTFlag) set as the test says. Everything else is the
// native function.
type sp234Flagged struct {
	vmcommon.BuiltinFunction
	active bool
}

func (f *sp234Flagged) IsActive() bool { return f.active }

// typeRequired makes every shard of the world a node on which the baseline
// materializes token types, or not.
func (w *sp233World) typeRequired(active bool) {
	w.t.Helper()
	for _, shard := range w.shards {
		native, err := shard.builtIns.Get(core.ESDTSetTokenType)
		require.NoError(w.t, err)
		if flagged, ok := native.(*sp234Flagged); ok {
			flagged.active = active
			continue
		}
		require.NoError(w.t, shard.builtIns.Replace(core.ESDTSetTokenType, &sp234Flagged{BuiltinFunction: native, active: active}))
	}
}

// roleLeg opens a role grant for the holder of shard 1 with the given family
// in its envelope and returns the leg.
func (w *sp233World) roleLeg(family, origin string) vmcommon.OutputTransfer {
	w.t.Helper()
	request := w.grant(1, core.ESDTRoleLocalMint)
	request.TokenType, request.Origin = []byte(family), w.hash(origin)
	_, transfers := w.sp232World.open(request)
	return transfers[0]
}

func (w *sp233World) plant(shard uint32, item []byte) {
	w.t.Helper()
	s := w.shards[shard]
	account, err := s.store.LoadAccount(core.SystemAccountAddress)
	require.NoError(w.t, err)
	require.NoError(w.t, account.(vmcommon.UserAccountHandler).AccountDataHandler().SaveKeyValue(sp233ItemKey, item))
	require.NoError(w.t, s.store.SaveAccount(account))
	s.commit()
}

// Part A 4.1 step 3: "Expected token type ... must be unambiguous at every
// execution locus before its earliest dependent effect ... a later ACK cannot
// retroactively protect an earlier mutation." The earliest dependent effect on
// a shard is a protected leg other than the type leg.
func TestQualSP234DependentLegNeedsTheExactTypeOnItsShard(t *testing.T) {
	system := registryDeltaSystemAddress(1)
	nft := burnReadinessTypeByte[core.NonFungibleESDTv2]
	cases := []struct {
		name     string
		required bool
		item     []byte
		admitted bool
	}{
		{"type required, item missing", true, nil, false},
		{"type required, item without a type", true, []byte{0, 0}, false},
		{"type required, type of another family", true, []byte{0, burnReadinessTypeByte[core.SemiFungibleESDT]}, false},
		{"type required, fungible type for an NFT", true, []byte{0, burnReadinessTypeByte[core.FungibleESDT]}, false},
		{"type required, one byte", true, []byte{0}, false},
		{"type required, three bytes", true, []byte{0, nft, 0}, false},
		{"type required, exact type", true, []byte{0, nft}, true},
		{"no type in the baseline, item missing", false, nil, true},
		{"no type in the baseline, item without a type", false, []byte{0, 0}, true},
		{"no type in the baseline, exact type", false, []byte{0, nft}, true},
		{"no type in the baseline, type of another family", false, []byte{0, burnReadinessTypeByte[core.DynamicNFTESDT]}, false},
		{"no type in the baseline, one byte", false, []byte{0}, false},
		{"no type in the baseline, three bytes", false, []byte{0, 0, 0}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := sp233New(t, c.required)
			w.typeRequired(c.required)
			shard := w.shards[1]
			if c.item != nil {
				w.plant(1, c.item)
			}
			leg := w.roleLeg(core.NonFungibleESDTv2, "role origin")
			if !c.admitted {
				calls := shard.binding.calls
				before := shard.root()
				_, err := shard.call(sp232Input(t, system, leg, "leg result hash"))
				require.ErrorIs(t, err, ErrTokenTypeNotMaterialized)
				require.ErrorIs(t, err, ErrInvalidAdminEffect)
				require.Equal(t, before, shard.root())
				require.Empty(t, shard.roles())
				require.Equal(t, calls, shard.binding.calls, "refused before the binding is consulted")
				return
			}
			_, err := shard.deliver(leg)
			require.NoError(t, err)
			require.Equal(t, sp232Roles(core.ESDTRoleLocalMint), shard.roles())
		})
	}
	// Every kind of dependent leg, with the type required and missing: the
	// role, the limited-transfer setting, the transfer-role address and the
	// burn normalisation. Only the type leg itself passes.
	w := sp233New(t, true)
	w.typeRequired(true)
	shard := w.shards[1]
	token := []byte(sp232Token)
	for name, payload := range map[string][]byte{
		"limited transfer":      sp232Payload(core.BuiltInFunctionESDTSetLimitedTransfer, token),
		"transfer-role address": sp232Payload(vmcommon.BuiltInFunctionESDTTransferRoleAddAddress, token, shard.holder),
		"burn normalisation":    sp232Payload(vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, token),
	} {
		request := w.limited()
		request.Origin, request.Payload = w.hash(name), payload
		_, transfers := w.sp232World.open(request)
		before := shard.root()
		_, err := shard.call(sp232Input(t, system, transfers[1], "leg result hash"))
		require.ErrorIs(t, err, ErrTokenTypeNotMaterialized, name)
		require.Equal(t, before, shard.root(), name)
	}
	// An envelope of an unknown family is refused by the same guard.
	refused := sp232Mutated(w.sp232World, w.roleLeg(core.FungibleESDT, "family origin"), func(e *adminEffectEnvelope) {
		e.tokenType = []byte(core.NonFungibleESDT)
	})
	shard.refused("legacy NFT family", sp232Input(t, system, refused, "leg result hash"))
}

// Same-block registration and first effect; delayed, reordered and duplicated
// type effects; rollback and restart at each step.
func TestQualSP234SameBlockOrderRollbackAndRestart(t *testing.T) {
	w := sp233New(t, true)
	w.typeRequired(true)
	shard := w.shards[1]
	system := registryDeltaSystemAddress(1)
	typeLegs, unsetLegs := w.open(core.NonFungibleESDTv2)
	role := w.roleLeg(core.NonFungibleESDTv2, "role origin")
	typed := []byte{0, burnReadinessTypeByte[core.NonFungibleESDTv2]}
	refused := func(label string, leg vmcommon.OutputTransfer) {
		t.Helper()
		before := shard.root()
		_, err := shard.call(sp232Input(t, system, leg, "leg result hash"))
		require.ErrorIs(t, err, ErrInvalidAdminEffect, label)
		require.Equal(t, before, shard.root(), label)
	}
	block := shard.commit()

	// One block: the dependent legs arrive before the type leg (reordered),
	// are refused, and apply after it; nothing is committed in between.
	refused("role before the type", role)
	refused("burn normalisation before the type", unsetLegs[1])
	require.Empty(t, shard.roles())
	_, err := shard.deliver(typeLegs[1])
	require.NoError(t, err)
	_, err = shard.deliver(role)
	require.NoError(t, err)
	_, err = shard.deliver(unsetLegs[1])
	require.NoError(t, err)
	require.Equal(t, typed, w.item(1))
	require.Equal(t, sp232Roles(core.ESDTRoleLocalMint), shard.roles())
	// Duplicated and delayed type effects: nothing changes.
	applied := shard.commit()
	for range 3 {
		_, err = shard.deliver(typeLegs[1])
		require.NoError(t, err)
	}
	require.Equal(t, applied, shard.commit())

	// The block is rolled back: no type, no role; the dependent leg is refused
	// again; the same legs apply once on the replacing chain.
	require.NoError(t, shard.store.RecreateTrie(holders.NewDefaultRootHashesHolder(block)))
	require.NoError(t, shard.registry.BeginExecution())
	require.Empty(t, w.item(1))
	require.Empty(t, shard.roles())
	refused("role after the rollback", role)
	_, err = shard.deliver(typeLegs[1])
	require.NoError(t, err)
	shard.restart()
	require.Equal(t, typed, w.item(1), "the type survives a restart")
	_, err = shard.deliver(role)
	require.NoError(t, err)
	_, err = shard.deliver(unsetLegs[1])
	require.NoError(t, err)
	require.Equal(t, applied, shard.commit(), "the same state as before the rollback")
}

// The exact protected materialization exception (AR-27): a token registered
// while the baseline sent no type gets its own family's type on every shard by
// the protected leg, compared with the native built-in on a twin shard. Until
// then every dependent leg is refused on a node that materializes types.
func TestQualSP234ProtectedMaterializationOfATokenRegisteredBeforeTheFlag(t *testing.T) {
	for _, family := range sp233Families {
		t.Run(family, func(t *testing.T) {
			// Registered with the flag off: the false item without a type.
			w := sp233New(t, false)
			_, unsetLegs := w.open(family)
			for shard := uint32(0); shard < 3; shard++ {
				w.apply(shard, unsetLegs[shard])
				w.acknowledge(shard)
				require.Equal(t, []byte{0, 0}, w.item(shard))
			}
			require.NoError(t, w.readiness.Verify([]byte(sp232Token)))

			// The flag activates.
			w.typeRequired(true)
			role := w.roleLeg(family, "role origin")
			_, err := w.shards[1].call(sp232Input(t, registryDeltaSystemAddress(1), role, "leg result hash"))
			require.ErrorIs(t, err, ErrTokenTypeNotMaterialized, "stale type state")

			owner, err := NewTypeMaterialization(w.effects, enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.DynamicESDTFlag))
			require.NoError(t, err)
			require.False(t, owner.IsInterfaceNil())
			output := &vmcommon.VMOutput{}
			id, remaining, err := owner.Open(output, TypeMaterializationRequest{TokenID: []byte(sp232Token), Family: []byte(family),
				Origin: w.hash("materialization"), Binding: "CURRENT_CEB", Epoch: 2}, 100+3*sp232LegGas+4)
			require.NoError(t, err)
			require.Equal(t, uint64(4), remaining)
			legs := sp232Transfers(output)
			require.Len(t, legs, 3)

			twin := sp232ShardNew(t, 1)
			twin.native(vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, core.SystemAccountAddress, []byte(sp232Token))
			twin.native(core.ESDTSetTokenType, core.SystemAccountAddress, []byte(sp232Token), []byte(family))
			expected := twin.value(core.SystemAccountAddress, sp233ItemKey)
			require.Equal(t, []byte{0, burnReadinessTypeByte[family]}, expected)
			for shard := uint32(0); shard < 3; shard++ {
				w.apply(shard, legs[shard])
				require.Equal(t, expected, w.item(shard), "exactly the native type state")
				_, err = w.sp232World.acknowledge(w.shards[shard], id, shard)
				require.NoError(t, err)
			}
			open, err := w.effects.Read(id)
			require.NoError(t, err)
			require.Nil(t, open, "closed on the complete set")
			_, err = w.shards[1].deliver(role)
			require.NoError(t, err)
			require.NoError(t, w.readiness.Verify([]byte(sp232Token)), "the burn readiness is untouched")

			// A second materialization converts nothing: its legs find the typed
			// item and are refused; a type of another family likewise.
			for label, other := range map[string]string{"again": family, "another family": sp233Families[(len(family)+1)%len(sp233Families)]} {
				if other == family && label != "again" {
					continue
				}
				output = &vmcommon.VMOutput{}
				_, _, err = owner.Open(output, TypeMaterializationRequest{TokenID: []byte(sp232Token), Family: []byte(other),
					Origin: w.hash(label), Binding: "CURRENT_CEB", Epoch: 2}, 100000)
				require.NoError(t, err)
				before := w.shards[1].root()
				_, err = w.shards[1].call(sp232Input(t, registryDeltaSystemAddress(1), sp232Transfers(output)[1], "leg result hash"))
				require.ErrorIs(t, err, ErrInvalidAdminEffect, label)
				require.Equal(t, before, w.shards[1].root(), label)
				require.Equal(t, expected, w.item(1), label)
			}
		})
	}
}

func TestQualSP234MaterializationRefusals(t *testing.T) {
	w := sp233New(t, true)
	on := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.DynamicESDTFlag)
	owner, err := NewTypeMaterialization(w.effects, on)
	require.NoError(t, err)
	request := func() TypeMaterializationRequest {
		return TypeMaterializationRequest{TokenID: []byte(sp232Token), Family: []byte(core.MetaESDT), Origin: w.hash("origin"),
			Binding: "CURRENT_CEB", Epoch: 2}
	}
	open := func(o *TypeMaterialization, mutate func(*TypeMaterializationRequest), available uint64) func() error {
		return func() error {
			r := request()
			mutate(&r)
			output := &vmcommon.VMOutput{}
			id, remaining, openErr := o.Open(output, r, available)
			require.Nil(t, id)
			require.Zero(t, remaining)
			require.Empty(t, output.OutputAccounts)
			return openErr
		}
	}
	none := func(*TypeMaterializationRequest) {}
	for name, mutate := range map[string]func(*TypeMaterializationRequest){
		"legacy NFT family":      func(r *TypeMaterializationRequest) { r.Family = []byte(core.NonFungibleESDT) },
		"no family":              func(r *TypeMaterializationRequest) { r.Family = nil },
		"not a token identifier": func(r *TypeMaterializationRequest) { r.TokenID = []byte("x") },
		"origin of wrong size":   func(r *TypeMaterializationRequest) { r.Origin = nil },
		"unknown binding kind":   func(r *TypeMaterializationRequest) { r.Binding = "NEXT_CEB" },
	} {
		w.denied(name, open(owner, mutate, 100000))
	}
	w.denied("underfunded", open(owner, none, 100+3*sp232LegGas-1))
	off, err := NewTypeMaterialization(w.effects, enableEpochsHandlerMock.NewEnableEpochsHandlerStub())
	require.NoError(t, err)
	w.denied("the baseline materializes no type", func() error {
		openErr := open(off, none, 100000)()
		require.ErrorIs(t, openErr, ErrInvalidTypeMaterialization)
		return openErr
	})
	w.domain = nil
	w.denied("no network domain", open(owner, none, 100000))
	w.domain = sp232Domain
	shardless := *w.effects
	shardless.args.Shards = 0
	none0, err := NewTypeMaterialization(&shardless, on)
	require.NoError(t, err)
	w.denied("no execution shards", open(none0, none, 100000))
	_, err = NewTypeMaterialization(nil, on)
	require.ErrorIs(t, err, ErrInvalidTypeMaterialization)
	_, err = NewTypeMaterialization(w.effects, nil)
	require.ErrorIs(t, err, ErrInvalidTypeMaterialization)
	require.True(t, (*TypeMaterialization)(nil).IsInterfaceNil())
	// The same origin twice: one effect.
	_, _, err = owner.Open(&vmcommon.VMOutput{}, request(), 100000)
	require.NoError(t, err)
	_, err = w.meta.store.Commit()
	require.NoError(t, err)
	w.denied("opened twice from one origin", func() error {
		_, _, openErr := owner.Open(&vmcommon.VMOutput{}, request(), 100000)
		return openErr
	})
}

// The fail-closed duty G19.H-settings-read: the native SetTokenType takes an
// unreadable or malformed item for empty metadata and writes a fresh item with
// every flag false. The protected leg never lets it: the leg reads the item
// itself first, a failed read refuses the leg, and an item that is not its
// exact expected predecessor refuses it before the native call.
func TestQualSP234TypeLegDeniesWhatTheNativeSettingsReadBlurs(t *testing.T) {
	system := registryDeltaSystemAddress(1)
	token := []byte(sp232Token)
	for name, item := range map[string][]byte{"one byte": {4}, "three bytes": {4, 0, 0}, "burn-for-all set": {4, 0},
		"paused": {1, 0}, "limited transfer": {2, 0}} {
		w := sp233New(t, true)
		w.typeRequired(true)
		typeLegs, _ := w.open(core.SemiFungibleESDT)
		w.plant(1, item)
		shard := w.shards[1]
		before := shard.root()
		_, err := shard.call(sp232Input(t, system, typeLegs[1], "leg result hash"))
		require.ErrorIs(t, err, ErrInvalidAdminEffect, name)
		require.Equal(t, before, shard.root(), name)
		require.Equal(t, item, w.item(1), name+": the item is as it was")

		// The native built-in alone, on the same item: the retained failure.
		if len(item) != 2 {
			twin := sp232ShardNew(t, 1)
			account, loadErr := twin.store.LoadAccount(core.SystemAccountAddress)
			require.NoError(t, loadErr)
			require.NoError(t, account.(vmcommon.UserAccountHandler).AccountDataHandler().SaveKeyValue(sp233ItemKey, item))
			require.NoError(t, twin.store.SaveAccount(account))
			twin.native(core.ESDTSetTokenType, core.SystemAccountAddress, token, []byte(core.SemiFungibleESDT))
			require.Equal(t, []byte{0, burnReadinessTypeByte[core.SemiFungibleESDT]}, twin.value(core.SystemAccountAddress, sp233ItemKey),
				name+": the native function overwrote the malformed item with false flags")
		}
	}

	// A failed read at any native operation of the type leg, the guard's own
	// read of a dependent leg included: refused, nothing written.
	w := sp233New(t, true)
	w.typeRequired(true)
	typeLegs, _ := w.open(core.SemiFungibleESDT)
	role := w.roleLeg(core.SemiFungibleESDT, "role origin")
	shard := w.shards[1]
	for _, peer := range []bool{false, true} {
		faults := &sp232Faults{AccountsAdapter: shard.store, peer: peer}
		coordinator, err := sharding.NewMultiShardCoordinator(3, 1)
		require.NoError(t, err)
		function, err := NewAdminEffectFunction(ArgsAdminEffectFunction{Accounts: faults, Marshaller: &marshal.GogoProtoMarshalizer{},
			Hasher: shard.f.reader.accounts.args.Hasher, Classifier: shard.registry, BuiltIns: shard.builtIns, Shard: 1,
			ShardOf: coordinator.ComputeId, Domain: func() []byte { return sp232Domain }, RecordBytes: 4096})
		require.NoError(t, err)
		require.NoError(t, function.SetBindingSource(shard.binding))
		for _, leg := range []vmcommon.OutputTransfer{typeLegs[1], role} {
			snapshot := shard.store.JournalLen()
			steps := sp232Sweep(t, faults, func() { require.NoError(t, shard.store.RevertToSnapshot(snapshot)) }, shard.root, func() error {
				_, callErr := function.ProcessBuiltinFunction(nil, nil, sp232Input(t, system, leg, "leg result hash"))
				return callErr
			})
			require.Greater(t, steps, 5)
			shard.commit()
		}
	}
	require.Equal(t, sp232Roles(core.ESDTRoleLocalMint), shard.roles())
}
