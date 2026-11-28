package drwa

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-33 test world: SP2-32's world (real stores, native built-ins, shard
// registries, production funding owner, convergence host and result reader)
// with this row's readiness owner and bound host on the metachain. The
// metachain role reader is a fixture here; the production reader is tested
// against the real creation path in vm/systemSmartContracts.

type sp233Roles struct {
	granted map[string]bool
	err     error
	calls   int
}

func (r *sp233Roles) IsInterfaceNil() bool { return r == nil }
func (r *sp233Roles) HasBurnForAllRole(tokenID []byte) (bool, error) {
	r.calls++
	return r.granted[string(tokenID)], r.err
}

type sp233World struct {
	*sp232World
	roles     *sp233Roles
	dynamic   bool
	readiness *BurnForAllReadiness
	bound     *BurnBoundConvergenceHost
	records   *convergenceRecords
}

func sp233New(t *testing.T, dynamic bool) *sp233World {
	t.Helper()
	w := &sp233World{sp232World: sp232New(t), roles: &sp233Roles{granted: map[string]bool{}}, dynamic: dynamic}
	w.rebuild()
	return w
}

func (w *sp233World) flags() common.EnableEpochsHandler {
	if w.dynamic {
		return enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.DynamicESDTFlag)
	}
	return enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
}

// rebuild constructs this row's owners over the current metachain owners.
func (w *sp233World) rebuild() {
	w.t.Helper()
	var err error
	w.readiness, err = NewBurnForAllReadiness(w.args())
	require.NoError(w.t, err)
	require.False(w.t, w.readiness.IsInterfaceNil())
	if w.accounts != state.AccountsAdapter(w.meta.store) {
		// A fault-injecting view of the store: the readiness owner alone.
		return
	}
	w.bound, err = NewBurnBoundConvergenceHost(w.meta.host, w.readiness)
	require.NoError(w.t, err)
	require.False(w.t, w.bound.IsInterfaceNil())
	boundary, err := NewRollbackContainment(w.meta.store)
	require.NoError(w.t, err)
	w.records, err = newConvergenceRecords(w.meta.store, boundary, &marshal.GogoProtoMarshalizer{}, w.meta.hasher, 4096, 16, w.bound)
	require.NoError(w.t, err)
}

func (w *sp233World) args() ArgsBurnForAllReadiness {
	return ArgsBurnForAllReadiness{Accounts: w.accounts, Marshaller: &marshal.GogoProtoMarshalizer{}, Hasher: w.meta.hasher,
		Domain: func() []byte { return w.domain }, Effects: w.effects, Funding: w.funding, Roles: w.roles, Block: w.meta.block,
		Flags: w.flags(), Limits: w.limits, RecordBytes: 4096, Shards: 3}
}

func (w *sp233World) restart() {
	w.t.Helper()
	w.sp232World.restart()
	w.rebuild()
}

func (w *sp233World) request(family string) BurnForAllReadinessRequest {
	return BurnForAllReadinessRequest{TokenID: []byte(sp232Token), Family: []byte(family), Origin: w.hash("registration"),
		Binding: "CURRENT_CEB", Epoch: 2}
}

// open opens the readiness of the world's token and returns the legs by
// effect: the type effect's (nil without the dynamic flag) and the unset
// effect's, each indexed by shard.
func (w *sp233World) open(family string) (typeLegs, unsetLegs []vmcommon.OutputTransfer) {
	w.t.Helper()
	output := &vmcommon.VMOutput{}
	effects := uint64(1)
	if w.dynamic {
		effects = 2
	}
	remaining, err := w.readiness.Open(output, w.request(family), effects*(100+3*sp232LegGas)+9)
	require.NoError(w.t, err)
	require.Equal(w.t, uint64(9), remaining)
	transfers := sp232Transfers(output)
	require.Len(w.t, transfers, int(effects)*3)
	if w.dynamic {
		return transfers[:3], transfers[3:]
	}
	return nil, transfers
}

var sp233ItemKey = append([]byte(adminTokenKeyPrefix), sp232Token...)

func (w *sp233World) item(shard uint32) []byte {
	return w.shards[shard].value(core.SystemAccountAddress, sp233ItemKey)
}

// apply delivers one leg to its shard and settles the shard.
func (w *sp233World) apply(shard uint32, leg vmcommon.OutputTransfer) {
	w.t.Helper()
	_, err := w.shards[shard].deliver(leg)
	require.NoError(w.t, err)
	w.shards[shard].settle()
}

// acknowledge presents the evidence of every effect's leg of one shard.
func (w *sp233World) acknowledge(shard uint32) {
	w.t.Helper()
	ids, err := w.readiness.Effects([]byte(sp232Token))
	require.NoError(w.t, err)
	for _, id := range ids {
		_, err = w.sp232World.acknowledge(w.shards[shard], id, shard)
		require.NoError(w.t, err)
	}
}

// phase is the bootstrap readiness phase of the world's token, admitted by
// the family owner.
func (w *sp233World) phase(family, phase string) convergenceTransition {
	shards := []uint32{0, 1, 2}
	ids := make([][]byte, len(shards))
	for i, shard := range shards {
		ids[i] = binary.BigEndian.AppendUint32(nil, shard)
	}
	t := convergenceTransition{action: bytes.Repeat([]byte{21}, 32), digest: bytes.Repeat([]byte{22}, 32), token: []byte(sp232Token),
		target: bytes.Repeat([]byte{23}, 32), dependencies: bytes.Repeat([]byte{24}, 32),
		requiredSet: w.meta.hasher.Compute(string(qualRecordFrame(ids...))), version: 7, shards: shards,
		context: &convergencePhaseContext{family: []byte(family), phase: []byte(phase), lineage: []byte("lineage"),
			predecessor: bytes.Repeat([]byte{25}, 32)}}
	_, binding, err := w.records.encode(t)
	require.NoError(w.t, err)
	b, err := w.meta.host.decode(binding)
	require.NoError(w.t, err)
	w.meta.owner.admitted[sp223BindingID(*b)] = struct{}{}
	return t
}

// phaseAcknowledged creates the phase and credits every shard's canonical
// acknowledgement of it: everything activation needs except E10.
func (w *sp233World) phaseAcknowledged(family, phase string) convergenceTransition {
	w.t.Helper()
	t := w.phase(family, phase)
	require.NoError(w.t, w.records.create(t))
	_, binding, err := w.records.encode(t)
	require.NoError(w.t, err)
	for shard := uint32(0); shard < 3; shard++ {
		ack := sp223Acknowledge(w.t, shard, 40+uint64(shard), binding)
		w.meta.block.hash, w.meta.block.header = ack.f.bHash, ack.f.w.Consumer
		require.NoError(w.t, w.records.acknowledge(t, shard, ack.origin, ack.evidence(w.t, binding)))
	}
	return t
}

func (w *sp233World) notReady(label string) {
	w.t.Helper()
	root, journal := w.metaRoot(), w.meta.store.JournalLen()
	require.ErrorIs(w.t, w.readiness.Verify([]byte(sp232Token)), ErrBurnForAllNotReady, label)
	require.Equal(w.t, root, w.metaRoot(), label)
	require.Equal(w.t, journal, w.meta.store.JournalLen(), label)
}

var sp233Families = []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT,
	core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT}

// Part A L6388-6393: "For every supported family ... across any supported flag
// boundary; prove no metachain burn-for-all role and shard IsBurnForAll=false
// bound into bootstrap readiness." The expected item of each family is the
// native built-in's own result on a twin shard.
func TestQualSP233EveryFamilyAndTypeFlagBoundary(t *testing.T) {
	require.Len(t, burnReadinessTypeByte, len(sp233Families))
	for _, family := range sp233Families {
		for _, dynamic := range []bool{true, false} {
			name := family + "/type fan-out off"
			if dynamic {
				name = family + "/type fan-out on"
			}
			t.Run(name, func(t *testing.T) {
				w := sp233New(t, dynamic)
				// The native oracle of the expected shard item.
				twin := sp232ShardNew(t, 1)
				if dynamic {
					twin.native(core.ESDTSetTokenType, core.SystemAccountAddress, []byte(sp232Token), []byte(family))
				}
				twin.native(vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, core.SystemAccountAddress, []byte(sp232Token))
				expected := twin.value(core.SystemAccountAddress, sp233ItemKey)
				require.Len(t, expected, 2, "a positively present record")
				if dynamic {
					require.Equal(t, []byte{0, burnReadinessTypeByte[family]}, expected, "the table is the native encoding")
				} else {
					require.Equal(t, []byte{0, 0}, expected)
				}

				w.notReady("never opened")
				typeLegs, unsetLegs := w.open(family)
				w.notReady("opened, nothing delivered")
				for shard := uint32(0); shard < 3; shard++ {
					require.Empty(t, w.item(shard), "no record before the leg: its false reading is no oracle")
					if dynamic {
						w.apply(shard, typeLegs[shard])
					}
					w.apply(shard, unsetLegs[shard])
					require.Equal(t, expected, w.item(shard), "exactly the native false item")
					w.notReady("applied on the shard, not acknowledged")
					w.acknowledge(shard)
					if shard < 2 {
						w.notReady("a shard is missing")
					}
				}
				require.NoError(t, w.readiness.Verify([]byte(sp232Token)))

				// The metachain role is an authoritative fact of its own.
				w.roles.granted[sp232Token] = true
				w.notReady("metachain role present")
				w.roles.granted[sp232Token] = false
				w.roles.err = errSP232
				require.ErrorIs(t, w.readiness.Verify([]byte(sp232Token)), errSP232, "a failed role read is a denial")
				w.roles.err = nil
				require.NoError(t, w.readiness.Verify([]byte(sp232Token)))

				// A record opened for fewer shards than the node has is not
				// readiness, even with every one of its effects closed.
				key := append([]byte(burnReadinessPrefix), sp232Token...)
				record := bytes.Clone(qualRegistryValue(t, w.meta.store, string(key)))
				f, err := w.readiness.codec.unframe(record, 6)
				require.NoError(t, err)
				f[3] = []byte{0, 0, 0, 2}
				qualRecordPut(t, w.meta.store, key, qualRecordFrame(f...))
				w.roles.calls = 0
				require.ErrorIs(t, w.readiness.Verify([]byte(sp232Token)), ErrBurnForAllNotReady)
				require.Zero(t, w.roles.calls)
				qualRecordPut(t, w.meta.store, key, record)
				require.NoError(t, w.readiness.Verify([]byte(sp232Token)))
			})
		}
	}
}

// "Activation must remain denied until the complete expected ACK set exists."
// Activation is the completion of the bootstrap readiness phase. Here every
// other predicate of that phase holds from the start.
func TestQualSP233ActivationRefusedUntilEveryShardAcknowledgedTheFalseState(t *testing.T) {
	for _, dynamic := range []bool{true, false} {
		w := sp233New(t, dynamic)
		phase := w.phaseAcknowledged(ConvergenceFamilyBootstrap, "TYPE_PROFILE_READINESS")
		refused := func(label string) {
			t.Helper()
			root := w.metaRoot()
			err := w.records.complete(phase)
			require.ErrorIs(t, err, ErrBurnForAllNotReady, label)
			require.Equal(t, root, w.metaRoot(), label)
			_, progress, err := w.records.observe(phase)
			require.NoError(t, err)
			require.Equal(t, "PENDING", progress.status, label)
		}
		refused("readiness never opened")
		typeLegs, unsetLegs := w.open(core.FungibleESDT)
		_, err := w.meta.store.Commit()
		require.NoError(t, err)
		refused("no leg delivered")
		// Partial fan-out, in the order 2, 0, 1.
		for i, shard := range []uint32{2, 0, 1} {
			if dynamic {
				w.apply(shard, typeLegs[shard])
			}
			w.apply(shard, unsetLegs[shard])
			refused("applied, not acknowledged")
			if dynamic {
				// One effect's acknowledgement without the other's, in both
				// orders: on the last shard the false state first (so that the
				// unset effect is complete while the type effect is not), on
				// the others the type first.
				ids, effectsErr := w.readiness.Effects([]byte(sp232Token))
				require.NoError(t, effectsErr)
				first, second := ids[0], ids[1]
				if i == 2 {
					first, second = ids[1], ids[0]
				}
				_, err = w.sp232World.acknowledge(w.shards[shard], first, shard)
				require.NoError(t, err)
				_, err = w.meta.store.Commit()
				require.NoError(t, err)
				refused("one of the two effects acknowledged")
				_, err = w.sp232World.acknowledge(w.shards[shard], second, shard)
				require.NoError(t, err)
			} else {
				w.acknowledge(shard)
			}
			_, err = w.meta.store.Commit()
			require.NoError(t, err)
			if i < 2 {
				refused("a shard's acknowledgement is missing")
			}
		}
		// The metachain role blocks it even now.
		w.roles.granted[sp232Token] = true
		refused("metachain role present")
		w.roles.granted[sp232Token] = false
		require.NoError(t, w.records.complete(phase))
		_, progress, err := w.records.observe(phase)
		require.NoError(t, err)
		require.Equal(t, "COMPLETE", progress.status)
	}
}

// Part A L11044: "through requalification/recovery/retirement". The phases of
// those lifecycles complete under the same predicate.
func TestQualSP233LaterLifecyclePhasesNeedTheSameReadiness(t *testing.T) {
	for _, c := range [][2]string{{ConvergenceFamilyCEB, "CURRENT_ACK"}, {ConvergenceFamilyCEB, "PREPARED_ACK"},
		{ConvergenceFamilyRecoveryCEB, "CURRENT_ACK"}, {ConvergenceFamilyRetirement, "WIND_DOWN_SEALED"},
		{ConvergenceFamilyRetirement, "TERMINAL_ATTESTATION"}, {ConvergenceFamilySetup, "SETUP_SEALED"}} {
		if c[0] == ConvergenceFamilyCEB && c[1] == "CURRENT_ACK" {
			continue // the one pair with the legacy nil context; covered by PREPARED_ACK
		}
		w := sp233New(t, false)
		phase := w.phaseAcknowledged(c[0], c[1])
		require.ErrorIs(t, w.records.complete(phase), ErrBurnForAllNotReady, c[0]+"/"+c[1])
		_, unsetLegs := w.open(core.FungibleESDT)
		for shard := uint32(0); shard < 3; shard++ {
			w.apply(shard, unsetLegs[shard])
			w.acknowledge(shard)
		}
		// A role that reappears on the metachain later blocks every later phase.
		w.roles.granted[sp232Token] = true
		require.ErrorIs(t, w.records.complete(phase), ErrBurnForAllNotReady, c[0]+"/"+c[1])
		w.roles.granted[sp232Token] = false
		require.NoError(t, w.records.complete(phase), c[0]+"/"+c[1])
	}
}

// "Include delayed, reordered, duplicate and forged enable/disable effects,
// partial fan-out, restart and rollback." and E.20.3: "No delayed enable
// effect may restore burn-for-all after the state was acknowledged."
func TestQualSP233DelayedReorderedDuplicateAndForgedEffects(t *testing.T) {
	w := sp233New(t, true)
	typeLegs, unsetLegs := w.open(core.NonFungibleESDTv2)
	shard := w.shards[1]
	system := registryDeltaSystemAddress(1)
	token := []byte(sp232Token)
	admission := NewBuiltInAdmission(shard.registry)
	// raw is a native global-setting call as the shard's hook would dispatch
	// it: admission first, then the native function.
	raw := func(function string, caller []byte, arguments ...[]byte) error {
		builtIn, err := shard.builtIns.Get(function)
		require.NoError(t, err)
		input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: caller, CallValue: big.NewInt(0),
			Arguments: arguments}, RecipientAddr: system, Function: function}
		if err = admission.AdmitBuiltIn(builtIn, input); err != nil {
			return err
		}
		_, err = builtIn.ProcessBuiltinFunction(nil, nil, input)
		return err
	}
	forged := func(label string) {
		t.Helper()
		before := shard.root()
		for _, caller := range [][]byte{core.ESDTSCAddress, shard.holder, sp232Holder(1, 9)} {
			for _, function := range []string{vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll} {
				require.ErrorIs(t, raw(function, caller, token), ErrRegulatedTokenOperation, label+": "+function)
			}
			require.ErrorIs(t, raw(core.ESDTSetTokenType, caller, token, []byte(core.FungibleESDT)), ErrRegulatedTokenOperation, label)
		}
		require.Equal(t, before, shard.root(), label)
	}
	forged("before any leg")

	// Reordered: the unset leg before the type leg is refused and leaves nothing.
	shard.refused("unset before type", sp232Input(t, system, unsetLegs[1], "leg result hash"))
	require.Empty(t, w.item(1))
	// A leg of another shard, and the same data from another sender.
	shard.refused("leg of shard 2", sp232Input(t, system, unsetLegs[2], "leg result hash"))
	copied := sp232Input(t, system, typeLegs[1], "leg result hash")
	copied.CallerAddr = shard.holder
	shard.refused("copied into a user transaction", copied)

	// In order, each twice (duplicate), with forged enables between.
	for _, leg := range []vmcommon.OutputTransfer{typeLegs[1], typeLegs[1], unsetLegs[1], unsetLegs[1], typeLegs[1]} {
		_, err := shard.deliver(leg)
		require.NoError(t, err)
		forged("between legs")
	}
	require.Equal(t, []byte{0, burnReadinessTypeByte[core.NonFungibleESDTv2]}, w.item(1))
	applied := shard.commit()
	shard.settle()
	w.acknowledge(1)

	// Delayed enable after the acknowledgement: refused, the state stays false.
	forged("after the acknowledgement")
	require.Equal(t, applied, shard.commit())
	// Setting burn-for-all cannot be carried as a protected leg either.
	w.denied("enable as a protected leg", func() error {
		request := w.limited()
		request.Origin = w.hash("an enabling origin")
		request.Payload = sp232Payload(vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, token)
		_, _, err := w.effects.Open(&vmcommon.VMOutput{}, request, 100000)
		return err
	})
	w.notReady("one shard of three")

	// A shard on which an enable effect was applied before the leg (it cannot
	// be, with the member withheld first; here it is planted natively): the
	// leg finds another state than the one it expects, is refused, and the
	// shard is never acknowledged.
	planted := w.shards[2]
	planted.native(vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, core.SystemAccountAddress, token)
	planted.commit()
	planted.refused("type leg on a shard with burn-for-all set", sp232Input(t, registryDeltaSystemAddress(2), typeLegs[2], "leg result hash"))
	planted.refused("unset leg on a shard with burn-for-all set", sp232Input(t, registryDeltaSystemAddress(2), unsetLegs[2], "leg result hash"))
	require.Equal(t, []byte{4, 0}, w.item(2))

	// "A successful unset call is not the oracle": the native unset applied
	// on shard 0 outside any leg gives the false item and no acknowledgement.
	loose := w.shards[0]
	loose.native(core.ESDTSetTokenType, core.SystemAccountAddress, token, []byte(core.NonFungibleESDTv2))
	loose.native(vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, core.SystemAccountAddress, token)
	loose.settle()
	require.Equal(t, w.item(1), w.item(0), "the same false item as the acknowledged shard")
	ids, err := w.readiness.Effects(token)
	require.NoError(t, err)
	w.meta.block.hash, w.meta.block.header = loose.f.bHash, loose.f.w.Consumer
	other := sp223Evidence(t, loose.witness(sp233ItemKey))
	for _, id := range ids {
		w.denied("the false item itself is no acknowledgement", func() error {
			_, ackErr := w.effects.Acknowledge(id, 0, other, 35)
			return ackErr
		})
	}
	w.notReady("two shards without acknowledgement")
}

// Restart and rollback at each step.
func TestQualSP233RestartAndRollback(t *testing.T) {
	w := sp233New(t, false)
	token := []byte(sp232Token)
	genesis, err := w.meta.store.Commit()
	require.NoError(t, err)
	_, unsetLegs := w.open(core.SemiFungibleESDT)
	opened, err := w.meta.store.Commit()
	require.NoError(t, err)
	w.restart()
	w.notReady("after a restart with the readiness open")
	ids, err := w.readiness.Effects(token)
	require.NoError(t, err)
	require.Len(t, ids, 1)

	// A shard block that carried the leg is rolled back: no state, no item.
	shard := w.shards[0]
	before := shard.commit()
	_, err = shard.deliver(unsetLegs[0])
	require.NoError(t, err)
	shard.commit()
	require.NoError(t, shard.store.RecreateTrie(holders.NewDefaultRootHashesHolder(before)))
	require.NoError(t, shard.registry.BeginExecution())
	require.Empty(t, w.item(0))
	require.Empty(t, shard.value(core.SystemAccountAddress, w.appliedKey(ids[0], 0)), "a rolled-back block leaves no acknowledgement item")

	for s := uint32(0); s < 3; s++ {
		w.apply(s, unsetLegs[s])
		w.shards[s].restart()
		w.acknowledge(s)
		_, err = w.meta.store.Commit()
		require.NoError(t, err)
		w.restart()
		if s < 2 {
			w.notReady("after a restart with a shard missing")
		}
	}
	require.NoError(t, w.readiness.Verify(token))
	ready, err := w.meta.store.Commit()
	require.NoError(t, err)

	// The metachain block of the last acknowledgement is rolled back.
	require.NoError(t, w.meta.store.RecreateTrie(holders.NewDefaultRootHashesHolder(opened)))
	w.sp232World.build()
	w.rebuild()
	w.notReady("after the acknowledgements were rolled back")
	// The registration itself is rolled back: no readiness at all.
	require.NoError(t, w.meta.store.RecreateTrie(holders.NewDefaultRootHashesHolder(genesis)))
	w.sp232World.build()
	w.rebuild()
	w.notReady("after the registration was rolled back")
	_, err = w.readiness.Effects(token)
	require.ErrorIs(t, err, ErrBurnForAllNotReady)
	// And the committed ready state reads as ready again after a reopen.
	require.NoError(t, w.meta.store.RecreateTrie(holders.NewDefaultRootHashesHolder(ready)))
	w.sp232World.build()
	w.rebuild()
	require.NoError(t, w.readiness.Verify(token))
}

func TestQualSP233OpenRefusalsAndRecordIntegrity(t *testing.T) {
	w := sp233New(t, true)
	token := []byte(sp232Token)
	open := func(mutate func(*BurnForAllReadinessRequest), available uint64) func() error {
		return func() error {
			request := w.request(core.MetaESDT)
			mutate(&request)
			output := &vmcommon.VMOutput{}
			remaining, err := w.readiness.Open(output, request, available)
			require.Zero(t, remaining)
			require.Empty(t, output.OutputAccounts)
			return err
		}
	}
	ample := uint64(2*(100+3*sp232LegGas) + 5)
	none := func(*BurnForAllReadinessRequest) {}
	for name, mutate := range map[string]func(*BurnForAllReadinessRequest){
		"unsupported family":     func(r *BurnForAllReadinessRequest) { r.Family = []byte(core.NonFungibleESDT) },
		"no family":              func(r *BurnForAllReadinessRequest) { r.Family = nil },
		"not a token identifier": func(r *BurnForAllReadinessRequest) { r.TokenID = []byte("x") },
		"origin of wrong size":   func(r *BurnForAllReadinessRequest) { r.Origin = []byte("short") },
		"unknown binding kind":   func(r *BurnForAllReadinessRequest) { r.Binding = "NEXT_CEB" },
	} {
		w.denied(name, open(mutate, ample))
	}
	w.denied("one gas unit short of both effects", func() error {
		err := open(none, ample-6)()
		require.ErrorIs(t, err, ErrCarrierUnderfunded)
		return err
	})
	w.prices.err = errSP232
	w.denied("no price", open(none, ample))
	w.prices.err = nil
	w.prices.price.Source = ^uint64(0)
	w.denied("price overflow", open(none, ample))
	w.prices.price = sp232Price()
	w.domain = nil
	w.denied("no network domain", open(none, ample))
	w.domain = sp232Domain
	hash := w.meta.block.hash
	w.meta.block.hash = nil
	w.denied("no block in execution", open(none, ample))
	w.meta.block.hash = hash

	// Construction.
	other := sp223New(t, sp223Ample())
	for name, mutate := range map[string]func(*ArgsBurnForAllReadiness){
		"no domain source":        func(a *ArgsBurnForAllReadiness) { a.Domain = nil },
		"no effects owner":        func(a *ArgsBurnForAllReadiness) { a.Effects = nil },
		"no funding owner":        func(a *ArgsBurnForAllReadiness) { a.Funding = nil },
		"no role reader":          func(a *ArgsBurnForAllReadiness) { a.Roles = nil },
		"no block source":         func(a *ArgsBurnForAllReadiness) { a.Block = nil },
		"no flags":                func(a *ArgsBurnForAllReadiness) { a.Flags = nil },
		"no record limit":         func(a *ArgsBurnForAllReadiness) { a.Limits.Records = 0 },
		"no byte limit":           func(a *ArgsBurnForAllReadiness) { a.Limits.RetainedBytes = 0 },
		"no rate limit":           func(a *ArgsBurnForAllReadiness) { a.Limits.NewRecordsPerEpoch = 0 },
		"too many shards":         func(a *ArgsBurnForAllReadiness) { a.Shards = 256 },
		"no record bound":         func(a *ArgsBurnForAllReadiness) { a.RecordBytes = 0 },
		"owners of another store": func(a *ArgsBurnForAllReadiness) { a.Accounts = other.store },
	} {
		args := w.args()
		mutate(&args)
		owner, err := NewBurnForAllReadiness(args)
		require.Error(t, err, name)
		require.Nil(t, owner, name)
	}
	require.True(t, (*BurnForAllReadiness)(nil).IsInterfaceNil())
	require.True(t, (*BurnBoundConvergenceHost)(nil).IsInterfaceNil())
	_, err := NewBurnBoundConvergenceHost(nil, w.readiness)
	require.ErrorIs(t, err, ErrInvalidBurnForAllReadiness)
	_, err = NewBurnBoundConvergenceHost(w.meta.host, nil)
	require.ErrorIs(t, err, ErrInvalidBurnForAllReadiness)
	_, err = NewBurnBoundConvergenceHost(other.host, w.readiness)
	require.ErrorIs(t, err, ErrInvalidBurnForAllReadiness)
	// A node with no execution shard has nothing to acknowledge and is never ready.
	shardless := w.args()
	shardless.Shards = 0
	owner, err := NewBurnForAllReadiness(shardless)
	require.NoError(t, err)
	w.denied("no execution shards", func() error {
		_, openErr := owner.Open(&vmcommon.VMOutput{}, w.request(core.MetaESDT), ample)
		return openErr
	})
	require.ErrorIs(t, owner.Verify(token), ErrBurnForAllNotReady)
	require.Error(t, w.readiness.Verify([]byte("x")))
	_, err = w.bound.Complete([]byte("not a binding"), bytes.Repeat([]byte{1}, 32))
	require.Error(t, err)

	// Opened once; a second opening is refused with nothing written.
	w.open(core.MetaESDT)
	w.denied("opened twice", open(none, ample))
	w.denied("opened twice for another family", open(func(r *BurnForAllReadinessRequest) { r.Family = []byte(core.FungibleESDT) }, ample))
	w.denied("opened again from another origin", open(func(r *BurnForAllReadinessRequest) { r.Origin = w.hash("another origin") }, ample))

	// A record that is not exactly what the owner writes is never readiness.
	key := append([]byte(burnReadinessPrefix), sp232Token...)
	record := bytes.Clone(qualRegistryValue(t, w.meta.store, string(key)))
	fields := func(change func([][]byte)) []byte {
		f, e := w.readiness.codec.unframe(record, 6)
		require.NoError(t, e)
		change(f)
		return qualRecordFrame(f...)
	}
	for label, corrupt := range map[string][]byte{
		"truncated":                  record[:len(record)-1],
		"not a record":               []byte("x"),
		"another token's record":     fields(func(f [][]byte) { f[1] = []byte("OTHER-0a1b2c") }),
		"unsupported family":         fields(func(f [][]byte) { f[2] = []byte("Other") }),
		"shard count of wrong size":  fields(func(f [][]byte) { f[3] = []byte{3} }),
		"unset effect of wrong size": fields(func(f [][]byte) { f[5] = []byte("short") }),
		"type effect of wrong size":  fields(func(f [][]byte) { f[4] = []byte("short") }),
		"another tag":                fields(func(f [][]byte) { f[0] = []byte("DRWA/OTHER") }),
	} {
		qualRecordPut(t, w.meta.store, key, corrupt)
		require.ErrorIs(t, w.readiness.Verify(token), ErrInvalidBurnForAllReadiness, label)
		_, err = w.readiness.Effects(token)
		require.ErrorIs(t, err, ErrInvalidBurnForAllReadiness, label)
		_, err = w.readiness.Open(&vmcommon.VMOutput{}, w.request(core.MetaESDT), ample)
		require.ErrorIs(t, err, ErrInvalidBurnForAllReadiness, label)
	}
	// An effect whose OpenEffect is gone is closed only if its funding record
	// says every leg has its outcome: a vanished record is not readiness.
	qualRecordPut(t, w.meta.store, key, record)
	ids, err := w.readiness.Effects(token)
	require.NoError(t, err)
	for _, id := range ids {
		effectKey := append([]byte(openEffectPrefix), id...)
		require.NotEmpty(t, qualRegistryValue(t, w.meta.store, string(effectKey)))
		qualRecordPut(t, w.meta.store, effectKey, nil)
	}
	require.ErrorIs(t, w.readiness.Verify(token), ErrBurnForAllNotReady, "effects gone, funding records still open")
	for _, id := range ids {
		binding, bindErr := w.funding.binding(AdminEffectCarrierClass, id)
		require.NoError(t, bindErr)
		qualRecordPut(t, w.meta.store, append([]byte(carrierFundingPrefix), binding...), nil)
	}
	require.ErrorIs(t, w.readiness.Verify(token), ErrBurnForAllNotReady, "effects and funding records gone")

	// A record opened for another shard count than the node's is not ready.
	qualRecordPut(t, w.meta.store, key, fields(func(f [][]byte) { f[3] = []byte{0, 0, 0, 2} }))
	require.ErrorIs(t, w.readiness.Verify(token), ErrBurnForAllNotReady)
	qualRecordPut(t, w.meta.store, key, record)
}

// A failed native read or write at any step of Open or Verify is an error of
// the request, never readiness (the row's fail-closed duty for its reads).
func TestQualSP233NativeFailuresDenyTheRequest(t *testing.T) {
	for _, peer := range []bool{false, true} {
		w := sp233New(t, true)
		faults := &sp232Faults{AccountsAdapter: w.meta.store, peer: peer}
		w.accounts = faults
		w.sp232World.build()
		w.rebuild()
		token := []byte(sp232Token)
		var snapshot int
		revert := func() { require.NoError(t, w.meta.store.RevertToSnapshot(snapshot)) }
		snapshot = w.meta.store.JournalLen()
		var transfers []vmcommon.OutputTransfer
		steps := sp232Sweep(t, faults, revert, w.metaRoot, func() error {
			output := &vmcommon.VMOutput{}
			_, err := w.readiness.Open(output, w.request(core.DynamicSFTESDT), 100000)
			transfers = sp232Transfers(output)
			return err
		})
		require.Greater(t, steps, 10)
		for shard := uint32(0); shard < 3; shard++ {
			w.apply(shard, transfers[shard])
			w.apply(shard, transfers[3+shard])
			w.acknowledge(shard)
		}
		_, err := w.meta.store.Commit()
		require.NoError(t, err)
		snapshot = w.meta.store.JournalLen()
		reads := sp232Sweep(t, faults, revert, w.metaRoot, func() error { return w.readiness.Verify(token) })
		require.Greater(t, reads, 5)
		sp232Sweep(t, faults, revert, w.metaRoot, func() error {
			_, effectsErr := w.readiness.Effects(token)
			return effectsErr
		})
	}
}
