package drwa

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Part A L3226: "The protected metachain ESDT/DRWA handler creates the
// OpenEffect before emitting any shard leg."
func TestQualSP232OpenEffectExistsBeforeEmission(t *testing.T) {
	w := sp232New(t)
	request := w.limited()
	id := w.effectID(request)

	// Every write of the opening happens while the output is still empty: the
	// account store is observed at each save.
	observed := &vmcommon.VMOutput{}
	watch := &sp232Faults{AccountsAdapter: w.meta.store}
	var saves, emittedAtSave int
	watch.onSave = func() {
		saves++
		emittedAtSave += len(observed.OutputAccounts)
	}
	w.accounts = watch
	w.build()
	snapshot := w.meta.store.JournalLen()
	_, _, err := w.effects.Open(observed, request, 1000)
	require.NoError(t, err)
	require.NotZero(t, saves)
	require.Zero(t, emittedAtSave, "no leg was in the output at any write")
	require.Len(t, observed.OutputAccounts, 3, "the legs follow the last write")
	open, err := w.effects.Read(id)
	require.NoError(t, err)
	require.NotNil(t, open, "the OpenEffect preceded emission")
	require.NoError(t, w.meta.store.RevertToSnapshot(snapshot))
	w.accounts = w.meta.store
	w.build()

	// An output that cannot take the legs is refused before anything is written.
	blocked := &vmcommon.VMOutput{OutputAccounts: map[string]*vmcommon.OutputAccount{"x": {Address: []byte("x"),
		OutputTransfers: []vmcommon.OutputTransfer{{Index: ^uint32(0) - 2, Value: big.NewInt(0)}}}}}
	w.denied("no room for three legs", func() error { _, _, e := w.effects.Open(blocked, request, 1000); return e })
	blocked.OutputAccounts["x"].OutputTransfers[0].Index = ^uint32(0)
	w.denied("transfer index space exhausted", func() error { _, _, e := w.effects.Open(blocked, request, 1000); return e })
	w.denied("an output account that is nil", func() error {
		_, _, e := w.effects.Open(&vmcommon.VMOutput{OutputAccounts: map[string]*vmcommon.OutputAccount{"x": nil}}, request, 1000)
		return e
	})
	require.Len(t, blocked.OutputAccounts, 1)

	// Retention fails: nothing was emitted.
	w.limits = RegistrationResourceLimits{Records: 3, RetainedBytes: 1 << 40, NewRecordsPerEpoch: 1 << 20}
	w.build()
	output := &vmcommon.VMOutput{}
	_, _, err = w.effects.Open(output, request, 1000)
	require.Error(t, err)
	require.Empty(t, output.OutputAccounts)
	require.NoError(t, w.meta.store.RevertToSnapshot(snapshot))
	w.limits = sp223Ample()
	w.build()

	// Admitted: the record is exactly the independent expectation, and the
	// legs follow every transfer the operation already had.
	output = &vmcommon.VMOutput{OutputAccounts: map[string]*vmcommon.OutputAccount{"x": {Address: []byte("x"),
		OutputTransfers: []vmcommon.OutputTransfer{{Index: 4, Value: big.NewInt(0)}}}}}
	got, remaining, err := w.effects.Open(output, request, 100+3*sp232LegGas+11)
	require.NoError(t, err)
	require.Equal(t, id, got)
	require.Equal(t, uint64(11), remaining)
	open, err = w.effects.Read(id)
	require.NoError(t, err)
	require.Equal(t, uint32(3), open.Legs)
	require.Equal(t, []byte{0}, open.Acknowledged)
	require.Equal(t, []byte(sp232Token), open.TokenID)
	require.Equal(t, request.Origin, open.Origin)
	require.Equal(t, uint64(2), open.Epoch)
	for shard := uint32(0); shard < 3; shard++ {
		transfers := output.OutputAccounts[string(registryDeltaSystemAddress(shard))].OutputTransfers
		require.Len(t, transfers, 1)
		transfer := transfers[0]
		require.Equal(t, 5+shard, transfer.Index)
		require.Equal(t, uint64(sp232LegGas), transfer.GasLimit)
		require.Zero(t, transfer.Value.Sign())
		require.Equal(t, vmData.AsynchronousCall, transfer.CallType)
		require.Equal(t, core.ESDTSCAddress, transfer.SenderAddress)
		e := w.envelope(transfer)
		require.Equal(t, id, e.effectID)
		require.Equal(t, open.Commitment, e.openCommitment)
		require.Equal(t, shard, e.targetShard)
		require.Equal(t, uint64(40), e.workLimit)
		require.Equal(t, w.fundingState(id).Identity, e.gasVersion)
		retained, legErr := w.effects.Leg(id, shard)
		require.NoError(t, legErr)
		require.Equal(t, sp232Frame(sp232Domain, e), retained, "the retained leg is the emitted envelope")
	}
	_, err = w.effects.Leg(id, 3)
	require.ErrorIs(t, err, ErrInvalidAdminEffect)
	_, err = w.effects.Leg(w.hash("unknown"), 0)
	require.ErrorIs(t, err, ErrAdminEffectNotOpen)

	// "Duplicate effect_id denies": the same effect again, while open.
	w.denied("duplicate effect", func() error {
		_, _, e := w.effects.Open(&vmcommon.VMOutput{}, request, 1000)
		return e
	})
}

// Part A 4.7.1: "each canonical matching DRWAStateAck sets its exact target
// bit atomically; duplicate matching acks are idempotent ... The effect is
// terminal only when every required bit is set."
func TestQualSP232EachAcknowledgementSetsOneBitAndTheCompleteSetCloses(t *testing.T) {
	w := sp232New(t)
	id, transfers := w.open(w.limited())
	key := append([]byte(adminTokenKeyPrefix), sp232Token...)

	// Partial and reordered: shards apply and acknowledge in the order 2, 0, 1.
	bitmaps := map[uint32][]byte{2: {4}, 0: {5}}
	for _, shard := range []uint32{2, 0} {
		output, err := w.shards[shard].deliver(transfers[shard])
		require.NoError(t, err)
		require.Equal(t, [][]byte{id, w.envelope(transfers[shard]).legID}, output.ReturnData)
		require.Equal(t, sp232TokenItem(true), w.shards[shard].value(core.SystemAccountAddress, key))
		w.shards[shard].settle()
		progress, err := w.acknowledge(w.shards[shard], id, shard)
		require.NoError(t, err)
		require.Equal(t, AdminEffectProgress{Applied: true, Remaining: 5}, progress)
		open, err := w.effects.Read(id)
		require.NoError(t, err)
		require.Equal(t, bitmaps[shard], open.Acknowledged, "only this leg's bit")
		require.Equal(t, CarrierOutcome, w.fundingState(id).Phase)

		// Duplicate acknowledgement: authenticated, then nothing.
		root, journal := w.metaRoot(), w.meta.store.JournalLen()
		progress, err = w.acknowledge(w.shards[shard], id, shard)
		require.NoError(t, err)
		require.Equal(t, AdminEffectProgress{Remaining: 35}, progress)
		require.Equal(t, root, w.metaRoot())
		require.Equal(t, journal, w.meta.store.JournalLen())
	}

	// Missing shard: the effect is open, whatever time passes.
	w.meta.block.epoch += 1000
	open, err := w.effects.Read(id)
	require.NoError(t, err)
	require.False(t, open.HasAcknowledged(1))
	require.True(t, open.HasAcknowledged(0) && open.HasAcknowledged(2))
	require.False(t, open.HasAcknowledged(3))
	require.False(t, (*OpenAdminEffect)(nil).HasAcknowledged(0))

	// An acknowledgement of a leg that was not applied: its shard has no item.
	w.shards[1].settle()
	w.meta.block.hash, w.meta.block.header = w.shards[1].f.bHash, w.shards[1].f.w.Consumer
	other := sp223Evidence(t, w.shards[1].witness(shardMemberKey([]byte(sp232Token))))
	w.denied("leg not applied", func() error {
		_, e := w.effects.Acknowledge(id, 1, other, 35)
		return e
	})

	// Closure exactly at the complete set.
	_, err = w.shards[1].deliver(transfers[1])
	require.NoError(t, err)
	w.shards[1].settle()
	progress, err := w.acknowledge(w.shards[1], id, 1)
	require.NoError(t, err)
	require.Equal(t, AdminEffectProgress{Applied: true, Closed: true, Remaining: 5}, progress)
	open, err = w.effects.Read(id)
	require.NoError(t, err)
	require.Nil(t, open, "removed in the step that set the last bit")
	require.Empty(t, qualRegistryValue(t, w.meta.store, string(append([]byte(openEffectPrefix), id...))))
	for leg := uint32(0); leg < 3; leg++ {
		require.Empty(t, qualRegistryValue(t, w.meta.store, string(w.effects.legKey(id, leg))), "and its retained legs with it")
	}
	funding := w.fundingState(id)
	require.Equal(t, CarrierTerminal, funding.Phase)
	require.Equal(t, byte(7), funding.Outcomes[0])

	// After closure: a late acknowledgement, a redrive and a second opening of
	// the same effect change nothing.
	for leg := uint32(0); leg < 3; leg++ {
		w.denied("late acknowledgement", func() error {
			_, e := w.acknowledge(w.shards[leg], id, leg)
			require.ErrorIs(t, e, ErrAdminEffectNotOpen)
			return e
		})
		w.denied("redrive after closure", func() error {
			_, e := w.effects.Redrive(&vmcommon.VMOutput{}, id, leg, 1000)
			require.ErrorIs(t, e, ErrAdminEffectNotOpen)
			return e
		})
	}
	w.denied("reopening a closed effect", func() error {
		_, _, e := w.effects.Open(&vmcommon.VMOutput{}, w.limited(), 1000)
		return e
	})
}

// Forged, foreign, unfinalized and underfunded acknowledgements (carry
// T40/EXISTING-30; Part A hostile producer requirement for acknowledgements).
func TestQualSP232AcknowledgementRefusals(t *testing.T) {
	w := sp232New(t)
	id, transfers := w.open(w.limited())
	for shard := uint32(0); shard < 3; shard++ {
		_, err := w.shards[shard].deliver(transfers[shard])
		require.NoError(t, err)
		w.shards[shard].settle()
	}
	good := w.evidence(w.shards[1], id, 1)
	tampered := bytes.Clone(good)
	tampered[len(tampered)/2] ^= 1
	foreign := w.evidence(w.shards[2], id, 2)
	w.evidence(w.shards[1], id, 1) // shard 1's consuming block is in execution

	cases := []struct {
		name     string
		effect   []byte
		leg      uint32
		evidence []byte
		provided uint64
	}{
		{"unknown effect", w.hash("unknown effect"), 1, good, 35},
		{"effect identifier of wrong size", id[:8], 1, good, 35},
		{"leg outside the set", id, 3, good, 35},
		{"evidence of another shard's leg", id, 1, foreign, 35},
		{"this shard's evidence for another leg", id, 0, good, 35},
		{"tampered evidence", id, 1, tampered, 35},
		{"empty evidence", id, 1, nil, 35},
		{"not evidence", id, 1, []byte("an acknowledgement body copied into a transaction"), 35},
		{"oversized evidence", id, 1, bytes.Repeat([]byte{1}, 1<<21), 35},
		{"too little gas for the retained completion work", id, 1, good, 29},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w.denied(c.name, func() error {
				_, err := w.effects.Acknowledge(c.effect, c.leg, c.evidence, c.provided)
				return err
			})
		})
	}
	t.Run("not final for the block in execution", func(t *testing.T) {
		hash, header := w.meta.block.hash, w.meta.block.header
		w.meta.block.hash, w.meta.block.header = w.shards[0].f.bHash, w.shards[0].f.w.Consumer
		w.denied("another consuming block", func() error {
			_, err := w.effects.Acknowledge(id, 1, good, 35)
			return err
		})
		w.meta.block.hash = nil
		w.denied("no block in execution", func() error {
			_, err := w.effects.Acknowledge(id, 1, good, 35)
			return err
		})
		w.meta.block.hash, w.meta.block.header = hash, header
	})
	t.Run("no network domain", func(t *testing.T) {
		w.domain = nil
		w.denied("acknowledge", func() error { _, err := w.effects.Acknowledge(id, 1, good, 35); return err })
		w.denied("redrive", func() error { _, err := w.effects.Redrive(&vmcommon.VMOutput{}, id, 1, 1000); return err })
		w.denied("open", func() error {
			_, _, err := w.effects.Open(&vmcommon.VMOutput{}, w.grant(1, "ESDTRoleLocalMint"), 1000)
			return err
		})
		w.domain = sp232Domain
	})
	open, err := w.effects.Read(id)
	require.NoError(t, err)
	require.Equal(t, []byte{0}, open.Acknowledged, "no refusal set a bit")
	require.Equal(t, CarrierOpen, w.fundingState(id).Phase)

	// Exactly the retained completion work is enough.
	progress, err := w.effects.Acknowledge(id, 1, good, 30)
	require.NoError(t, err)
	require.Equal(t, AdminEffectProgress{Applied: true}, progress)

	// Wrong origin: an envelope of the same effect and leg that names another
	// origin execution, were it ever applied on a shard, is not the retained
	// leg; its item acknowledges nothing.
	grant := w.grant(1, core.ESDTRoleLocalMint)
	grant.Origin = w.hash("second protected origin execution")
	grantID, legs := w.open(grant)
	forged := sp232Mutated(w, legs[0], func(e *adminEffectEnvelope) { e.origin = w.hash("another origin") })
	_, err = w.shards[1].deliver(forged)
	require.NoError(t, err, "the destination cannot tell: the metachain can")
	w.shards[1].settle()
	w.denied("item of an envelope with another origin", func() error {
		_, e := w.acknowledge(w.shards[1], grantID, 0)
		require.ErrorIs(t, e, ErrInvalidAdminEffect)
		return e
	})
}

func TestQualSP232OpenRefusals(t *testing.T) {
	w := sp232New(t)
	step := uint64(1)
	holder := w.shards[1].holder
	cases := []struct {
		name   string
		mutate func(*AdminEffectRequest)
	}{
		{"no legs", func(r *AdminEffectRequest) { r.Legs = nil }},
		{"more legs than a bitmap holds", func(r *AdminEffectRequest) { r.Legs = make([]AdminEffectLeg, 256) }},
		{"origin identity of wrong size", func(r *AdminEffectRequest) { r.Origin = []byte("short") }},
		{"payload not a call", func(r *AdminEffectRequest) { r.Payload = []byte("@@") }},
		{"empty payload", func(r *AdminEffectRequest) { r.Payload = nil }},
		{"leg for a shard that does not exist", func(r *AdminEffectRequest) { r.Legs[0].Shard = 3 }},
		{"leg for the metachain", func(r *AdminEffectRequest) { r.Legs[0].Shard = core.MetachainShardId }},
		{"legs out of order by shard", func(r *AdminEffectRequest) {
			r.Legs = append(r.Legs, AdminEffectLeg{Shard: 0, Target: holder, Predecessor: r.Legs[0].Predecessor, Result: r.Legs[0].Result})
		}},
		{"the same target twice", func(r *AdminEffectRequest) { r.Legs = append(r.Legs, r.Legs[0]) }},
		{"targets of one shard out of order", func(r *AdminEffectRequest) {
			lower := bytes.Clone(holder)
			lower[0]--
			r.Legs = append(r.Legs, AdminEffectLeg{Shard: 1, Target: lower, Predecessor: r.Legs[0].Predecessor, Result: r.Legs[0].Result})
		}},
		{"token not an identifier", func(r *AdminEffectRequest) { r.TokenID = []byte("x") }},
		{"unknown token type", func(r *AdminEffectRequest) { r.TokenType = []byte("Other") }},
		{"unknown binding kind", func(r *AdminEffectRequest) { r.Binding = "NEXT_CEB" }},
		{"unknown operation", func(r *AdminEffectRequest) { r.Operation = "DRWAOther" }},
		{"requalification without action and plan", func(r *AdminEffectRequest) { r.Operation = "DRWAApplyRequalificationAdmin" }},
		{"plan step without a plan", func(r *AdminEffectRequest) { r.PlanStep = &step }},
		{"plan without a step", func(r *AdminEffectRequest) { r.PlanDigest = w.hash("plan") }},
		{"action of wrong size", func(r *AdminEffectRequest) { r.ActionID = []byte("short") }},
		{"predecessor of wrong size", func(r *AdminEffectRequest) { r.Legs[0].Predecessor = nil }},
		{"result of wrong size", func(r *AdminEffectRequest) { r.Legs[0].Result = []byte("short") }},
		{"no target", func(r *AdminEffectRequest) { r.Legs[0].Target = nil }},
		{"oversized target", func(r *AdminEffectRequest) { r.Legs[0].Target = bytes.Repeat([]byte{1}, 5000) }},
		{"oversized payload", func(r *AdminEffectRequest) {
			r.Payload = sp232Payload(core.BuiltInFunctionSetESDTRole, []byte(sp232Token), bytes.Repeat([]byte{1}, 3000))
		}},
	}
	for _, function := range []string{core.BuiltInFunctionESDTPause, core.BuiltInFunctionESDTUnPause,
		core.BuiltInFunctionESDTFreeze, core.BuiltInFunctionESDTUnFreeze, core.BuiltInFunctionESDTWipe,
		vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, core.BuiltInFunctionESDTNFTCreateRoleTransfer,
		core.BuiltInFunctionESDTTransfer, core.BuiltInFunctionESDTLocalMint, core.ESDTMetaDataUpdate, "unknownFunction"} {
		cases = append(cases, struct {
			name   string
			mutate func(*AdminEffectRequest)
		}{"inner effect not admitted: " + function, func(r *AdminEffectRequest) {
			r.Payload = sp232Payload(function, []byte(sp232Token), []byte(core.ESDTRoleLocalMint))
		}})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			request := w.grant(1, core.ESDTRoleLocalMint)
			c.mutate(&request)
			output := &vmcommon.VMOutput{}
			w.denied(c.name, func() error {
				id, remaining, err := w.effects.Open(output, request, 1000)
				require.Nil(t, id)
				require.Zero(t, remaining)
				return err
			})
			require.Empty(t, output.OutputAccounts, "nothing emitted")
		})
	}
	request := w.grant(1, core.ESDTRoleLocalMint)
	open := func(available uint64) func() error {
		return func() error {
			_, _, err := w.effects.Open(&vmcommon.VMOutput{}, request, available)
			return err
		}
	}
	w.denied("no output to emit into", func() error { _, _, err := w.effects.Open(nil, request, 1000); return err })
	t.Run("funding", func(t *testing.T) {
		w.denied("one gas unit short", func() error {
			err := open(100 + sp232LegGas - 1)()
			require.ErrorIs(t, err, ErrCarrierUnderfunded)
			return err
		})
		w.prices.err = errSP232
		w.denied("no price for the class", open(1000))
		w.prices.err = nil
		w.prices.price.Destination = 0
		w.denied("no destination work in the price", open(1000))
		w.prices.price = sp232Price()
		w.meta.block.hash = nil
		w.denied("no block in execution", open(1000))
	})
}

// Section 13 item 6: "node restart/message-delay tests prove the pinned
// pending-result lifecycle can re-drive the same canonical admin envelope/ack
// without inventing a second authorization or applying the baseline mutation
// twice".
func TestQualSP232RestartDelayAndSameLegRedrive(t *testing.T) {
	w := sp232New(t)
	shard := w.shards[1]
	id, transfers := w.open(w.grant(1, core.ESDTRoleLocalMint))
	original := transfers[0]
	record := w.fundingState(id)

	// The metachain node restarts with the leg outstanding; a later schedule
	// prices new admissions differently.
	w.restart()
	w.prices.price = CarrierPrice{Source: 1000, Destination: 400, Success: 70, Refund: 90, Completion: 300}
	w.meta.block.epoch += 50

	refusals := []struct {
		name string
		run  func() (uint64, error)
	}{
		{"unknown effect", func() (uint64, error) { return w.effects.Redrive(&vmcommon.VMOutput{}, w.hash("unknown"), 0, 1000) }},
		{"leg outside the set", func() (uint64, error) { return w.effects.Redrive(&vmcommon.VMOutput{}, id, 1, 1000) }},
		{"no output", func() (uint64, error) { return w.effects.Redrive(nil, id, 0, 1000) }},
		{"one gas unit short of the retained source work and leg", func() (uint64, error) {
			return w.effects.Redrive(&vmcommon.VMOutput{}, id, 0, 100+sp232LegGas-1)
		}},
		{"effect identifier of wrong size", func() (uint64, error) { return w.effects.Redrive(&vmcommon.VMOutput{}, id[:4], 0, 1000) }},
	}
	for _, c := range refusals {
		t.Run(c.name, func(t *testing.T) {
			w.denied(c.name, func() error {
				remaining, err := c.run()
				require.Zero(t, remaining)
				return err
			})
		})
	}

	// Redrive: the same envelope, byte for byte, at the retained price.
	output := &vmcommon.VMOutput{}
	remaining, err := w.effects.Redrive(output, id, 0, 100+sp232LegGas+3)
	require.NoError(t, err)
	require.Equal(t, uint64(3), remaining)
	redriven := sp232Transfers(output)
	require.Len(t, redriven, 1)
	require.Equal(t, original, redriven[0], "the same canonical leg, at the retained price")
	after := w.fundingState(id)
	require.Equal(t, uint64(1), after.Redrives)
	require.Equal(t, record.Identity, after.Identity)
	require.Equal(t, record.Price, after.Price)
	open, err := w.effects.Read(id)
	require.NoError(t, err)
	require.Equal(t, []byte{0}, open.Acknowledged, "a redrive is no acknowledgement")
	require.Equal(t, uint32(1), open.Legs, "and no second effect")

	// Delay: the original and the redriven leg both arrive, in either order,
	// around a restart of the shard. One mutation.
	_, err = shard.deliver(redriven[0])
	require.NoError(t, err)
	require.Equal(t, sp232Roles(core.ESDTRoleLocalMint), shard.roles())
	applied := shard.commit()
	shard.restart()
	for range 3 {
		duplicate, dupErr := shard.deliver(original)
		require.NoError(t, dupErr)
		require.Equal(t, vmcommon.Ok, duplicate.ReturnCode)
		require.Equal(t, [][]byte{id, w.envelope(original).legID}, duplicate.ReturnData, "the same acknowledgement again")
		require.Equal(t, uint64(sp232LegGas-40), duplicate.GasRemaining)
		require.Empty(t, duplicate.Logs, "no second native effect")
	}
	require.Equal(t, sp232Roles(core.ESDTRoleLocalMint), shard.roles(), "the native role built-in appends: twice would show")
	require.Equal(t, applied, shard.commit(), "a duplicate leg writes nothing")

	// A second redrive while the acknowledgement is delayed is the same leg again.
	output = &vmcommon.VMOutput{}
	_, err = w.effects.Redrive(output, id, 0, 1000)
	require.NoError(t, err)
	require.Equal(t, original, sp232Transfers(output)[0])
	require.Equal(t, uint64(2), w.fundingState(id).Redrives)

	// The acknowledgement arrives after another metachain restart and closes
	// the effect; an acknowledged leg is not redriven.
	shard.settle()
	w.restart()
	progress, err := w.acknowledge(shard, id, 0)
	require.NoError(t, err)
	require.True(t, progress.Applied && progress.Closed)
	w.denied("redrive of a closed effect", func() error {
		_, e := w.effects.Redrive(&vmcommon.VMOutput{}, id, 0, 1000)
		return e
	})
}

// An acknowledged leg of an effect that is still open is not redriven.
func TestQualSP232AcknowledgedLegIsNotRedriven(t *testing.T) {
	w := sp232New(t)
	id, transfers := w.open(w.limited())
	_, err := w.shards[0].deliver(transfers[0])
	require.NoError(t, err)
	w.shards[0].settle()
	_, err = w.acknowledge(w.shards[0], id, 0)
	require.NoError(t, err)
	w.denied("acknowledged leg", func() error {
		_, e := w.effects.Redrive(&vmcommon.VMOutput{}, id, 0, 1000)
		require.ErrorIs(t, e, ErrInvalidAdminEffect)
		return e
	})
	output := &vmcommon.VMOutput{}
	_, err = w.effects.Redrive(output, id, 2, 1000)
	require.NoError(t, err)
	expected := transfers[2]
	expected.Index = 0 // the only transfer of the redriving operation's output
	require.Equal(t, expected, sp232Transfers(output)[0])
}

// A block that carried a leg, or an acknowledgement, is reorganised away: its
// effect leaves with it, and the same leg or acknowledgement applies once on
// the replacing chain.
func TestQualSP232ReorganisationRemovesLegAndAcknowledgement(t *testing.T) {
	w := sp232New(t)
	shard := w.shards[1]
	before := shard.commit()
	id, transfers := w.open(w.grant(1, core.ESDTRoleLocalMint))
	opened, err := w.meta.store.Commit()
	require.NoError(t, err)

	// The shard block with the leg is replaced.
	_, err = shard.deliver(transfers[0])
	require.NoError(t, err)
	carried := shard.commit()
	require.NotEqual(t, before, carried)
	require.NoError(t, shard.store.RecreateTrie(holders.NewDefaultRootHashesHolder(before)))
	require.NoError(t, shard.registry.BeginExecution())
	require.Empty(t, shard.roles(), "the role left with the block")
	require.Empty(t, shard.value(core.SystemAccountAddress, w.appliedKey(id, 0)), "and so did the applied-leg item")
	_, err = shard.deliver(transfers[0])
	require.NoError(t, err)
	require.Equal(t, sp232Roles(core.ESDTRoleLocalMint), shard.roles())
	require.Equal(t, carried, shard.commit(), "applied once, to the same state")

	// The metachain block with the acknowledgement is replaced.
	shard.settle()
	progress, err := w.acknowledge(shard, id, 0)
	require.NoError(t, err)
	require.True(t, progress.Closed)
	closed, err := w.meta.store.Commit()
	require.NoError(t, err)
	require.NoError(t, w.meta.store.RecreateTrie(holders.NewDefaultRootHashesHolder(opened)))
	w.build()
	open, err := w.effects.Read(id)
	require.NoError(t, err)
	require.Equal(t, []byte{0}, open.Acknowledged, "the bit left with the block")
	require.Equal(t, CarrierOpen, w.fundingState(id).Phase)
	progress, err = w.acknowledge(shard, id, 0)
	require.NoError(t, err)
	require.True(t, progress.Applied && progress.Closed)
	again, err := w.meta.store.Commit()
	require.NoError(t, err)
	require.Equal(t, closed, again)

	// The metachain block that opened the effect is replaced: there is no
	// effect, and the leg's item acknowledges nothing.
	require.NoError(t, w.meta.store.RecreateTrie(holders.NewDefaultRootHashesHolder(w.genesisRoot)))
	w.build()
	w.denied("acknowledgement of an effect that left with its block", func() error {
		_, e := w.acknowledge(shard, id, 0)
		require.ErrorIs(t, e, ErrAdminEffectNotOpen)
		return e
	})
}

// Part A L3272: "An A→B→A state cycle cannot make an already-applied leg fresh
// again."
func TestQualSP232AppliedLegStaysAppliedThroughAStateCycle(t *testing.T) {
	w := sp232New(t)
	shard := w.shards[1]
	_, grant := w.open(w.grant(1, core.ESDTRoleLocalMint))
	_, err := shard.deliver(grant[0])
	require.NoError(t, err)

	revoke := w.grant(1, core.ESDTRoleLocalMint)
	revoke.Origin = w.hash("the revoking origin execution")
	revoke.Payload = sp232Payload(core.BuiltInFunctionUnSetESDTRole, []byte(sp232Token), []byte(core.ESDTRoleLocalMint))
	revoke.Legs[0].Predecessor, revoke.Legs[0].Result = revoke.Legs[0].Result, revoke.Legs[0].Predecessor
	_, revoked := w.open(revoke)
	_, err = shard.deliver(revoked[0])
	require.NoError(t, err)
	require.Empty(t, shard.roles(), "back to the grant's predecessor state")

	// The grant leg again: its predecessor is current, but it was applied.
	shard.refused("grant after its revocation", sp232Input(t, registryDeltaSystemAddress(1), grant[0], "leg result hash"))
	require.Empty(t, shard.roles())
	// The revocation leg again: applied, and its result is current.
	duplicate, err := shard.deliver(revoked[0])
	require.NoError(t, err)
	require.Empty(t, duplicate.Logs)
	require.Empty(t, shard.roles())
}

// Every inner effect of the closed set, applied by its native built-in. The
// expected state of each is produced on a twin shard by the native built-in
// alone, outside this row's code.
func TestQualSP232EveryAdmittedInnerEffect(t *testing.T) {
	token := []byte(sp232Token)
	roles := append([]byte(adminRolesKeyPrefix), sp232Token...)
	nonce := append([]byte(adminNonceKeyPrefix), sp232Token...)
	global := append([]byte(adminTokenKeyPrefix), sp232Token...)
	transfer := append([]byte(adminTransferRoleKeyPrefix), sp232Token...)
	address := sp232Holder(2, 3)
	cases := []struct {
		function  string
		arguments [][]byte
		system    bool
		keys      [][]byte
		prepare   func(s *sp232Shard)
	}{
		{core.BuiltInFunctionSetESDTRole, [][]byte{token, []byte(core.ESDTRoleLocalMint), []byte(core.ESDTRoleLocalBurn)}, false, [][]byte{roles, nonce}, nil},
		{core.BuiltInFunctionSetESDTRole, [][]byte{token, []byte(core.ESDTRoleNFTCreateMultiShard)}, false, [][]byte{roles, nonce}, nil},
		{core.BuiltInFunctionUnSetESDTRole, [][]byte{token, []byte(core.ESDTRoleLocalBurn)}, false, [][]byte{roles, nonce}, func(s *sp232Shard) {
			s.native(core.BuiltInFunctionSetESDTRole, s.holder, token, []byte(core.ESDTRoleLocalMint), []byte(core.ESDTRoleLocalBurn))
		}},
		{core.BuiltInFunctionESDTSetLimitedTransfer, [][]byte{token}, true, [][]byte{global}, nil},
		{core.BuiltInFunctionESDTUnSetLimitedTransfer, [][]byte{token}, true, [][]byte{global}, func(s *sp232Shard) {
			s.native(core.BuiltInFunctionESDTSetLimitedTransfer, core.SystemAccountAddress, token)
		}},
		{vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, [][]byte{token}, true, [][]byte{global}, func(s *sp232Shard) {
			s.native(vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, core.SystemAccountAddress, token)
		}},
		{core.ESDTSetTokenType, [][]byte{token, []byte(core.NonFungibleESDTv2)}, true, [][]byte{global}, nil},
		{vmcommon.BuiltInFunctionESDTTransferRoleAddAddress, [][]byte{token, address}, true, [][]byte{transfer}, nil},
		{vmcommon.BuiltInFunctionESDTTransferRoleDeleteAddress, [][]byte{token, address}, true, [][]byte{transfer}, func(s *sp232Shard) {
			s.native(vmcommon.BuiltInFunctionESDTTransferRoleAddAddress, core.SystemAccountAddress, token, address, sp232Holder(0, 4))
		}},
	}
	seen := map[string]struct{}{}
	for _, c := range cases {
		seen[c.function] = struct{}{}
		t.Run(c.function+"/"+string(c.arguments[len(c.arguments)-1]), func(t *testing.T) {
			w := sp232New(t)
			shard, twin := w.shards[1], sp232ShardNew(t, 1)
			target := shard.holder
			if c.system {
				target = core.SystemAccountAddress
			}
			state := func(s *sp232Shard) ([]byte, [][]byte) {
				var items, values [][]byte
				for _, key := range c.keys {
					value := s.value(target, key)
					items, values = append(items, key, value), append(values, value)
				}
				return w.stateHash(target, items...), values
			}
			if c.prepare != nil {
				c.prepare(shard)
				c.prepare(twin)
			}
			predecessor, _ := state(shard)
			twin.native(c.function, target, c.arguments...)
			result, expected := state(twin)
			require.NotEqual(t, predecessor, result)

			id, transfers := w.open(AdminEffectRequest{Operation: "DRWAApplyTokenAdmin", Origin: w.hash("origin"),
				TokenID: token, TokenType: []byte(core.FungibleESDT), Binding: "CURRENT_CEB", Epoch: 2,
				Payload: sp232Payload(c.function, c.arguments...),
				Legs:    []AdminEffectLeg{{Shard: 1, Target: target, Predecessor: predecessor, Result: result}}})
			_, err := shard.deliver(transfers[0])
			require.NoError(t, err)
			_, values := state(shard)
			require.Equal(t, expected, values, "exactly the native effect")
			require.Equal(t, sp232Frame(sp232Domain, w.envelope(transfers[0])), shard.value(core.SystemAccountAddress, w.appliedKey(id, 0)))
			_, err = shard.deliver(transfers[0])
			require.NoError(t, err)
			_, values = state(shard)
			require.Equal(t, expected, values, "once")
			shard.settle()
			progress, err := w.acknowledge(shard, id, 0)
			require.NoError(t, err)
			require.True(t, progress.Closed)
		})
	}
	require.Len(t, seen, len(adminEffectLoci), "every admitted inner effect is exercised")
	for function := range adminEffectLoci {
		require.Contains(t, seen, function)
	}
}

func TestQualSP232OriginConstructionAndRecordIntegrity(t *testing.T) {
	w := sp232New(t)
	args := ArgsAdminEffects{Accounts: w.meta.store, Marshaller: &marshal.GogoProtoMarshalizer{}, Hasher: w.meta.hasher,
		Domain: func() []byte { return sp232Domain }, Funding: w.funding, Block: w.meta.block, Evidence: w.meta.host,
		Limits: sp223Ample(), RecordBytes: 4096, Shards: 3}
	other := sp223New(t, sp223Ample())
	for name, mutate := range map[string]func(*ArgsAdminEffects){
		"no domain source":   func(a *ArgsAdminEffects) { a.Domain = nil },
		"no funding":         func(a *ArgsAdminEffects) { a.Funding = nil },
		"no block source":    func(a *ArgsAdminEffects) { a.Block = nil },
		"no evidence reader": func(a *ArgsAdminEffects) { a.Evidence = nil },
		"no record limit":    func(a *ArgsAdminEffects) { a.Limits.Records = 0 },
		"no byte limit":      func(a *ArgsAdminEffects) { a.Limits.RetainedBytes = 0 },
		"no rate limit":      func(a *ArgsAdminEffects) { a.Limits.NewRecordsPerEpoch = 0 },
		"too many shards":    func(a *ArgsAdminEffects) { a.Shards = 256 },
		"no accounts":        func(a *ArgsAdminEffects) { a.Accounts = nil },
		"no record bound":    func(a *ArgsAdminEffects) { a.RecordBytes = 0 },
		"funding of another store": func(a *ArgsAdminEffects) {
			a.Accounts = other.store
		},
	} {
		bad := args
		mutate(&bad)
		effects, err := NewAdminEffects(bad)
		require.Error(t, err, name)
		require.Nil(t, effects, name)
	}
	require.True(t, (*AdminEffects)(nil).IsInterfaceNil())
	// A node configured with no execution shard can carry no leg.
	none := args
	none.Shards = 0
	shardless, err := NewAdminEffects(none)
	require.NoError(t, err)
	w.denied("no execution shards", func() error {
		_, _, e := shardless.Open(&vmcommon.VMOutput{}, w.limited(), 1000)
		return e
	})

	// A retained record that is not exactly what the owner writes refuses
	// every operation on the effect.
	id, _ := w.open(w.limited())
	key := append([]byte(openEffectPrefix), id...)
	legKey := w.effects.legKey(id, 1)
	record := bytes.Clone(qualRegistryValue(t, w.meta.store, string(key)))
	leg := bytes.Clone(qualRegistryValue(t, w.meta.store, string(legKey)))
	all := func(label string) {
		t.Helper()
		_, err := w.effects.Read(id)
		require.ErrorIs(t, err, ErrInvalidAdminEffect, label)
		_, err = w.effects.Leg(id, 1)
		require.ErrorIs(t, err, ErrInvalidAdminEffect, label)
		_, err = w.effects.Acknowledge(id, 1, []byte("e"), 35)
		require.ErrorIs(t, err, ErrInvalidAdminEffect, label)
		_, err = w.effects.Redrive(&vmcommon.VMOutput{}, id, 1, 1000)
		require.ErrorIs(t, err, ErrInvalidAdminEffect, label)
		_, _, err = w.effects.Open(&vmcommon.VMOutput{}, w.limited(), 1000)
		require.ErrorIs(t, err, ErrInvalidAdminEffect, label)
	}
	fields := func(change func([][]byte)) []byte {
		f, err := w.effects.codec.unframe(record, 14)
		require.NoError(t, err)
		change(f)
		return qualRecordFrame(f...)
	}
	for label, corrupt := range map[string][]byte{
		"truncated":                 record[:len(record)-1],
		"not a record":              []byte("x"),
		"another effect's record":   fields(func(f [][]byte) { f[1] = w.hash("other") }),
		"no legs":                   fields(func(f [][]byte) { f[11] = make([]byte, 4) }),
		"too many legs":             fields(func(f [][]byte) { f[11] = []byte{0, 0, 1, 0} }),
		"bitmap of wrong size":      fields(func(f [][]byte) { f[12] = []byte{0, 0} }),
		"bit of a leg it lacks":     fields(func(f [][]byte) { f[12] = []byte{8} }),
		"complete set still stored": fields(func(f [][]byte) { f[12] = []byte{7} }),
		"another state":             fields(func(f [][]byte) { f[13] = []byte("CLOSED") }),
		"another kind":              fields(func(f [][]byte) { f[2] = []byte("METADATA_ADMIN") }),
		"epoch of wrong size":       fields(func(f [][]byte) { f[7] = []byte{1} }),
		"leg count of wrong size":   fields(func(f [][]byte) { f[11] = []byte{1} }),
	} {
		qualRecordPut(t, w.meta.store, key, corrupt)
		all(label)
	}
	qualRecordPut(t, w.meta.store, key, record)

	// A retained leg that is missing, not an envelope, or of another effect.
	foreignID, _ := w.open(w.grant(1, core.ESDTRoleLocalMint))
	foreign := bytes.Clone(qualRegistryValue(t, w.meta.store, string(w.effects.legKey(foreignID, 0))))
	for label, corrupt := range map[string][]byte{"missing": nil, "not an envelope": []byte("x"), "another effect's leg": foreign} {
		qualRecordPut(t, w.meta.store, legKey, corrupt)
		_, err := w.effects.Acknowledge(id, 1, []byte("e"), 35)
		require.ErrorIs(t, err, ErrInvalidAdminEffect, label)
		_, err = w.effects.Redrive(&vmcommon.VMOutput{}, id, 1, 1000)
		require.ErrorIs(t, err, ErrInvalidAdminEffect, label)
	}
	qualRecordPut(t, w.meta.store, legKey, leg)
	_, err = w.effects.Read(id)
	require.NoError(t, err)

	// A retained leg that names another OpenEffect commitment acknowledges
	// nothing, even when a shard holds exactly that envelope as applied.
	e2, err := w.carrier().decode(leg)
	require.NoError(t, err)
	e2.openCommitment = w.hash("another commitment")
	recommitted, err := w.carrier().encode(e2)
	require.NoError(t, err)
	qualRecordPut(t, w.meta.store, legKey, recommitted)
	_, err = w.meta.store.Commit()
	require.NoError(t, err)
	_, legs := w.open(func() AdminEffectRequest { r := w.limited(); r.Origin = w.hash("twin origin"); return r }())
	_, err = w.shards[1].deliver(sp232With(legs[1], recommitted))
	require.NoError(t, err)
	w.shards[1].settle()
	w.denied("leg of another commitment", func() error {
		_, ackErr := w.acknowledge(w.shards[1], id, 1)
		require.ErrorIs(t, ackErr, ErrInvalidAdminEffect)
		return ackErr
	})
	qualRecordPut(t, w.meta.store, legKey, leg)
	_, err = w.meta.store.Commit()
	require.NoError(t, err)

	// A retained leg whose price is not the funding record's is not redriven,
	// and the funding owner counts nothing.
	e, err := w.carrier().decode(leg)
	require.NoError(t, err)
	e.gasVersion = w.hash("another pricing identity")
	repriced, err := w.carrier().encode(e)
	require.NoError(t, err)
	qualRecordPut(t, w.meta.store, legKey, repriced)
	_, err = w.meta.store.Commit()
	require.NoError(t, err)
	w.denied("leg at another price", func() error {
		_, redriveErr := w.effects.Redrive(&vmcommon.VMOutput{}, id, 1, 1000)
		require.ErrorIs(t, redriveErr, ErrInvalidAdminEffect)
		return redriveErr
	})
	qualRecordPut(t, w.meta.store, legKey, leg)
	_, err = w.meta.store.Commit()
	require.NoError(t, err)
	// A redrive into an output that cannot take it writes nothing either.
	w.denied("redrive into a full output", func() error {
		_, redriveErr := w.effects.Redrive(&vmcommon.VMOutput{OutputAccounts: map[string]*vmcommon.OutputAccount{"x": {
			OutputTransfers: []vmcommon.OutputTransfer{{Index: ^uint32(0)}}}}}, id, 1, 1000)
		return redriveErr
	})
	require.Zero(t, w.fundingState(id).Redrives)
}

// Part A L3272: "equal result state reached through a different leg is not
// duplicate proof." Two effects grant the same role from the same state. The
// second leg finds its result state current and no applied item of its own:
// it is refused, writes no item, and its effect cannot be acknowledged.
func TestQualSP232ResultStateReachedThroughAnotherLegIsNoDuplicate(t *testing.T) {
	w := sp232New(t)
	shard := w.shards[1]
	firstID, first := w.open(w.grant(1, core.ESDTRoleLocalMint))
	second := w.grant(1, core.ESDTRoleLocalMint)
	second.Origin = w.hash("another protected origin execution")
	secondID, other := w.open(second)
	require.NotEqual(t, firstID, secondID)

	_, err := shard.deliver(first[0])
	require.NoError(t, err)
	require.Equal(t, sp232Roles(core.ESDTRoleLocalMint), shard.roles())
	shard.refused("result state reached through another leg", sp232Input(t, registryDeltaSystemAddress(1), other[0], "leg result hash"))
	require.Empty(t, shard.value(core.SystemAccountAddress, w.appliedKey(secondID, 0)))
	require.NotEmpty(t, shard.value(core.SystemAccountAddress, w.appliedKey(firstID, 0)))

	shard.settle()
	progress, err := w.acknowledge(shard, firstID, 0)
	require.NoError(t, err)
	require.True(t, progress.Closed)
	// The first leg's item is no acknowledgement of the second effect.
	w.meta.block.hash, w.meta.block.header = shard.f.bHash, shard.f.w.Consumer
	borrowed := sp223Evidence(t, shard.witness(w.appliedKey(firstID, 0)))
	w.denied("another effect's item", func() error {
		_, ackErr := w.effects.Acknowledge(secondID, 0, borrowed, 35)
		return ackErr
	})
	open, err := w.effects.Read(secondID)
	require.NoError(t, err)
	require.Equal(t, []byte{0}, open.Acknowledged, "the second effect stays open")
}

// Part A L3314: "Demonstrate ordered delivery or a source-supported
// pending/redrive construction for both arrival orders". A leg that arrives
// before the shard holds the token's registry member is refused and leaves
// nothing; the effect stays open at its origin; the same leg, redriven after
// the member arrived, applies once.
func TestQualSP232LegBeforeItsDependencyStaysPendingAndAppliesWhenRedriven(t *testing.T) {
	w := sp232New(t)
	shard := w.shards[1]
	later := []byte("LATER-0a1b2c")
	rolesKey := append([]byte(adminRolesKeyPrefix), later...)
	hash := func(roles []byte) []byte {
		return w.stateHash(shard.holder, rolesKey, roles, append([]byte(adminNonceKeyPrefix), later...), nil)
	}
	id, transfers := w.open(AdminEffectRequest{Operation: "DRWAApplyTokenAdmin", Origin: w.hash("origin"), TokenID: later,
		TokenType: []byte(core.FungibleESDT), Binding: "CURRENT_CEB", Epoch: 2,
		Payload: sp232Payload(core.BuiltInFunctionSetESDTRole, later, []byte(core.ESDTRoleLocalMint)),
		Legs:    []AdminEffectLeg{{Shard: 1, Target: shard.holder, Predecessor: hash(nil), Result: hash(sp232Roles(core.ESDTRoleLocalMint))}}})

	// Leg first: the shard does not know the token as regulated.
	shard.refused("leg before the registry member", sp232Input(t, registryDeltaSystemAddress(1), transfers[0], "leg result hash"))
	require.Empty(t, shard.value(shard.holder, rolesKey))
	open, err := w.effects.Read(id)
	require.NoError(t, err)
	require.Equal(t, []byte{0}, open.Acknowledged)

	// The member arrives.
	_, err = shard.registry.DeltaFunction().ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{CallerAddr: core.ESDTSCAddress, CallValue: big.NewInt(0), CallType: vmData.AsynchronousCall,
			Arguments: [][]byte{later, {0, 0, 0, 0, 0, 0, 0, 1}}},
		RecipientAddr: registryDeltaSystemAddress(1), Function: RegistryDeltaFunctionName})
	require.NoError(t, err)
	shard.commit()

	// The same leg, redriven.
	output := &vmcommon.VMOutput{}
	_, err = w.effects.Redrive(output, id, 0, 1000)
	require.NoError(t, err)
	redriven := sp232Transfers(output)[0]
	require.Equal(t, transfers[0], redriven)
	_, err = shard.deliver(redriven)
	require.NoError(t, err)
	require.Equal(t, sp232Roles(core.ESDTRoleLocalMint), shard.value(shard.holder, rolesKey))
	shard.settle()
	progress, err := w.acknowledge(shard, id, 0)
	require.NoError(t, err)
	require.True(t, progress.Closed)
}
