package drwa

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/sharding"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	nativeBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// sp232Sweep runs one request once for every native operation it performs,
// with that operation failing. Each failure is an error of the request; the
// native caller reverts its journal, and the state is the state before.
func sp232Sweep(t *testing.T, faults *sp232Faults, revert func(), root func() []byte, run func() error) int {
	t.Helper()
	before := root()
	for at := 1; ; at++ {
		faults.at, faults.calls, faults.hit = at, 0, false
		err := run()
		if !faults.hit {
			require.NoError(t, err, "the request succeeds with no fault")
			faults.at = 0
			return at - 1
		}
		require.Error(t, err, "native operation %d failed: the request is refused", at)
		revert()
		require.Equal(t, before, root(), "operation %d", at)
	}
}

// A failed native read or write at any step is an error of that request,
// never an opened effect, a set bit, a redrive or an applied leg.
func TestQualSP232NativeFailuresDenyTheRequest(t *testing.T) {
	for _, peer := range []bool{false, true} {
		w := sp232New(t)
		faults := &sp232Faults{AccountsAdapter: w.meta.store, peer: peer}
		w.accounts = faults
		w.build()
		request := w.limited()
		var snapshot int
		revert := func() { require.NoError(t, w.meta.store.RevertToSnapshot(snapshot)) }

		snapshot = w.meta.store.JournalLen()
		var transfers []vmcommon.OutputTransfer
		var id []byte
		opened := sp232Sweep(t, faults, revert, w.metaRoot, func() error {
			output := &vmcommon.VMOutput{}
			effect, _, err := w.effects.Open(output, request, 1000)
			id, transfers = effect, sp232Transfers(output)
			return err
		})
		require.Greater(t, opened, 5)
		for shard := uint32(0); shard < 3; shard++ {
			_, err := w.shards[shard].deliver(transfers[shard])
			require.NoError(t, err)
			w.shards[shard].settle()
		}
		_, err := w.meta.store.Commit()
		require.NoError(t, err)

		snapshot = w.meta.store.JournalLen()
		redriven := sp232Sweep(t, faults, revert, w.metaRoot, func() error {
			_, redriveErr := w.effects.Redrive(&vmcommon.VMOutput{}, id, 2, 1000)
			return redriveErr
		})
		require.Greater(t, redriven, 3)

		// The acknowledgement that sets a bit, and the one that closes.
		for leg := uint32(0); leg < 3; leg++ {
			evidence := w.evidence(w.shards[leg], id, leg)
			_, err = w.meta.store.Commit()
			require.NoError(t, err)
			snapshot = w.meta.store.JournalLen()
			acknowledged := sp232Sweep(t, faults, revert, w.metaRoot, func() error {
				_, ackErr := w.effects.Acknowledge(id, leg, evidence, 35)
				return ackErr
			})
			require.Greater(t, acknowledged, 5)
		}
		open, err := w.effects.Read(id)
		require.NoError(t, err)
		require.Nil(t, open)
	}

	// The destination.
	for _, peer := range []bool{false, true} {
		for _, request := range []func(w *sp232World) AdminEffectRequest{
			func(w *sp232World) AdminEffectRequest { return w.grant(1, core.ESDTRoleLocalMint) },
			func(w *sp232World) AdminEffectRequest { return w.limited() },
		} {
			w := sp232New(t)
			shard := w.shards[1]
			faults := &sp232Faults{AccountsAdapter: shard.store, peer: peer}
			coordinator, err := sharding.NewMultiShardCoordinator(3, 1)
			require.NoError(t, err)
			function, err := NewAdminEffectFunction(ArgsAdminEffectFunction{Accounts: faults, Marshaller: &marshal.GogoProtoMarshalizer{},
				Hasher: shard.f.reader.accounts.args.Hasher, Classifier: shard.registry, BuiltIns: shard.builtIns, Shard: 1,
				ShardOf: coordinator.ComputeId, Domain: func() []byte { return sp232Domain }, RecordBytes: 4096})
			require.NoError(t, err)
			require.NoError(t, function.SetBindingSource(shard.binding))
			_, transfers := w.open(request(w))
			leg := transfers[0]
			if len(transfers) == 3 {
				leg = transfers[1]
			}
			input := sp232Input(t, registryDeltaSystemAddress(1), leg, "leg result hash")
			snapshot := shard.store.JournalLen()
			applied := sp232Sweep(t, faults, func() { require.NoError(t, shard.store.RevertToSnapshot(snapshot)) }, shard.root, func() error {
				_, callErr := function.ProcessBuiltinFunction(nil, nil, input)
				return callErr
			})
			require.Greater(t, applied, 5)
			// And the duplicate.
			snapshot = shard.store.JournalLen()
			sp232Sweep(t, faults, func() { require.NoError(t, shard.store.RevertToSnapshot(snapshot)) }, shard.root, func() error {
				_, callErr := function.ProcessBuiltinFunction(nil, nil, input)
				return callErr
			})
		}
	}
}

type sp232BuiltIn struct {
	output *vmcommon.VMOutput
	err    error
	// native, when set, runs first: the stub then is the native effect plus
	// what output adds to its outcome.
	native vmcommon.BuiltinFunction
}

func (b *sp232BuiltIn) IsInterfaceNil() bool              { return b == nil }
func (b *sp232BuiltIn) IsActive() bool                    { return true }
func (b *sp232BuiltIn) SetNewGasConfig(*vmcommon.GasCost) {}
func (b *sp232BuiltIn) ProcessBuiltinFunction(snd, dst vmcommon.UserAccountHandler, input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	if b.native != nil {
		if _, err := b.native.ProcessBuiltinFunction(snd, dst, input); err != nil {
			return nil, err
		}
	}
	return b.output, b.err
}

// "The protected wrappers execute only the exact verified inner baseline
// effect": an inner built-in that is missing, fails, returns nothing or would
// send anything onward is not that effect.
func TestQualSP232InnerEffectThatIsNotTheBaselineEffectIsRefused(t *testing.T) {
	w := sp232New(t)
	shard := w.shards[1]
	_, grant := w.open(w.grant(1, core.ESDTRoleLocalMint))
	_, limited := w.open(w.limited())
	coordinator, err := sharding.NewMultiShardCoordinator(3, 1)
	require.NoError(t, err)
	onward := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, OutputAccounts: map[string]*vmcommon.OutputAccount{"x": {Address: []byte("x")}}}
	for name, inner := range map[string]vmcommon.BuiltinFunction{
		"missing":            nil,
		"fails":              &sp232BuiltIn{err: errSP232},
		"returns nothing":    &sp232BuiltIn{},
		"native user error":  &sp232BuiltIn{output: &vmcommon.VMOutput{ReturnCode: vmcommon.UserError}},
		"sends onward":       &sp232BuiltIn{output: onward},
		"deletes an account": &sp232BuiltIn{output: &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, DeletedAccounts: [][]byte{{1}}}},
		"touches an account": &sp232BuiltIn{output: &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, TouchedAccounts: [][]byte{{1}}}},
		"changes no state":   &sp232BuiltIn{output: &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}},
	} {
		container := nativeBuiltins.NewBuiltInFunctionContainer()
		if inner != nil {
			require.NoError(t, container.Add(core.BuiltInFunctionSetESDTRole, inner))
			require.NoError(t, container.Add(core.BuiltInFunctionESDTSetLimitedTransfer, inner))
		}
		function, e := NewAdminEffectFunction(ArgsAdminEffectFunction{Accounts: shard.store, Marshaller: &marshal.GogoProtoMarshalizer{},
			Hasher: shard.f.reader.accounts.args.Hasher, Classifier: shard.registry, BuiltIns: container, Shard: 1,
			ShardOf: coordinator.ComputeId, Domain: func() []byte { return sp232Domain }, RecordBytes: 4096})
		require.NoError(t, e)
		require.NoError(t, function.SetBindingSource(shard.binding))
		for _, leg := range []vmcommon.OutputTransfer{grant[0], limited[1]} {
			before, snapshot := shard.root(), shard.store.JournalLen()
			output, callErr := function.ProcessBuiltinFunction(nil, nil, sp232Input(t, registryDeltaSystemAddress(1), leg, "leg result hash"))
			require.ErrorIs(t, callErr, ErrInvalidAdminEffect, name)
			require.Nil(t, output, name)
			require.NoError(t, shard.store.RevertToSnapshot(snapshot))
			require.Equal(t, before, shard.root(), name)
		}
	}
	// The exact native effect, with something more in its outcome: the state
	// is the expected state, and the leg is still refused.
	setRole, err := shard.builtIns.Get(core.BuiltInFunctionSetESDTRole)
	require.NoError(t, err)
	for name, more := range map[string]*vmcommon.VMOutput{
		"sends onward":       {ReturnCode: vmcommon.Ok, OutputAccounts: map[string]*vmcommon.OutputAccount{"x": {Address: []byte("x")}}},
		"deletes an account": {ReturnCode: vmcommon.Ok, DeletedAccounts: [][]byte{{1}}},
		"touches an account": {ReturnCode: vmcommon.Ok, TouchedAccounts: [][]byte{{1}}},
	} {
		container := nativeBuiltins.NewBuiltInFunctionContainer()
		require.NoError(t, container.Add(core.BuiltInFunctionSetESDTRole, &sp232BuiltIn{output: more, native: setRole}))
		function, e := NewAdminEffectFunction(ArgsAdminEffectFunction{Accounts: shard.store, Marshaller: &marshal.GogoProtoMarshalizer{},
			Hasher: shard.f.reader.accounts.args.Hasher, Classifier: shard.registry, BuiltIns: container, Shard: 1,
			ShardOf: coordinator.ComputeId, Domain: func() []byte { return sp232Domain }, RecordBytes: 4096})
		require.NoError(t, e)
		require.NoError(t, function.SetBindingSource(shard.binding))
		before, snapshot := shard.root(), shard.store.JournalLen()
		output, callErr := function.ProcessBuiltinFunction(nil, nil, sp232Input(t, registryDeltaSystemAddress(1), grant[0], "leg result hash"))
		require.ErrorIs(t, callErr, ErrInvalidAdminEffect, name)
		require.Nil(t, output, name)
		require.NoError(t, shard.store.RevertToSnapshot(snapshot))
		require.Equal(t, before, shard.root(), name)
	}

	// The real native built-in refusing its arguments: a token type it does
	// not know.
	request := w.limited()
	request.Origin = w.hash("type change origin")
	request.Payload = sp232Payload(core.ESDTSetTokenType, []byte(sp232Token), []byte("NotAType"))
	_, typed := w.open(request)
	shard.refused("native refusal", sp232Input(t, registryDeltaSystemAddress(1), typed[1], "leg result hash"))

	// An item larger than the record bound is not hashed.
	account, err := shard.store.LoadAccount(shard.holder)
	require.NoError(t, err)
	require.NoError(t, account.(vmcommon.UserAccountHandler).AccountDataHandler().SaveKeyValue(
		append([]byte(adminRolesKeyPrefix), sp232Token...), bytes.Repeat([]byte{1}, 5000)))
	require.NoError(t, shard.store.SaveAccount(account))
	shard.commit()
	shard.refused("oversized item", sp232Input(t, registryDeltaSystemAddress(1), grant[0], "leg result hash"))
}

// The context's own checks, each called as the sequence calls it.
func TestQualSP232VerifiedContextChecks(t *testing.T) {
	w := sp232New(t)
	shard := w.shards[1]
	_, transfers := w.open(w.grant(1, core.ESDTRoleLocalMint))
	input := sp232Input(t, registryDeltaSystemAddress(1), transfers[0], "leg result hash")
	context := &verifiedAdminEffectContext{function: shard.function, input: input}
	context.carrier = &adminCarrier{codec: shard.function.codec, host: context, domain: sp232Domain}
	e := w.envelope(transfers[0])
	envelope := input.Arguments[0]

	require.NoError(t, context.VerifyCanonical(envelope, []byte("leg result hash")))
	require.ErrorIs(t, context.VerifyCanonical(envelope, []byte("another result")), errAdminCarrier)
	require.ErrorIs(t, context.VerifyCanonical(append(bytes.Clone(envelope), 0), []byte("leg result hash")), errAdminCarrier)
	garbage := *context
	garbage.input = sp232Input(t, registryDeltaSystemAddress(1), sp232With(transfers[0], []byte("x")), "leg result hash")
	require.Error(t, garbage.VerifyCanonical([]byte("x"), []byte("leg result hash")))

	broken := e.copy()
	broken.payload = []byte("@@")
	_, err := context.StateHash(broken)
	require.ErrorIs(t, err, errAdminCarrier)
	_, err = context.ApplyNative(broken)
	require.ErrorIs(t, err, errAdminCarrier)
	require.ErrorIs(t, context.ValidateLocal(broken), errAdminCarrier)

	// The outcome never returns more gas than the carrier brought less the
	// retained work.
	output, err := context.Ack(e, nil, nil)
	require.NoError(t, err)
	require.Equal(t, uint64(sp232LegGas-40), output.GasRemaining)
	poor := *context
	poor.input = &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{GasProvided: 39, CallValue: big.NewInt(0)}}
	_, err = poor.Ack(e, nil, nil)
	require.ErrorIs(t, err, ErrCarrierUnderfunded)

	// T14's containment form of the sequence needs its containment owner.
	require.ErrorIs(t, (&adminCarrier{codec: shard.function.codec, host: context, domain: sp232Domain}).apply(envelope, []byte("p")), errAdminCarrier)

	// The convergence host's item read refuses the metachain and an empty key,
	// whatever the evidence; with a shard and its item key it reads the item.
	_, err = shard.deliver(transfers[0])
	require.NoError(t, err)
	shard.settle()
	id := w.effectID(w.grant(1, core.ESDTRoleLocalMint))
	evidence := w.evidence(shard, id, 0)
	_, _, err = w.meta.host.ReadFinalItem(core.MetachainShardId, w.appliedKey(id, 0), evidence)
	require.ErrorIs(t, err, errConvergence)
	_, _, err = w.meta.host.ReadFinalItem(1, nil, evidence)
	require.ErrorIs(t, err, errConvergence)
	_, _, err = w.meta.host.ReadFinalItem(1, w.appliedKey(id, 0), []byte("not evidence"))
	require.ErrorIs(t, err, errConvergence)
	origin, item, err := w.meta.host.ReadFinalItem(1, w.appliedKey(id, 0), evidence)
	require.NoError(t, err)
	require.Equal(t, envelope, item)
	require.Equal(t, shard.f.hash(shard.f.w.Account.ExecutedHeader), origin)
}

// The origin's inconsistent-state and bound refusals.
func TestQualSP232OriginBoundsAndInconsistentState(t *testing.T) {
	w := sp232New(t)
	big := bytes.Repeat([]byte{1}, 5000)
	for name, mutate := range map[string]func(*AdminEffectRequest){
		"oversized action":     func(r *AdminEffectRequest) { r.ActionID = big },
		"oversized plan":       func(r *AdminEffectRequest) { r.PlanDigest = big },
		"oversized token":      func(r *AdminEffectRequest) { r.TokenID = big },
		"oversized token type": func(r *AdminEffectRequest) { r.TokenType = big },
		"oversized operation":  func(r *AdminEffectRequest) { r.Operation = string(big) },
		"targets larger than a record": func(r *AdminEffectRequest) {
			for i := range r.Legs {
				r.Legs[i].Target = bytes.Repeat([]byte{byte(i + 1)}, 2000)
			}
		},
	} {
		request := w.limited()
		mutate(&request)
		w.denied(name, func() error { _, _, err := w.effects.Open(&vmcommon.VMOutput{}, request, 1000); return err })
	}
	// The price changes between the envelope and the funding record.
	w.prices.flip = true
	snapshot := w.meta.store.JournalLen()
	_, _, err := w.effects.Open(&vmcommon.VMOutput{}, w.limited(), 100000)
	require.ErrorIs(t, err, ErrInvalidAdminEffect)
	require.NoError(t, w.meta.store.RevertToSnapshot(snapshot))
	w.prices.flip = false

	id, transfers := w.open(w.limited())
	for shard := uint32(0); shard < 3; shard++ {
		_, err = w.shards[shard].deliver(transfers[shard])
		require.NoError(t, err)
		w.shards[shard].settle()
	}
	// The funding record already has the leg's outcome, the OpenEffect does not.
	_, err = w.funding.Outcome(AdminEffectCarrierClass, id, 1, 35)
	require.NoError(t, err)
	_, err = w.meta.store.Commit()
	require.NoError(t, err)
	w.denied("outcome without a bit", func() error {
		_, ackErr := w.acknowledge(w.shards[1], id, 1)
		require.ErrorIs(t, ackErr, ErrInvalidAdminEffect)
		return ackErr
	})
	// The OpenEffect would close while the funding record has a leg open.
	key := append([]byte(openEffectPrefix), id...)
	f, err := w.effects.codec.unframe(qualRegistryValue(t, w.meta.store, string(key)), 14)
	require.NoError(t, err)
	f[11] = []byte{0, 0, 0, 1}
	qualRecordPut(t, w.meta.store, key, qualRecordFrame(f...))
	_, err = w.meta.store.Commit()
	require.NoError(t, err)
	snapshot = w.meta.store.JournalLen()
	_, err = w.acknowledge(w.shards[0], id, 0)
	require.ErrorIs(t, err, ErrInvalidAdminEffect)
	require.False(t, errors.Is(err, ErrAdminEffectNotOpen))
	require.NoError(t, w.meta.store.RevertToSnapshot(snapshot))
	// No funding record for an open effect: no redrive.
	fresh := sp232New(t)
	freshID, _ := fresh.open(fresh.grant(1, core.ESDTRoleLocalMint))
	binding, err := fresh.funding.binding(AdminEffectCarrierClass, freshID)
	require.NoError(t, err)
	qualRecordPut(t, fresh.meta.store, append([]byte(carrierFundingPrefix), binding...), nil)
	_, err = fresh.meta.store.Commit()
	require.NoError(t, err)
	fresh.denied("no funding record", func() error {
		_, redriveErr := fresh.effects.Redrive(&vmcommon.VMOutput{}, freshID, 0, 1000)
		return redriveErr
	})
}
