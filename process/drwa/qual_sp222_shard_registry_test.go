package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"sort"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-22, owner decisions of 27 November (option A, then option 1): the
// registry delta is the only result a metachain registration releases, the
// shard applies it into its own journaled state and acknowledges it.

func sp222Delta(token string, ordinal uint64) *vmcommon.ContractCallInput {
	return &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress), CallValue: big.NewInt(0), GasProvided: 500,
			CallType:  vmData.AsynchronousCall,
			Arguments: [][]byte{[]byte(token), binary.BigEndian.AppendUint64(nil, ordinal)}},
		RecipientAddr: registryDeltaSystemAddress(0), Function: RegistryDeltaFunctionName,
	}
}

type sp222Effects struct {
	fail  error
	noGas bool
	calls []struct {
		token   string
		ordinal uint64
		effects []WithheldEffect
	}
}

func (e *sp222Effects) IsInterfaceNil() bool { return e == nil }

func (e *sp222Effects) AcknowledgmentGas() uint64 {
	if e.noGas {
		return 0
	}
	return 700
}

func (e *sp222Effects) Withhold(accounts state.AccountsAdapter, tokenID []byte, ordinal uint64, effects []WithheldEffect) error {
	if e.fail != nil {
		return e.fail
	}
	// As the metachain half must: kept in the registration's own journal.
	account, err := accounts.LoadAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}
	if err = account.(state.UserAccountHandler).SaveKeyValue([]byte("held@"+string(tokenID)), []byte{byte(len(effects))}); err != nil {
		return err
	}
	if err = accounts.SaveAccount(account); err != nil {
		return err
	}
	e.calls = append(e.calls, struct {
		token   string
		ordinal uint64
		effects []WithheldEffect
	}{string(tokenID), ordinal, effects})
	return nil
}

// Until the metachain half is installed the registration is as it was: the
// delta ahead of every creator result. It asks for no gas, so no shard
// acknowledges it.
func TestQualSP222RegistrationEmitsTheDeltaBeforeEveryCreatorResult(t *testing.T) {
	s := qualRegistrationStore(t, 0)
	r, c, err := NewRegistryRegistration(s, &testscommon.ShardsCoordinatorMock{NoShards: 3,
		SelfIDCalled: func() uint32 { return core.MetachainShardId }}, 4)
	require.NoError(t, err)
	owner, burnForAllShard1 := bytes.Repeat([]byte{7}, 32), registryDeltaSystemAddress(1)
	creator := func(id string) func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		return func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
			_, _, createErr := qualRegistrationCreator(t, id)(accounts)
			// The creator's own fan-out: a burn-role setting to a shard's system
			// account, the type fan-out and a transfer to the owner.
			return []byte(id), &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, OutputAccounts: map[string]*vmcommon.OutputAccount{
				string(burnForAllShard1): {Address: burnForAllShard1, OutputTransfers: []vmcommon.OutputTransfer{
					{Index: 1, Data: []byte("ESDTSetBurnRoleForAll@" + hexEncode([]byte(id)))},
					{Index: 2, Data: []byte("ESDTSetTokenType@" + hexEncode([]byte(id)))}}},
				string(owner): {Address: owner, OutputTransfers: []vmcommon.OutputTransfer{{Index: 3, Data: []byte("ESDTTransfer@" + hexEncode([]byte(id)))}}},
			}}, createErr
		}
	}
	require.NoError(t, r.RegisterToken(creator("TOKEN-abcdef")))
	require.NoError(t, r.RegisterToken(creator("TOKEN-fedcba")))
	_, outputs, err := c.Commit()
	require.NoError(t, err)
	require.Len(t, outputs, 2)
	for ordinal, output := range outputs {
		token := []string{"TOKEN-abcdef", "TOKEN-fedcba"}[ordinal]
		type indexed struct {
			index uint32
			to    []byte
			data  string
			from  []byte
			kind  vmData.CallType
			gas   uint64
		}
		var all []indexed
		for _, account := range output.OutputAccounts {
			for _, transfer := range account.OutputTransfers {
				all = append(all, indexed{transfer.Index, account.Address, string(transfer.Data), transfer.SenderAddress, transfer.CallType, transfer.GasLimit})
			}
		}
		// The order in which results are created (sortIndexedScrs).
		sort.Slice(all, func(i, j int) bool { return all[i].index < all[j].index })
		require.Len(t, all, 6)
		want := RegistryDeltaFunctionName + "@" + hexEncode([]byte(token)) + "@" + hexEncode(binary.BigEndian.AppendUint64(nil, uint64(ordinal)))
		for shard := 0; shard < 3; shard++ {
			require.Equal(t, want, all[shard].data, "result %d is the delta", shard)
			require.Equal(t, registryDeltaSystemAddress(uint32(shard)), all[shard].to)
			require.Equal(t, core.ESDTSCAddress, all[shard].from)
			require.Equal(t, vmData.AsynchronousCall, all[shard].kind)
			require.Zero(t, all[shard].gas, "nobody to acknowledge to")
		}
		require.Equal(t, "ESDTSetBurnRoleForAll@"+hexEncode([]byte(token)), all[3].data, "creator order is kept")
		require.Equal(t, "ESDTSetTokenType@"+hexEncode([]byte(token)), all[4].data)
		require.Equal(t, "ESDTTransfer@"+hexEncode([]byte(token)), all[5].data)
		seen := map[uint32]bool{}
		for _, one := range all {
			require.False(t, seen[one.index], "no two results share an index")
			seen[one.index] = true
		}
	}
}

// Owner decision of 27 November, option 1: with the metachain half installed
// a registration releases the delta and nothing else; every result of the
// creator is handed to the metachain half, which holds it until every shard
// has acknowledged.
func TestQualSP222RegistrationReleasesOnlyTheDelta(t *testing.T) {
	coordinator := &testscommon.ShardsCoordinatorMock{NoShards: 3, SelfIDCalled: func() uint32 { return core.MetachainShardId }}
	owner, burnForAllShard1 := bytes.Repeat([]byte{7}, 32), registryDeltaSystemAddress(1)
	creator := func(id string, withEffects bool) func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		return func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
			_, _, createErr := qualRegistrationCreator(t, id)(accounts)
			output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}
			if withEffects {
				// The creator's own fan-out: a burn-role setting to a shard's
				// system account, the type fan-out and a transfer to the owner.
				output.OutputAccounts = map[string]*vmcommon.OutputAccount{
					string(owner): {Address: owner, OutputTransfers: []vmcommon.OutputTransfer{{Index: 3, Data: []byte("ESDTTransfer@" + hexEncode([]byte(id)))}}},
					string(burnForAllShard1): {Address: burnForAllShard1, OutputTransfers: []vmcommon.OutputTransfer{
						{Index: 2, Data: []byte("ESDTSetTokenType@" + hexEncode([]byte(id)))},
						{Index: 1, Data: []byte("ESDTSetBurnRoleForAll@" + hexEncode([]byte(id)))}}},
				}
			}
			return []byte(id), output, createErr
		}
	}
	s := qualRegistrationStore(t, 0)
	r, c, err := NewRegistryRegistration(s, coordinator, 4)
	require.NoError(t, err)
	effects := &sp222Effects{}
	var none *sp222Effects
	require.ErrorIs(t, r.SetRegistrationEffects(nil), ErrInvalidRegistryRegistration)
	require.ErrorIs(t, r.SetRegistrationEffects(none), ErrInvalidRegistryRegistration)
	require.NoError(t, r.SetRegistrationEffects(effects))
	require.ErrorIs(t, r.SetRegistrationEffects(&sp222Effects{}), ErrInvalidRegistryRegistration, "the owner is set once")

	require.NoError(t, r.RegisterToken(creator("TOKEN-abcdef", true)))
	require.NoError(t, r.RegisterToken(creator("TOKEN-fedcba", false)))
	_, outputs, err := c.Commit()
	require.NoError(t, err)
	require.Len(t, outputs, 2)
	for ordinal, output := range outputs {
		token := []string{"TOKEN-abcdef", "TOKEN-fedcba"}[ordinal]
		want := RegistryDeltaFunctionName + "@" + hexEncode([]byte(token)) + "@" + hexEncode(binary.BigEndian.AppendUint64(nil, uint64(ordinal)))
		released := 0
		for _, account := range output.OutputAccounts {
			for _, transfer := range account.OutputTransfers {
				shard := uint32(account.Address[len(account.Address)-1])
				require.Equal(t, registryDeltaSystemAddress(shard), account.Address, "released only to a shard's system account")
				require.Equal(t, want, string(transfer.Data), "released only the delta")
				require.Equal(t, shard, transfer.Index)
				require.Equal(t, uint64(700), transfer.GasLimit, "the gas of the acknowledgment")
				require.Zero(t, transfer.GasLocked)
				require.Equal(t, vmData.AsynchronousCall, transfer.CallType, "answered by the native callback")
				member := binary.BigEndian.AppendUint64([]byte(token), uint64(ordinal))
				require.Equal(t, "@"+hexEncode(append(bytes.Clone(member), uint8(shard)))+"@"+hexEncode(member), string(transfer.AsyncData))
				require.Zero(t, transfer.Value.Sign())
				require.Equal(t, core.ESDTSCAddress, transfer.SenderAddress)
				released++
			}
		}
		require.Equal(t, 3, released, "one delta for each execution shard")
	}
	// The creator's results went to the metachain half, in creation order, and
	// what it kept is in the committed store.
	require.Len(t, effects.calls, 1, "a registration without creator results hands nothing over")
	held := effects.calls[0]
	require.Equal(t, "TOKEN-abcdef", held.token)
	require.Zero(t, held.ordinal)
	require.Len(t, held.effects, 3)
	require.Equal(t, "ESDTSetBurnRoleForAll@"+hexEncode([]byte("TOKEN-abcdef")), string(held.effects[0].Transfer.Data))
	require.Equal(t, burnForAllShard1, held.effects[0].Destination)
	require.Equal(t, "ESDTSetTokenType@"+hexEncode([]byte("TOKEN-abcdef")), string(held.effects[1].Transfer.Data))
	require.Equal(t, "ESDTTransfer@"+hexEncode([]byte("TOKEN-abcdef")), string(held.effects[2].Transfer.Data))
	require.Equal(t, owner, held.effects[2].Destination)
	account, err := s.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	kept, _, err := account.(state.UserAccountHandler).RetrieveValue([]byte("held@TOKEN-abcdef"))
	require.NoError(t, err)
	require.Equal(t, []byte{3}, kept)

	// Every refusal leaves the store at its root: no member, no count, nothing held.
	refused := func(name string, prepare func(*RegistryRegistration), create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) {
		store := qualRegistrationStore(t, 0)
		registration, _, newErr := NewRegistryRegistration(store, coordinator, 4)
		require.NoError(t, newErr)
		prepare(registration)
		before, rootErr := store.RootHash()
		require.NoError(t, rootErr)
		require.Error(t, registration.RegisterToken(create), name)
		require.Zero(t, store.JournalLen(), name)
		after, rootErr := store.RootHash()
		require.NoError(t, rootErr)
		require.Equal(t, before, after, name)
	}
	withOutput := func(accounts map[string]*vmcommon.OutputAccount) func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		return func(store state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
			_, _, createErr := qualRegistrationCreator(t, "TOKEN-abcdef")(store)
			return []byte("TOKEN-abcdef"), &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, OutputAccounts: accounts}, createErr
		}
	}
	refused("a delta without gas for its acknowledgment", func(x *RegistryRegistration) {
		require.NoError(t, x.SetRegistrationEffects(&sp222Effects{noGas: true}))
	}, creator("TOKEN-abcdef", false))
	failing := errors.New("the metachain half cannot keep the effects")
	refused("the metachain half fails", func(x *RegistryRegistration) {
		require.NoError(t, x.SetRegistrationEffects(&sp222Effects{fail: failing}))
	}, creator("TOKEN-abcdef", true))
	refused("two creator results share an index", func(x *RegistryRegistration) {
		require.NoError(t, x.SetRegistrationEffects(&sp222Effects{}))
	}, withOutput(map[string]*vmcommon.OutputAccount{
		"a": {Address: []byte("a"), OutputTransfers: []vmcommon.OutputTransfer{{Index: 1}}},
		"b": {Address: []byte("b"), OutputTransfers: []vmcommon.OutputTransfer{{Index: 1}}}}))
	refused("a nil output account", func(x *RegistryRegistration) {
		require.NoError(t, x.SetRegistrationEffects(&sp222Effects{}))
	}, withOutput(map[string]*vmcommon.OutputAccount{"x": nil}))

	out := &vmcommon.VMOutput{}
	require.ErrorIs(t, emitRegistryDelta(nil, []byte("TOKEN-abcdef"), 0, 3, 700), ErrInvalidRegistryDelta)
	require.ErrorIs(t, emitRegistryDelta(out, []byte("not a token"), 0, 3, 700), ErrInvalidRegistryDelta)
	require.ErrorIs(t, emitRegistryDelta(out, []byte("TOKEN-abcdef"), 0, 256, 700), ErrInvalidRegistryDelta)
	require.Empty(t, out.OutputAccounts)
	require.NoError(t, emitRegistryDelta(out, []byte("TOKEN-abcdef"), 0, 3, 700))
	require.ErrorIs(t, emitRegistryDelta(out, []byte("TOKEN-fedcba"), 1, 3, 700), ErrInvalidRegistryDelta, "a creator cannot supply a delta of its own")
	require.ErrorIs(t, emitRegistryDelta(&vmcommon.VMOutput{OutputAccounts: map[string]*vmcommon.OutputAccount{"x": nil}}, []byte("TOKEN-abcdef"), 0, 3, 700), ErrInvalidRegistryDelta)
	require.ErrorIs(t, emitRegistryDelta(&vmcommon.VMOutput{OutputAccounts: map[string]*vmcommon.OutputAccount{"x": {
		OutputTransfers: []vmcommon.OutputTransfer{{Index: ^uint32(0)}}}}}, []byte("TOKEN-abcdef"), 0, 3, 700), ErrInvalidRegistryDelta)

	// A creator output that already carries a delta refuses the registration,
	// with or without the metachain half.
	delta := map[string]*vmcommon.OutputAccount{
		"x": {Address: []byte("x"), OutputTransfers: []vmcommon.OutputTransfer{{Data: []byte(RegistryDeltaFunctionName + "@00")}}}}
	refused("a creator delta, without the metachain half", func(*RegistryRegistration) {}, withOutput(delta))
	refused("a creator delta, with the metachain half", func(x *RegistryRegistration) {
		require.NoError(t, x.SetRegistrationEffects(&sp222Effects{}))
	}, withOutput(delta))
}

// The outcome of a delta the shard holds is what the native processor returns
// to the metachain as the callback, and the metachain reads the shard from the
// callback's sender. (The processor itself is exercised in
// process/smartContract/processorV2, qual_sp222_registry_acknowledgment_test.go.)
func TestQualSP222HeldDeltaOutcomeAndTheMetachainReading(t *testing.T) {
	store := qualContainmentStore(t)
	registry, err := NewShardRegistry(store, 2)
	require.NoError(t, err)
	require.NoError(t, registry.BeginExecution())
	apply := registry.DeltaFunction()
	delta := func(token string, ordinal uint64) *vmcommon.ContractCallInput {
		input := sp222Delta(token, ordinal)
		input.RecipientAddr = registryDeltaSystemAddress(2)
		return input
	}
	// callback is the call the metachain ESDT system contract receives for an
	// outcome: return code first, then the returned data.
	callback := func(output *vmcommon.VMOutput) *vmcommon.ContractCallInput {
		return &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: registryDeltaSystemAddress(2), CallValue: big.NewInt(0),
			CallType: vmData.AsynchronousCallBack, Arguments: append([][]byte{{byte(output.ReturnCode)}}, output.ReturnData...)},
			RecipientAddr: bytes.Clone(core.ESDTSCAddress), Function: RegistryAcknowledgmentFunctionName}
	}
	held := func(output *vmcommon.VMOutput, token string, ordinal uint64) {
		require.Equal(t, vmcommon.Ok, output.ReturnCode)
		require.Empty(t, output.OutputAccounts, "the shard emits nothing of its own")
		require.Equal(t, uint64(500), output.GasRemaining, "all the gas of the delta stays for the callback")
		parsed, parseErr := ParseRegistryAcknowledgment(callback(output), 3)
		require.NoError(t, parseErr)
		require.Equal(t, &RegistryAcknowledgment{Shard: 2, TokenID: []byte(token), Ordinal: ordinal}, parsed)
	}

	output, err := apply.ProcessBuiltinFunction(nil, nil, delta("TOKEN-abcdef", 0))
	require.NoError(t, err)
	held(output, "TOKEN-abcdef", 0)
	output, err = apply.ProcessBuiltinFunction(nil, nil, delta("TOKEN-fedcba", 1))
	require.NoError(t, err)
	held(output, "TOKEN-fedcba", 1)
	_, err = store.Commit()
	require.NoError(t, err)
	require.NoError(t, registry.Committed())
	require.NoError(t, registry.BeginExecution())

	// A member delivered again: the same outcome, no second mutation.
	for ordinal, token := range []string{"TOKEN-abcdef", "TOKEN-fedcba"} {
		output, err = apply.ProcessBuiltinFunction(nil, nil, delta(token, uint64(ordinal)))
		require.NoError(t, err)
		held(output, token, uint64(ordinal))
		require.Zero(t, store.JournalLen(), "nothing is written twice")
	}
	// A held member under another ordinal, another token under a held ordinal,
	// a member not yet due: refused, with no outcome to acknowledge.
	for name, input := range map[string]*vmcommon.ContractCallInput{
		"held member, wrong ordinal": delta("TOKEN-abcdef", 1),
		"held member, next ordinal":  delta("TOKEN-abcdef", 2),
		"held ordinal, other token":  delta("THIRD-abcdef", 0),
		"member not yet due":         delta("THIRD-abcdef", 3),
	} {
		output, err = apply.ProcessBuiltinFunction(nil, nil, input)
		require.ErrorIs(t, err, ErrInvalidRegistryDelta, name)
		require.Nil(t, output, name)
		require.Zero(t, store.JournalLen(), name)
	}

	// The metachain accepts the callback of an applied delta from a shard's
	// system account address, and nothing else.
	good := func() *vmcommon.ContractCallInput {
		return callback(&vmcommon.VMOutput{ReturnData: [][]byte{[]byte("TOKEN-abcdef"), binary.BigEndian.AppendUint64(nil, 7)}})
	}
	parsed, err := ParseRegistryAcknowledgment(good(), 3)
	require.NoError(t, err)
	require.Equal(t, &RegistryAcknowledgment{Shard: 2, TokenID: []byte("TOKEN-abcdef"), Ordinal: 7}, parsed)
	contract := append(make([]byte, 8), bytes.Repeat([]byte{5}, 24)...)
	almost := registryDeltaSystemAddress(1)
	almost[0] ^= 1
	for name, change := range map[string]func(*vmcommon.ContractCallInput){
		"a user caller":                func(i *vmcommon.ContractCallInput) { i.CallerAddr = bytes.Repeat([]byte{1}, 32) },
		"a contract caller":            func(i *vmcommon.ContractCallInput) { i.CallerAddr = contract },
		"the metachain ESDT contract":  func(i *vmcommon.ContractCallInput) { i.CallerAddr = bytes.Clone(core.ESDTSCAddress) },
		"the unsharded system account": func(i *vmcommon.ContractCallInput) { i.CallerAddr = bytes.Clone(core.SystemAccountAddress) },
		"a shard that does not exist":  func(i *vmcommon.ContractCallInput) { i.CallerAddr = registryDeltaSystemAddress(3) },
		"not quite a system account":   func(i *vmcommon.ContractCallInput) { i.CallerAddr = almost },
		"a short caller":               func(i *vmcommon.ContractCallInput) { i.CallerAddr = i.CallerAddr[1:] },
		"no caller":                    func(i *vmcommon.ContractCallInput) { i.CallerAddr = nil },
		"a direct call":                func(i *vmcommon.ContractCallInput) { i.CallType = vmData.DirectCall },
		"an asynchronous call":         func(i *vmcommon.ContractCallInput) { i.CallType = vmData.AsynchronousCall },
		"another function":             func(i *vmcommon.ContractCallInput) { i.Function = RegistryDeltaFunctionName },
		"another recipient":            func(i *vmcommon.ContractCallInput) { i.RecipientAddr = contract },
		"with value":                   func(i *vmcommon.ContractCallInput) { i.CallValue = big.NewInt(1) },
		"no value field":               func(i *vmcommon.ContractCallInput) { i.CallValue = nil },
		"the callback of a refusal":    func(i *vmcommon.ContractCallInput) { i.Arguments[0] = []byte{byte(vmcommon.UserError)} },
		"an empty return code":         func(i *vmcommon.ContractCallInput) { i.Arguments[0] = nil },
		"no returned member":           func(i *vmcommon.ContractCallInput) { i.Arguments = i.Arguments[:1] },
		"an extra argument":            func(i *vmcommon.ContractCallInput) { i.Arguments = append(i.Arguments, []byte{1}) },
		"a short ordinal":              func(i *vmcommon.ContractCallInput) { i.Arguments[2] = []byte{1} },
		"not an identifier":            func(i *vmcommon.ContractCallInput) { i.Arguments[1] = []byte("x") },
	} {
		input := good()
		change(input)
		parsed, err = ParseRegistryAcknowledgment(input, 3)
		require.ErrorIs(t, err, ErrInvalidRegistryAcknowledgment, name)
		require.Nil(t, parsed, name)
	}
	for name, shards := range map[string]uint32{"no execution shards": 0, "fewer shards": 2, "more shards than an address": 256} {
		parsed, err = ParseRegistryAcknowledgment(good(), shards)
		require.ErrorIs(t, err, ErrInvalidRegistryAcknowledgment, name)
		require.Nil(t, parsed, name)
	}
	parsed, err = ParseRegistryAcknowledgment(nil, 3)
	require.ErrorIs(t, err, ErrInvalidRegistryAcknowledgment)
	require.Nil(t, parsed)
}

func TestQualSP222ShardRegistryLifecycle(t *testing.T) {
	store := qualContainmentStore(t) // no system account at all: a shard genesis
	registry, err := NewShardRegistry(store, 0)
	require.NoError(t, err)
	apply := registry.DeltaFunction()
	classify := func(token string) bool {
		regulated, classifyErr := registry.ClassifyToken([]byte(token))
		require.NoError(t, classifyErr)
		return regulated
	}
	_, err = registry.ClassifyToken([]byte("TOKEN-abcdef"))
	require.ErrorIs(t, err, ErrClassificationUnresolved, "before the projection is verified")

	require.NoError(t, registry.BeginExecution())
	require.False(t, classify("TOKEN-abcdef"))
	output, err := apply.ProcessBuiltinFunction(nil, nil, sp222Delta("TOKEN-abcdef", 0))
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, output.ReturnCode)
	require.Equal(t, uint64(500), output.GasRemaining, "the gas of the delta stays for its acknowledgment")
	require.True(t, classify("TOKEN-abcdef"), "visible to the rest of the same block")
	require.False(t, classify("OTHER-abcdef"))

	// The block is reverted: the member is gone with it.
	require.NoError(t, store.RevertToSnapshot(0))
	require.NoError(t, registry.BeginExecution())
	require.False(t, classify("TOKEN-abcdef"))

	// The block is committed: the member stays.
	_, err = apply.ProcessBuiltinFunction(nil, nil, sp222Delta("TOKEN-abcdef", 0))
	require.NoError(t, err)
	root, err := store.Commit()
	require.NoError(t, err)
	require.NoError(t, registry.Committed())
	require.NoError(t, registry.BeginExecution())
	require.True(t, classify("TOKEN-abcdef"))

	// Each member once, in registry order, from the metachain ESDT contract only.
	refused := func(name string, change func(*vmcommon.ContractCallInput)) {
		input := sp222Delta("TOKEN-fedcba", 1)
		change(input)
		_, refuseErr := apply.ProcessBuiltinFunction(nil, nil, input)
		require.Error(t, refuseErr, name)
		require.Zero(t, store.JournalLen(), name)
		require.False(t, classify("TOKEN-fedcba"), name)
	}
	refused("a user caller", func(i *vmcommon.ContractCallInput) { i.CallerAddr = bytes.Repeat([]byte{1}, 32) })
	refused("not a system account", func(i *vmcommon.ContractCallInput) { i.RecipientAddr = bytes.Repeat([]byte{1}, 32) })
	refused("with value", func(i *vmcommon.ContractCallInput) { i.CallValue = big.NewInt(1) })
	refused("no value field", func(i *vmcommon.ContractCallInput) { i.CallValue = nil })
	refused("not an asynchronous call", func(i *vmcommon.ContractCallInput) { i.CallType = vmData.DirectCall })
	refused("a callback", func(i *vmcommon.ContractCallInput) { i.CallType = vmData.AsynchronousCallBack })
	refused("another shard's system account", func(i *vmcommon.ContractCallInput) { i.RecipientAddr = registryDeltaSystemAddress(1) })
	refused("the unsharded system account", func(i *vmcommon.ContractCallInput) { i.RecipientAddr = bytes.Clone(core.SystemAccountAddress) })
	refused("a skipped ordinal", func(i *vmcommon.ContractCallInput) { i.Arguments[1] = binary.BigEndian.AppendUint64(nil, 2) })
	refused("a repeated ordinal", func(i *vmcommon.ContractCallInput) { i.Arguments[1] = binary.BigEndian.AppendUint64(nil, 0) })
	refused("a short ordinal", func(i *vmcommon.ContractCallInput) { i.Arguments[1] = []byte{1} })
	refused("an extra argument", func(i *vmcommon.ContractCallInput) { i.Arguments = append(i.Arguments, []byte{1}) })
	refused("not an identifier", func(i *vmcommon.ContractCallInput) { i.Arguments[0] = []byte("x") })
	_, err = apply.ProcessBuiltinFunction(nil, nil, nil)
	require.ErrorIs(t, err, ErrInvalidRegistryDelta)
	_, err = apply.ProcessBuiltinFunction(nil, nil, sp222Delta("TOKEN-abcdef", 1))
	require.ErrorIs(t, err, ErrInvalidRegistryDelta, "a member already applied")
	require.Zero(t, store.JournalLen())
	require.True(t, apply.IsActive())
	require.False(t, apply.IsInterfaceNil())
	apply.SetNewGasConfig(nil)

	// A delta whose transaction is reverted inside a block that commits: the
	// projection is rebuilt from the store at the commit.
	snapshot := store.JournalLen()
	_, err = apply.ProcessBuiltinFunction(nil, nil, sp222Delta("TOKEN-fedcba", 1))
	require.NoError(t, err)
	require.NoError(t, store.RevertToSnapshot(snapshot))
	_, err = apply.ProcessBuiltinFunction(nil, nil, sp222Delta("THIRD-abcdef", 1))
	require.NoError(t, err)
	_, err = store.Commit()
	require.NoError(t, err)
	require.NoError(t, registry.Committed())
	require.False(t, classify("TOKEN-fedcba"))
	require.True(t, classify("THIRD-abcdef"))

	// Restart: a new projection over the committed store.
	restarted, err := NewShardRegistry(store, 0)
	require.NoError(t, err)
	require.NoError(t, restarted.Committed(), "a commit before the first execution also rebuilds")
	regulated, err := restarted.ClassifyToken([]byte("THIRD-abcdef"))
	require.NoError(t, err)
	require.True(t, regulated)
	regulated, err = restarted.ClassifyToken([]byte("TOKEN-abcdef"))
	require.NoError(t, err)
	require.True(t, regulated)

	// The store moves to another root without this projection (state sync,
	// rollback): the next execution rebuilds, here to the older member set.
	require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	require.NoError(t, registry.BeginExecution())
	require.True(t, classify("TOKEN-abcdef"))
	require.False(t, classify("THIRD-abcdef"))

	var none *ShardRegistry
	require.True(t, none.IsInterfaceNil())
	require.False(t, registry.IsInterfaceNil())
	for _, bad := range []uint32{core.MetachainShardId, 256} {
		_, err = NewShardRegistry(store, bad)
		require.Error(t, err)
	}
	_, err = NewShardRegistry(nil, 0)
	require.Error(t, err)
}

// A failed read is never an empty registry: the projection stays unresolved.
func TestQualSP222ShardRegistryReadFaultsAreUnresolved(t *testing.T) {
	for _, kind := range []string{"load", "read", "root", "write", "save"} {
		for at := 1; at < 40; at++ {
			store := &sp222FaultStore{qualNativeStore: qualContainmentStore(t)}
			registry, err := NewShardRegistry(store, 0)
			require.NoError(t, err)
			require.NoError(t, registry.BeginExecution())
			apply := registry.DeltaFunction()
			_, err = apply.ProcessBuiltinFunction(nil, nil, sp222Delta("TOKEN-abcdef", 0))
			require.NoError(t, err)
			_, err = store.Commit()
			require.NoError(t, err)
			require.NoError(t, registry.Committed())

			store.kind, store.at, store.count = kind, at, 0
			_, applyErr := apply.ProcessBuiltinFunction(nil, nil, sp222Delta("TOKEN-fedcba", 1))
			fresh, _ := NewShardRegistry(store, 0)
			beginErr := fresh.BeginExecution()
			commitErr := fresh.Committed()
			reached := store.count >= at
			store.kind = ""
			if !reached {
				break
			}
			if applyErr == nil && beginErr == nil && commitErr == nil {
				t.Fatalf("%s fault %d was not reported", kind, at)
			}
			if beginErr != nil && commitErr != nil {
				_, classifyErr := fresh.ClassifyToken([]byte("TOKEN-abcdef"))
				require.ErrorIs(t, classifyErr, ErrClassificationUnresolved, "%s %d", kind, at)
			}
			if applyErr != nil {
				require.True(t, errors.Is(applyErr, errSP222Fault), "%s %d: %v", kind, at, applyErr)
			}
		}
	}

	// Damaged member state is refused, not read as a smaller registry.
	damage := func(key, value []byte) error {
		store := qualContainmentStore(t)
		registry, err := NewShardRegistry(store, 0)
		require.NoError(t, err)
		require.NoError(t, registry.BeginExecution())
		_, err = registry.DeltaFunction().ProcessBuiltinFunction(nil, nil, sp222Delta("TOKEN-abcdef", 0))
		require.NoError(t, err)
		a, err := store.LoadAccount(core.SystemAccountAddress)
		require.NoError(t, err)
		require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(key, value))
		require.NoError(t, store.SaveAccount(a))
		_, err = store.Commit()
		require.NoError(t, err)
		fresh, _ := NewShardRegistry(store, 0)
		err = fresh.BeginExecution()
		_, classifyErr := fresh.ClassifyToken([]byte("TOKEN-abcdef"))
		require.ErrorIs(t, classifyErr, ErrClassificationUnresolved)
		require.Error(t, fresh.Committed(), "a commit does not make damaged state usable")
		_, classifyErr = fresh.ClassifyToken([]byte("TOKEN-abcdef"))
		require.ErrorIs(t, classifyErr, ErrClassificationUnresolved)
		return err
	}
	marker, err := membershipKey([]byte("TOKEN-abcdef"))
	require.NoError(t, err)
	require.Error(t, damage([]byte(localMembershipCountKey), []byte{1}))
	require.Error(t, damage([]byte(localMembershipCountKey), binary.BigEndian.AppendUint64(nil, 2)))
	require.Error(t, damage(marker, []byte{2}))
	require.Error(t, damage(marker, nil))
	require.Error(t, damage(localMembershipEntryKey(0), []byte("x")))
}

type sp222FaultData struct {
	vmcommon.AccountDataHandler
	store *sp222FaultStore
}

func (d *sp222FaultData) RetrieveValue(key []byte) ([]byte, uint32, error) {
	if err := d.store.hit("read"); err != nil {
		return nil, 0, err
	}
	return d.AccountDataHandler.RetrieveValue(key)
}
func (d *sp222FaultData) SaveKeyValue(key, value []byte) error {
	if err := d.store.hit("write"); err != nil {
		return err
	}
	return d.AccountDataHandler.SaveKeyValue(key, value)
}

// AccountDataHandler exposes the native data handler with the same faults.
func (a *sp222FaultAccount) AccountDataHandler() vmcommon.AccountDataHandler {
	return &sp222FaultData{AccountDataHandler: a.UserAccountHandler.(vmcommon.UserAccountHandler).AccountDataHandler(), store: a.store}
}

func (s *sp222FaultStore) LoadAccount(address []byte) (vmcommon.AccountHandler, error) {
	if err := s.hit("load"); err != nil {
		return nil, err
	}
	a, err := s.qualNativeStore.LoadAccount(address)
	if err != nil {
		return nil, err
	}
	return &sp222FaultAccount{UserAccountHandler: a.(state.UserAccountHandler), store: s}, nil
}

type sp222ForeignAccount struct{ vmcommon.AccountHandler }

func (a *sp222ForeignAccount) IsInterfaceNil() bool { return a == nil }

type sp222ForeignStore struct{ *qualNativeStore }

func (s *sp222ForeignStore) GetExistingAccount([]byte) (vmcommon.AccountHandler, error) {
	return &sp222ForeignAccount{}, nil
}
func (s *sp222ForeignStore) LoadAccount([]byte) (vmcommon.AccountHandler, error) {
	return &sp222ForeignAccount{}, nil
}

func TestQualSP222ShardRegistryCommitAndAccountFaults(t *testing.T) {
	// The store cannot be read at the commit of a block that applied a delta.
	store := &sp222FaultStore{qualNativeStore: qualContainmentStore(t)}
	registry, err := NewShardRegistry(store, 0)
	require.NoError(t, err)
	require.NoError(t, registry.BeginExecution())
	_, err = registry.DeltaFunction().ProcessBuiltinFunction(nil, nil, sp222Delta("TOKEN-abcdef", 0))
	require.NoError(t, err)
	_, err = store.Commit()
	require.NoError(t, err)
	store.kind, store.at, store.count = "load", 1, 0
	require.ErrorIs(t, registry.Committed(), errSP222Fault)
	store.kind = ""
	_, err = registry.ClassifyToken([]byte("TOKEN-abcdef"))
	require.ErrorIs(t, err, ErrClassificationUnresolved)
	require.NoError(t, registry.BeginExecution(), "rebuilt from the store at the next execution")
	regulated, err := registry.ClassifyToken([]byte("TOKEN-abcdef"))
	require.NoError(t, err)
	require.True(t, regulated)
	store.kind, store.at, store.count = "root", 1, 0
	require.ErrorIs(t, registry.Committed(), errSP222Fault)
	store.kind = ""
	_, err = registry.ClassifyToken([]byte("TOKEN-abcdef"))
	require.ErrorIs(t, err, ErrClassificationUnresolved)

	// A store that answers with something that is not a user account.
	foreign, err := NewShardRegistry(&sp222ForeignStore{qualContainmentStore(t)}, 0)
	require.NoError(t, err)
	require.ErrorIs(t, foreign.BeginExecution(), ErrInvalidRegistryDelta)
	_, err = foreign.DeltaFunction().ProcessBuiltinFunction(nil, nil, sp222Delta("TOKEN-abcdef", 0))
	require.ErrorIs(t, err, ErrInvalidRegistryDelta)

	// The shard key is the membership key of the metachain-side code.
	key, err := membershipKey([]byte("TOKEN-abcdef"))
	require.NoError(t, err)
	require.Equal(t, key, shardMemberKey([]byte("TOKEN-abcdef")))
}
