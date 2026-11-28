package processing

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	"github.com/multiversx/mx-chain-go/vm"
)

// SP2-22, option A with the owner's condition (Part A 5.1, before-first-effect)
// and option 1: on an execution shard built by the production factory, the
// registry delta of a token is applied before any operation on that token can
// take effect, because the registration releases nothing but the delta until
// every shard has acknowledged it.

const qualSP222Fresh = "FRESH-abcdef"

type qualSP222Shard struct {
	*qualSP225Shard
	handler  process.DRWAClassificationHandler
	builtIns vmcommon.BuiltInFunctionContainer
}

func qualSP222ShardNode(t *testing.T, deployment bool) *qualSP222Shard {
	t.Helper()
	sender, another := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	store := qualSP225ShardStore(t, sender)
	pcf := qualSP225Factory(t, 0, deployment, store, integrationtests.CreateInMemoryShardAccountsDB())
	// As on a network, the ESDT system contract is a metachain address.
	pcf.bootstrapComponents.ShardCoordinator().(*testscommon.ShardsCoordinatorMock).ComputeIdCalled = func(address []byte) uint32 {
		if bytes.Equal(address, core.ESDTSCAddress) {
			return core.MetachainShardId
		}
		return 0
	}
	builtIns := qualSP225BuiltIns(t, pcf, store)
	handler, err := pcf.installDRWAShardRegistry(store, builtIns.BuiltInFunctionContainer())
	require.NoError(t, err)
	factory, err := pcf.createVMFactoryShard(store, &testscommon.MissingTrieNodesNotifierStub{}, builtIns.BuiltInFunctionContainer(),
		&testscommon.ESDTTransferParserStub{}, &sync.RWMutex{}, pcf.config.SmartContractsStorage, builtIns.NFTStorageHandler(),
		builtIns.ESDTGlobalSettingsHandler(), &testscommon.EpochStartTriggerStub{})
	require.NoError(t, err)
	hook := factory.BlockChainHookImpl().(*hooks.BlockChainHookImpl)
	t.Cleanup(func() { _ = hook.Close() })
	require.NoError(t, builtIns.SetPayableHandler(hook))
	require.NoError(t, hook.SetCurrentHeader(&block.Header{Epoch: 12, Round: 440, Nonce: 5}))
	return &qualSP222Shard{qualSP225Shard: &qualSP225Shard{pcf: pcf, store: store, hook: hook, sender: sender, another: another}, handler: handler,
		builtIns: builtIns.BuiltInFunctionContainer()}
}

// qualSP222Effects is the metachain half in these tests: it keeps what the
// registration hands over.
type qualSP222Effects struct {
	held []drwa.WithheldEffect
}

func (e *qualSP222Effects) IsInterfaceNil() bool      { return e == nil }
func (e *qualSP222Effects) AcknowledgmentGas() uint64 { return 1000000 }
func (e *qualSP222Effects) Withhold(_ state.AccountsAdapter, _ []byte, _ uint64, effects []drwa.WithheldEffect) error {
	e.held = append(e.held, effects...)
	return nil
}

func qualSP222Call(t *testing.T, destination []byte, transfer vmcommon.OutputTransfer) *vmcommon.ContractCallInput {
	t.Helper()
	parts := strings.Split(string(transfer.Data), "@")
	call := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress),
		CallValue: big.NewInt(0), GasProvided: transfer.GasLimit, CallType: transfer.CallType},
		RecipientAddr: bytes.Clone(destination), Function: parts[0]}
	for _, part := range parts[1:] {
		argument, err := hex.DecodeString(part)
		require.NoError(t, err)
		call.Arguments = append(call.Arguments, argument)
	}
	return call
}

// qualSP222Released turns the output the registration releases into the calls
// this shard executes, in the order the results are created (transfer index).
func qualSP222Released(t *testing.T, output *vmcommon.VMOutput, shard uint8) []*vmcommon.ContractCallInput {
	t.Helper()
	type indexed struct {
		index uint32
		call  *vmcommon.ContractCallInput
	}
	var all []indexed
	for _, account := range output.OutputAccounts {
		if !vmcommon.IsSystemAccountAddress(account.Address) || account.Address[len(account.Address)-1] != shard {
			continue
		}
		for _, transfer := range account.OutputTransfers {
			all = append(all, indexed{transfer.Index, qualSP222Call(t, account.Address, transfer)})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].index < all[j].index })
	calls := make([]*vmcommon.ContractCallInput, 0, len(all))
	for _, one := range all {
		calls = append(calls, one.call)
	}
	return calls
}

// qualSP222Withheld is the creator's fan-out for this shard, which the
// metachain half holds until every shard has acknowledged the member.
func qualSP222Withheld(t *testing.T, held []drwa.WithheldEffect, shard uint8) []*vmcommon.ContractCallInput {
	t.Helper()
	var calls []*vmcommon.ContractCallInput
	for _, effect := range held {
		if effect.Destination[len(effect.Destination)-1] == shard {
			calls = append(calls, qualSP222Call(t, effect.Destination, effect.Transfer))
		}
	}
	return calls
}

// qualSP222Registration is a metachain registration whose creator fans out
// the burn role and the token type to every shard, as the native issuance
// does: the output it releases, and what it handed to the metachain half.
func qualSP222Registration(t *testing.T) (*vmcommon.VMOutput, []drwa.WithheldEffect) {
	t.Helper()
	store := integrationtests.CreateInMemoryShardAccountsDB()
	account, err := store.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue([]byte(core.ProtectedKeyPrefix+"DRWA@registry@count"), make([]byte, 8)))
	require.NoError(t, store.SaveAccount(account))
	_, err = store.Commit()
	require.NoError(t, err)
	registration, boundary, err := drwa.NewRegistryRegistration(store,
		&testscommon.ShardsCoordinatorMock{NoShards: 3, CurrentShard: core.MetachainShardId}, 4)
	require.NoError(t, err)
	effects := &qualSP222Effects{}
	require.NoError(t, registration.SetRegistrationEffects(effects))
	require.NoError(t, registration.RegisterToken(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, OutputAccounts: map[string]*vmcommon.OutputAccount{}}
		index := uint32(0)
		for _, function := range []string{vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, core.ESDTSetTokenType} {
			for shard := uint8(0); shard < 3; shard++ {
				address := bytes.Clone(core.SystemAccountAddress)
				address[len(address)-1] = shard
				if output.OutputAccounts[string(address)] == nil {
					output.OutputAccounts[string(address)] = &vmcommon.OutputAccount{Address: address}
				}
				data := function + "@" + hex.EncodeToString([]byte(qualSP222Fresh))
				if function == core.ESDTSetTokenType {
					data += "@" + hex.EncodeToString([]byte(core.FungibleESDT))
				}
				output.OutputAccounts[string(address)].OutputTransfers = append(output.OutputAccounts[string(address)].OutputTransfers,
					vmcommon.OutputTransfer{Index: index, Value: big.NewInt(0), Data: []byte(data)})
				index++
			}
		}
		return []byte(qualSP222Fresh), output, nil
	}))
	_, outputs, err := boundary.Commit()
	require.NoError(t, err)
	require.Len(t, outputs, 1)
	require.Len(t, effects.held, 6)
	return outputs[0], effects.held
}

func TestQualSP222InstalledShardAppliesTheDeltaBeforeTheFirstEffect(t *testing.T) {
	n := qualSP222ShardNode(t, true)
	require.NotNil(t, n.handler)

	// Before the first execution the projection is unresolved: nothing runs.
	_, err := n.hook.ProcessBuiltInFunction(n.routes(qualSP225Ordinary)["transfer"])
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.NoError(t, n.handler.BeginExecution())

	// An ordinary token is native on this shard.
	_, err = n.hook.ProcessBuiltInFunction(n.routes(qualSP225Ordinary)["transfer"])
	require.NoError(t, err)
	require.Equal(t, int64(10), n.balance(t, n.another, qualSP225Ordinary))
	_, err = n.store.Commit()
	require.NoError(t, err)
	require.NoError(t, n.handler.Committed())
	require.NoError(t, n.handler.BeginExecution())

	// A token the metachain has not delivered has no state here, and nothing a
	// user sends for its identifier takes effect.
	for name, call := range n.routes(qualSP222Fresh) {
		_, err = n.hook.ProcessBuiltInFunction(call)
		require.Error(t, err, name)
		require.Zero(t, n.store.JournalLen(), "%s left an effect", name)
	}
	// Nobody but the metachain ESDT contract can deliver a member.
	forged := n.call(drwa.RegistryDeltaFunctionName, core.SystemAccountAddress, []byte(qualSP222Fresh), make([]byte, 8))
	_, err = n.hook.ProcessBuiltInFunction(forged)
	require.ErrorIs(t, err, drwa.ErrInvalidRegistryDelta)
	require.Zero(t, n.store.JournalLen())

	// The registration releases one result to this shard, the delta. Its
	// outcome is what the native processor returns to the metachain as the
	// acknowledgment (process/smartContract/processorV2,
	// qual_sp222_registry_acknowledgment_test.go).
	output, held := qualSP222Registration(t)
	released := qualSP222Released(t, output, 0)
	require.Len(t, released, 1, "nothing but the delta is released")
	require.Equal(t, drwa.RegistryDeltaFunctionName, released[0].Function)
	outcome, err := n.hook.ProcessBuiltInFunction(released[0])
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, outcome.ReturnCode)
	require.Equal(t, [][]byte{[]byte(qualSP222Fresh), make([]byte, 8)}, outcome.ReturnData)
	require.Equal(t, released[0].GasProvided, outcome.GasRemaining)
	applied := n.store.JournalLen()
	require.NotZero(t, applied)
	// The creator's own fan-out for the token, which the metachain half holds
	// until every shard has acknowledged: when it arrives, the token is
	// already classified regulated here.
	fanOuts := qualSP222Withheld(t, held, 0)
	require.Len(t, fanOuts, 2)
	for _, fanOut := range fanOuts {
		_, err = n.hook.ProcessBuiltInFunction(fanOut)
		require.ErrorIs(t, err, drwa.ErrRegulatedTokenOperation, fanOut.Function)
		require.Equal(t, applied, n.store.JournalLen(), "%s left an effect", fanOut.Function)
	}
	// Later in the same block, and after commit and restart of the projection,
	// every public operation on the token is refused before any effect.
	check := func() {
		for name, call := range n.routes(qualSP222Fresh) {
			before := n.store.JournalLen()
			_, err = n.hook.ProcessBuiltInFunction(call)
			require.ErrorIs(t, err, drwa.ErrRegulatedTokenOperation, name)
			require.Equal(t, before, n.store.JournalLen(), name)
		}
	}
	check()
	_, err = n.store.Commit()
	require.NoError(t, err)
	require.NoError(t, n.handler.Committed())
	require.NoError(t, n.handler.BeginExecution())
	check()
	// A second delivery of the same member changes nothing and has the same
	// outcome to acknowledge.
	before, err := n.store.RootHash()
	require.NoError(t, err)
	again, err := n.hook.ProcessBuiltInFunction(released[0])
	require.NoError(t, err)
	require.Equal(t, outcome.ReturnData, again.ReturnData)
	after, err := n.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, before, after, "the state of the shard is the same")
	// The ordinary token is still native.
	_, err = n.hook.ProcessBuiltInFunction(n.routes(qualSP225Ordinary)["transfer"])
	require.NoError(t, err)
	require.Equal(t, int64(20), n.balance(t, n.another, qualSP225Ordinary))
}

// What the withholding prevents: a fan-out that reached a shard which does not
// hold the member would be applied as for an ordinary token. A shard cannot
// know of a member it was not given; the metachain releases the fan-out only
// after this shard has acknowledged.
func TestQualSP222FanOutWithoutTheMemberWouldBeNative(t *testing.T) {
	n := qualSP222ShardNode(t, true)
	require.NoError(t, n.handler.BeginExecution())
	_, held := qualSP222Registration(t)
	_, err := n.hook.ProcessBuiltInFunction(qualSP222Withheld(t, held, 0)[0])
	require.NoError(t, err, "without the delta the shard cannot know the token is regulated")
	require.NotZero(t, n.store.JournalLen())
}

func TestQualSP222ShardRegistryInstallation(t *testing.T) {
	native := qualSP222ShardNode(t, false)
	require.Nil(t, native.handler, "an ordinary node gets no registry")
	require.Nil(t, native.pcf.drwaShardRegistrySource)
	_, err := native.hook.ProcessBuiltInFunction(native.call(drwa.RegistryDeltaFunctionName, core.SystemAccountAddress, []byte(qualSP222Fresh), make([]byte, 8)))
	require.Error(t, err, "and no delta function")
	require.Zero(t, native.store.JournalLen())
	_, err = native.hook.ProcessBuiltInFunction(native.routes(qualSP225Ordinary)["transfer"])
	require.NoError(t, err)

	enabled := qualSP222ShardNode(t, true)
	require.NotNil(t, enabled.pcf.drwaShardRegistrySource)
	_, err = enabled.pcf.installDRWAShardRegistry(enabled.store, vmcommon.BuiltInFunctionContainer(nil))
	require.ErrorIs(t, err, drwa.ErrInvalidRegistryDelta, "one registry per node")

	meta := qualSP225Factory(t, core.MetachainShardId, true, enabled.store, integrationtests.CreateInMemoryShardAccountsDB())
	_, err = meta.installDRWAShardRegistry(enabled.store, vmcommon.BuiltInFunctionContainer(nil))
	require.Error(t, err, "the metachain has no shard registry")
}

// Step 2 of the before-first-effect argument, over the whole processing
// container: for an identifier that has no state on the shard, no built-in a
// shard-side sender can call changes the state. Each function is called with
// the identifier first and with plausible further arguments, to itself and to
// another account, on its own node; the committed root must equal the root of
// a node on which nothing was called.
func TestQualSP222NoShardSenderCanCreateStateForAnUndeliveredToken(t *testing.T) {
	baseline := qualSP222ShardNode(t, true)
	require.NoError(t, baseline.handler.BeginExecution())
	untouched, err := baseline.store.Commit()
	require.NoError(t, err)
	functions := baseline.builtIns.Keys()
	require.GreaterOrEqual(t, len(functions), 43, "the whole container, including the delta call")
	one, role := big.NewInt(1).Bytes(), []byte(core.ESDTRoleLocalMint)
	shapes := [][][]byte{
		{[]byte(qualSP222Fresh)},
		{[]byte(qualSP222Fresh), one},
		{[]byte(qualSP222Fresh), one, one},
		{[]byte(qualSP222Fresh), role},
		{[]byte(qualSP222Fresh), one, one, bytes.Repeat([]byte{2}, 32)},
		{bytes.Repeat([]byte{2}, 32), one, []byte(qualSP222Fresh), {0}, one},
		{[]byte(qualSP222Fresh), make([]byte, 8)},
	}
	accountOnly := map[string]bool{core.BuiltInFunctionSaveKeyValue: true, core.BuiltInFunctionSetUserName: true,
		core.BuiltInFunctionSetGuardian: true, core.BuiltInFunctionGuardAccount: true, core.BuiltInFunctionUnGuardAccount: true,
		core.BuiltInFunctionMigrateDataTrie: true, core.BuiltInFunctionClaimDeveloperRewards: true,
		core.BuiltInFunctionChangeOwnerAddress: true, "DeleteUserName": true}
	checked := 0
	for function := range functions {
		if accountOnly[function] {
			continue // these carry no token identifier
		}
		for shape, arguments := range shapes {
			for _, toSelf := range []bool{true, false} {
				n := qualSP222ShardNode(t, true)
				require.NoError(t, n.handler.BeginExecution())
				recipient := n.another
				if toSelf {
					recipient = n.sender
				}
				_, _ = n.hook.ProcessBuiltInFunction(n.call(function, recipient, arguments...))
				root, commitErr := n.store.Commit()
				require.NoError(t, commitErr)
				require.Equal(t, untouched, root, "%s shape %d toSelf %t changed the shard state", function, shape, toSelf)
				require.NoError(t, n.handler.Committed())
				regulated, classifyErr := n.pcf.drwaShardRegistrySource.ClassifyToken([]byte(qualSP222Fresh))
				require.NoError(t, classifyErr)
				require.False(t, regulated, "%s made the token a member", function)
				checked++
			}
		}
	}
	require.GreaterOrEqual(t, checked, 33*len(shapes)*2)
}
