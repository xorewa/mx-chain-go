package processing

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"path/filepath"
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

// SP2-32 through the node's own construction: the destination of protected
// admin legs is in the processing built-in container of an execution shard on
// a DRWA deployment only, behind the real blockchain hook; on the metachain
// node of such a deployment the origin owner exists beside the funding owner.

func qualSP232Leg(n *qualSP222Shard, envelope []byte) *vmcommon.ContractCallInput {
	return &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress),
		CallValue: big.NewInt(0), GasProvided: 1000, CallType: vmData.AsynchronousCall, Arguments: [][]byte{envelope},
		CurrentTxHash: []byte("leg result hash")}, RecipientAddr: qualSP232System(),
		Function: drwa.AdminEffectFunctionName}
}

// qualSP232System is the system account address of shard 0, the destination
// of the native all-shard fan-out for that shard.
func qualSP232System() []byte {
	address := bytes.Clone(core.SystemAccountAddress)
	address[len(address)-1] = 0
	return address
}

type qualSP232Prices struct{}

func (p *qualSP232Prices) IsInterfaceNil() bool { return p == nil }
func (p *qualSP232Prices) CarrierPrice(string) (drwa.CarrierPrice, error) {
	return drwa.CarrierPrice{Source: 10, Destination: 400, Success: 5, Refund: 9, Completion: 30}, nil
}

type qualSP232Block struct{}

func (b *qualSP232Block) IsInterfaceNil() bool { return b == nil }
func (b *qualSP232Block) ExecutingBlock() ([]byte, []byte, uint32, error) {
	return []byte("block"), []byte("header"), 4, nil
}

type qualSP232Evidence struct{}

func (e *qualSP232Evidence) IsInterfaceNil() bool { return e == nil }
func (e *qualSP232Evidence) ReadFinalItem(uint32, []byte, []byte) ([]byte, []byte, error) {
	return nil, nil, drwa.ErrInvalidAdminEffect
}

type qualSP232Binding struct{ seen int }

func (b *qualSP232Binding) IsInterfaceNil() bool { return b == nil }
func (b *qualSP232Binding) VerifyAdminEffect(drwa.AdminEffect) error {
	b.seen++
	return nil
}

// A real leg through the node's own hook: the origin owner emits it, the hook
// of a DRWA shard node dispatches it to the installed destination, and the
// native role built-in of the node's own container grants the role once. The
// same role call on the public path stays refused.
func TestQualSP232LegThroughTheInstalledHook(t *testing.T) {
	n := qualSP222ShardNode(t, true)
	require.NoError(t, n.handler.BeginExecution())
	identity := qualA77Identity(t)
	unit, err := n.pcf.drwaIdentityOwner.open(filepath.Join(t.TempDir(), "chain-specific"), qualA77IdentityParameters(),
		identity, qualA77IdentityFresh(identity))
	require.NoError(t, err)
	t.Cleanup(func() { _ = unit.Close() })
	binding := &qualSP232Binding{}
	require.NoError(t, drwaAdminEffectFunctionOf(n.builtIns).SetBindingSource(binding))

	// The token becomes a member of this shard's registry by the metachain's delta.
	token := []byte(qualSP222Fresh)
	delta := qualSP232Leg(n, nil)
	delta.Function, delta.Arguments = drwa.RegistryDeltaFunctionName, [][]byte{token, make([]byte, 8)}
	_, err = n.hook.ProcessBuiltInFunction(delta)
	require.NoError(t, err)
	_, err = n.store.Commit()
	require.NoError(t, err)
	require.NoError(t, n.handler.Committed())

	// The origin owner, over a metachain store of its own, with the node's
	// hasher, marshaller and network domain.
	marshaller, hasher := n.pcf.coreData.InternalMarshalizer(), n.pcf.coreData.Hasher()
	metaStore := integrationtests.CreateInMemoryShardAccountsDB()
	system, err := metaStore.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	budgetKey := []byte(core.ProtectedKeyPrefix + "DRWA@scopedAdmission@budget")
	budget := binary.BigEndian.AppendUint64(nil, 1)
	budget = binary.BigEndian.AppendUint64(budget, uint64(len(budgetKey)+32))
	budget = binary.BigEndian.AppendUint64(budget, 4)
	budget = binary.BigEndian.AppendUint64(budget, 0)
	require.NoError(t, system.(state.UserAccountHandler).SaveKeyValue(budgetKey, budget))
	require.NoError(t, metaStore.SaveAccount(system))
	_, err = metaStore.Commit()
	require.NoError(t, err)
	limits := drwa.RegistrationResourceLimits{Records: 1000, RetainedBytes: 1 << 30, NewRecordsPerEpoch: 1000}
	funding, err := drwa.NewCarrierFunding(drwa.ArgsCarrierFunding{Accounts: metaStore, Marshaller: marshaller, Hasher: hasher,
		Block: &qualSP232Block{}, Prices: &qualSP232Prices{}, Limits: limits, RecordBytes: 4096})
	require.NoError(t, err)
	effects, err := drwa.NewAdminEffects(drwa.ArgsAdminEffects{Accounts: metaStore, Marshaller: marshaller, Hasher: hasher,
		Domain: n.pcf.drwaDomain, Funding: funding, Block: &qualSP232Block{}, Evidence: &qualSP232Evidence{}, Limits: limits,
		RecordBytes: 4096, Shards: 3})
	require.NoError(t, err)
	role := []byte(core.ESDTRoleLocalMint)
	rolesKey := []byte(core.ProtectedKeyPrefix + core.ESDTRoleIdentifier + core.ESDTKeyIdentifier + qualSP222Fresh)
	granted := append([]byte{0x0a, byte(len(role))}, role...)
	stateHash := func(roles []byte) []byte {
		raw, marshalErr := marshaller.Marshal(batch.New([]byte("DRWA/ADMIN/STATE/candidate1"), identity.Domain(), n.another,
			rolesKey, roles, []byte(core.ProtectedKeyPrefix+core.ESDTNFTLatestNonceIdentifier+qualSP222Fresh), nil))
		require.NoError(t, marshalErr)
		return hasher.Compute(string(raw))
	}
	output := &vmcommon.VMOutput{}
	_, _, err = effects.Open(output, drwa.AdminEffectRequest{Operation: "DRWAApplyTokenAdmin", Origin: hasher.Compute("origin"),
		TokenID: token, TokenType: []byte(core.FungibleESDT), Binding: "CURRENT_CEB", Epoch: 2,
		Payload: []byte(core.BuiltInFunctionSetESDTRole + "@" + hex.EncodeToString(token) + "@" + hex.EncodeToString(role)),
		Legs:    []drwa.AdminEffectLeg{{Shard: 0, Target: n.another, Predecessor: stateHash(nil), Result: stateHash(granted)}}}, 100000)
	require.NoError(t, err)
	transfer := output.OutputAccounts[string(qualSP232System())].OutputTransfers[0]
	leg := qualSP222Call(t, qualSP232System(), transfer)
	leg.CurrentTxHash = []byte("leg result hash")
	roles := func() []byte {
		account, loadErr := n.store.LoadAccount(n.another)
		require.NoError(t, loadErr)
		value, _, _ := account.(state.UserAccountHandler).RetrieveValue(rolesKey)
		return value
	}

	// The role call itself, on the public path, as the metachain would have
	// sent it natively: refused for the regulated token.
	public := n.call(core.BuiltInFunctionSetESDTRole, n.another, token, role)
	public.CallerAddr = bytes.Clone(core.ESDTSCAddress)
	_, err = n.hook.ProcessBuiltInFunction(public)
	require.ErrorIs(t, err, drwa.ErrRegulatedTokenOperation)
	require.Empty(t, roles())
	// The envelope in a user's transaction: refused.
	copied := qualSP222Call(t, qualSP232System(), transfer)
	copied.CurrentTxHash, copied.CallerAddr, copied.CallType = []byte("user hash"), bytes.Clone(n.sender), vmData.DirectCall
	_, err = n.hook.ProcessBuiltInFunction(copied)
	require.ErrorIs(t, err, drwa.ErrInvalidAdminEffect)
	require.Empty(t, roles())
	require.Zero(t, binding.seen)

	// The protected leg: the role, once, and the outcome with the unused gas.
	result, err := n.hook.ProcessBuiltInFunction(leg)
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, result.ReturnCode)
	require.Equal(t, granted, roles())
	require.Equal(t, transfer.GasLimit-400, result.GasRemaining)
	require.NotZero(t, binding.seen)
	applied, err := n.store.Commit()
	require.NoError(t, err)
	again, err := n.hook.ProcessBuiltInFunction(leg)
	require.NoError(t, err)
	require.Equal(t, result.ReturnData, again.ReturnData)
	require.Equal(t, granted, roles())
	root, err := n.store.Commit()
	require.NoError(t, err)
	require.Equal(t, applied, root, "the same leg again writes nothing")
}

func TestQualSP232AdminEffectFunctionInstallation(t *testing.T) {
	native := qualSP222ShardNode(t, false)
	function, err := native.pcf.installDRWAAdminEffects(native.store, native.builtIns, nil)
	require.NoError(t, err)
	require.Nil(t, function, "an ordinary node gets no admin-effect destination")
	require.Nil(t, drwaAdminEffectFunctionOf(native.builtIns))
	require.Nil(t, native.pcf.drwaDomain())
	_, err = native.builtIns.Get(drwa.AdminEffectFunctionName)
	require.Error(t, err)
	_, err = native.hook.ProcessBuiltInFunction(qualSP232Leg(native, []byte("envelope")))
	require.Error(t, err, "and no such function")
	require.Zero(t, native.store.JournalLen())

	// The registry installation of a DRWA shard node installs the destination
	// with it, in the same container.
	enabled := qualSP222ShardNode(t, true)
	require.NoError(t, enabled.handler.BeginExecution())
	function = drwaAdminEffectFunctionOf(enabled.builtIns)
	require.NotNil(t, function)
	installed, err := enabled.builtIns.Get(drwa.AdminEffectFunctionName)
	require.NoError(t, err)
	require.Same(t, function, installed)
	other := vmcommon.BuiltinFunction(enabled.pcf.drwaShardRegistrySource.(*drwa.ShardRegistry).DeltaFunction())
	foreign := qualSP225BuiltIns(t, native.pcf, native.store).BuiltInFunctionContainer()
	require.NoError(t, foreign.Add(drwa.AdminEffectFunctionName, other))
	require.Nil(t, drwaAdminEffectFunctionOf(foreign), "another function under the name is not the destination")
	_, err = enabled.pcf.installDRWAAdminEffects(enabled.store, enabled.builtIns, enabled.pcf.drwaShardRegistrySource)
	require.Error(t, err, "one destination per container")
	_, err = enabled.pcf.installDRWAAdminEffects(enabled.store, enabled.builtIns, nil)
	require.ErrorIs(t, err, drwa.ErrInvalidAdminEffect, "the registry is required")

	// The record bound of the deployment is required, not defaulted: without
	// it the shard gets neither the destination nor a registry source.
	unbounded := qualSP225Factory(t, 0, true, enabled.store, integrationtests.CreateInMemoryShardAccountsDB())
	unbounded.drwaInitialProgrammeStartup.Limits.RecordBytes = 0
	container := qualSP225BuiltIns(t, unbounded, enabled.store).BuiltInFunctionContainer()
	handler, err := unbounded.installDRWAShardRegistry(enabled.store, container)
	require.Error(t, err)
	require.Nil(t, handler)
	require.Nil(t, unbounded.drwaShardRegistrySource)
	_, err = container.Get(drwa.AdminEffectFunctionName)
	require.Error(t, err)

	// The real hook hands the protected call to the function. Before the
	// deployment identity is open there is no network domain: refused.
	refused := func(label string, input *vmcommon.ContractCallInput) {
		t.Helper()
		root, rootErr := enabled.store.RootHash()
		require.NoError(t, rootErr)
		output, callErr := enabled.hook.ProcessBuiltInFunction(input)
		require.ErrorIs(t, callErr, drwa.ErrInvalidAdminEffect, label)
		require.Nil(t, output, label)
		after, rootErr := enabled.store.RootHash()
		require.NoError(t, rootErr)
		require.Equal(t, root, after, label)
	}
	require.Nil(t, enabled.pcf.drwaDomain())
	refused("no network domain", qualSP232Leg(enabled, []byte("envelope")))
	// The domain is that of the deployment identity the node has open.
	identity := qualA77Identity(t)
	unit, err := enabled.pcf.drwaIdentityOwner.open(filepath.Join(t.TempDir(), "chain-specific"), qualA77IdentityParameters(),
		identity, qualA77IdentityFresh(identity))
	require.NoError(t, err)
	require.NotEmpty(t, identity.Domain())
	require.Equal(t, identity.Domain(), enabled.pcf.drwaDomain())
	refused("not an envelope", qualSP232Leg(enabled, []byte("envelope")))
	t.Cleanup(func() { _ = unit.Close() })

	// Copied into a user transaction or a contract's result, the same bytes
	// never reach the envelope check.
	user := qualSP232Leg(enabled, []byte("envelope"))
	user.CallerAddr, user.CallType = bytes.Clone(enabled.sender), vmData.DirectCall
	refused("user transaction", user)
	// A contract of this shard as sender: the function refuses it, as it
	// refuses the user. (A contract that does not exist is refused by the hook
	// itself, before the function.)
	contract := qualSP232Leg(enabled, []byte("envelope"))
	contract.CallerAddr = append(make([]byte, 8), bytes.Repeat([]byte{5}, 24)...)
	account, err := enabled.store.LoadAccount(contract.CallerAddr)
	require.NoError(t, err)
	require.NoError(t, enabled.store.SaveAccount(account))
	_, err = enabled.store.Commit()
	require.NoError(t, err)
	refused("contract result", contract)
}

// An ordinary token-admin call, an ordinary metadata call and ordinary
// transfers give the same outcome and the same state on a native node and on
// a DRWA shard node with the registry and the admin-effect destination
// installed.
func TestQualSP232OrdinaryCallsAreUnchangedWithTheDestinationInstalled(t *testing.T) {
	native := qualSP222ShardNode(t, false)
	enabled := qualSP222ShardNode(t, true)
	require.NoError(t, enabled.handler.BeginExecution())
	require.NotNil(t, drwaAdminEffectFunctionOf(enabled.builtIns))

	fromESDT := func(n *qualSP222Shard, function string, recipient []byte, arguments ...[]byte) *vmcommon.ContractCallInput {
		input := n.call(function, recipient, arguments...)
		input.CallerAddr = bytes.Clone(core.ESDTSCAddress)
		return input
	}
	nft := []byte("ORDNFT-abcdef")
	steps := []struct {
		name    string
		build   func(n *qualSP222Shard) *vmcommon.ContractCallInput
		succeed bool
	}{
		{"token-admin: role grant", func(n *qualSP222Shard) *vmcommon.ContractCallInput {
			return fromESDT(n, core.BuiltInFunctionSetESDTRole, n.sender, nft, []byte(core.ESDTRoleNFTCreate), []byte(core.ESDTRoleNFTUpdateAttributes))
		}, true},
		{"token-admin: global setting", func(n *qualSP222Shard) *vmcommon.ContractCallInput {
			return fromESDT(n, core.BuiltInFunctionESDTSetLimitedTransfer, core.SystemAccountAddress, nft)
		}, true},
		{"token-admin: role revoke", func(n *qualSP222Shard) *vmcommon.ContractCallInput {
			return fromESDT(n, core.BuiltInFunctionUnSetESDTRole, n.sender, []byte(qualSP225Ordinary), []byte(core.ESDTRoleLocalBurn))
		}, true},
		{"create", func(n *qualSP222Shard) *vmcommon.ContractCallInput {
			return n.call(core.BuiltInFunctionESDTNFTCreate, n.sender, nft, []byte{1}, []byte("name"), []byte{0}, []byte("hash"), []byte("attributes"), []byte("uri"))
		}, true},
		{"metadata: update attributes", func(n *qualSP222Shard) *vmcommon.ContractCallInput {
			return n.call(core.BuiltInFunctionESDTNFTUpdateAttributes, n.sender, nft, []byte{1}, []byte("new attributes"))
		}, true},
		{"transfer", func(n *qualSP222Shard) *vmcommon.ContractCallInput { return n.routes(qualSP225Ordinary)["transfer"] }, true},
		{"multi transfer", func(n *qualSP222Shard) *vmcommon.ContractCallInput {
			return n.routes(qualSP225Ordinary)["multi_transfer"]
		}, true},
		{"local mint", func(n *qualSP222Shard) *vmcommon.ContractCallInput { return n.routes(qualSP225Ordinary)["local_mint"] }, true},
		{"local burn after the revoke", func(n *qualSP222Shard) *vmcommon.ContractCallInput { return n.routes(qualSP225Ordinary)["local_burn"] }, false},
	}
	for _, step := range steps {
		expected, expectedErr := native.hook.ProcessBuiltInFunction(step.build(native))
		actual, actualErr := enabled.hook.ProcessBuiltInFunction(step.build(enabled))
		if step.succeed {
			require.NoError(t, expectedErr, step.name)
		} else {
			require.Error(t, expectedErr, step.name)
		}
		require.Equal(t, expectedErr, actualErr, step.name)
		require.Equal(t, expected, actual, step.name+": same result and gas")
		before, err := native.store.RootHash()
		require.NoError(t, err)
		after, err := enabled.store.RootHash()
		require.NoError(t, err)
		require.Equal(t, before, after, step.name+": same state")
	}
	expectedRoot, err := native.store.Commit()
	require.NoError(t, err)
	actualRoot, err := enabled.store.Commit()
	require.NoError(t, err)
	require.Equal(t, expectedRoot, actualRoot)
}

func TestQualSP232AdminEffectsOriginExistsOnlyOnTheMetachainOfADRWADeployment(t *testing.T) {
	accounts := &stateMock.AccountsStub{}
	validator := &processMocks.HeaderValidatorMock{}
	limits := config.DRWAInitialProgrammeLimits{RecordBytes: 4096, AggregateBytes: 1 << 16,
		Records: 100, RetainedBytes: 1 << 20, NewRecordsPerEpoch: 10}

	shard, _ := qualSP222Factory(t)
	shard.drwaConfigurationCandidate, _, _ = qualS1OverlayCandidate(t, 12)
	shard.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{Limits: limits}
	shard.drwaHeaderProofVerifier = &consensusMock.HeaderSigVerifierMock{}
	owner, err := shard.newDRWAFinalityImport(accounts, validator)
	require.NoError(t, err)
	_, isMeta := owner.(*drwaMetaFinalityImport)
	require.False(t, isMeta, "an execution shard is a destination, not an origin")

	meta, _ := qualSP222Factory(t)
	meta.bootstrapComponents = &qualSP222Bootstrap{coordinator: &testscommon.ShardsCoordinatorMock{CurrentShard: core.MetachainShardId, NoShards: 3}}
	meta.coreData.(*factoryMock.CoreComponentsMock).EnableEpochsHandlerField = enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	meta.config.StateTriesConfig.MaxStateTrieLevelInMemory = 5
	meta.drwaConfigurationCandidate, _, _ = qualS1OverlayCandidate(t, 12)
	meta.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{Limits: limits}
	meta.drwaHeaderProofVerifier = &consensusMock.HeaderSigVerifierMock{}
	owner, err = meta.newDRWAFinalityImport(accounts, validator)
	require.NoError(t, err)
	installed, isMeta := owner.(*drwaMetaFinalityImport)
	require.True(t, isMeta)
	effects := installed.DRWAAdminEffects()
	require.NotNil(t, effects)
	require.False(t, effects.IsInterfaceNil())
	// The deployment identity is not open: no domain, so nothing is carried.
	_, _, err = effects.Open(&vmcommon.VMOutput{}, drwa.AdminEffectRequest{}, 1000)
	require.ErrorIs(t, err, drwa.ErrInvalidAdminEffect)
	_, err = effects.Acknowledge(make([]byte, 32), 0, []byte("no evidence"), 1000)
	require.ErrorIs(t, err, drwa.ErrInvalidAdminEffect)
	_, err = effects.Redrive(&vmcommon.VMOutput{}, make([]byte, 32), 0, 1000)
	require.ErrorIs(t, err, drwa.ErrInvalidAdminEffect)

	// More execution shards than an acknowledgement bitmap holds, or no gas
	// schedule to price a carried effect from: the node is not built.
	meta.bootstrapComponents = &qualSP222Bootstrap{coordinator: &testscommon.ShardsCoordinatorMock{CurrentShard: core.MetachainShardId, NoShards: 256}}
	_, err = meta.newDRWAFinalityImport(accounts, validator)
	require.ErrorIs(t, err, drwa.ErrInvalidAdminEffect)
	meta.bootstrapComponents = &qualSP222Bootstrap{coordinator: &testscommon.ShardsCoordinatorMock{CurrentShard: core.MetachainShardId, NoShards: 3}}
	meta.gasSchedule = nil
	_, err = meta.newDRWAFinalityImport(accounts, validator)
	require.ErrorIs(t, err, drwa.ErrCarrierFunding)
}
