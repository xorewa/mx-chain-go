package processing

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
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
	"github.com/multiversx/mx-chain-go/testscommon/processMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
)

// SP2-33 through the node's own construction and the installed hook of a
// shard node.

func qualSP233FromESDT(n *qualSP222Shard, function string, arguments ...[]byte) *vmcommon.ContractCallInput {
	input := n.call(function, qualSP232System(), arguments...)
	input.CallerAddr, input.CallType = bytes.Clone(core.ESDTSCAddress), vmData.DirectCall
	return input
}

// Part A L6393: "Raw burn denial and ordinary-token behavior must remain
// independent controls; a successful unset call is not the oracle." A public
// burn of a regulated token is refused whatever the shard's global-burn item
// says: absent, true (as if an enable effect had been applied) or false.
func TestQualSP233RawBurnOfARegulatedTokenIsRefusedWhateverTheGlobalItem(t *testing.T) {
	token := []byte(qualSP225Regulated)
	itemKey := []byte(core.ProtectedKeyPrefix + core.ESDTKeyIdentifier + qualSP225Regulated)
	for name, item := range map[string][]byte{"no item": nil, "burn-for-all true": {4, 0}, "burn-for-all false": {0, 0}} {
		n := qualSP222ShardNode(t, true)
		require.NoError(t, n.handler.BeginExecution())
		delta := qualSP232Leg(n, nil)
		delta.Function, delta.Arguments = drwa.RegistryDeltaFunctionName, [][]byte{token, make([]byte, 8)}
		_, err := n.hook.ProcessBuiltInFunction(delta)
		require.NoError(t, err, name)
		if item != nil {
			system, loadErr := n.store.LoadAccount(core.SystemAccountAddress)
			require.NoError(t, loadErr)
			require.NoError(t, system.(state.UserAccountHandler).SaveKeyValue(itemKey, item))
			require.NoError(t, n.store.SaveAccount(system))
		}
		_, err = n.store.Commit()
		require.NoError(t, err)
		require.NoError(t, n.handler.Committed())
		root, err := n.store.RootHash()
		require.NoError(t, err)

		burns := map[string]*vmcommon.ContractCallInput{
			"local burn by the role holder": n.routes(qualSP225Regulated)["local_burn"],
			"burn by the holder":            n.call(core.BuiltInFunctionESDTBurn, n.sender, token, big.NewInt(10).Bytes()),
			"NFT burn":                      n.call(core.BuiltInFunctionESDTNFTBurn, n.sender, token, []byte{1}, big.NewInt(1).Bytes()),
		}
		stranger := n.call(core.BuiltInFunctionESDTLocalBurn, n.another, token, big.NewInt(1).Bytes())
		stranger.CallerAddr = bytes.Clone(n.another)
		burns["local burn by an account without the role"] = stranger
		for label, burn := range burns {
			output, burnErr := n.hook.ProcessBuiltInFunction(burn)
			require.ErrorIs(t, burnErr, drwa.ErrRegulatedTokenOperation, name+": "+label)
			require.Nil(t, output, name+": "+label)
		}
		// The public toggles and the type call, from any sender, the metachain
		// ESDT system contract included: refused, the item unchanged.
		for _, function := range []string{vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll} {
			_, toggleErr := n.hook.ProcessBuiltInFunction(qualSP233FromESDT(n, function, token))
			require.ErrorIs(t, toggleErr, drwa.ErrRegulatedTokenOperation, name+": "+function)
		}
		_, err = n.hook.ProcessBuiltInFunction(qualSP233FromESDT(n, core.ESDTSetTokenType, token, []byte(core.FungibleESDT)))
		require.ErrorIs(t, err, drwa.ErrRegulatedTokenOperation, name)
		after, err := n.store.RootHash()
		require.NoError(t, err)
		require.Equal(t, root, after, name+": no state")
		require.EqualValues(t, 100, n.balance(t, n.sender, qualSP225Regulated), name)
	}
}

// An ordinary token's burn-for-all behaviour is the upstream behaviour, on a
// native node and on a DRWA shard node alike: the same outcome, gas and state
// at every step.
func TestQualSP233OrdinaryBurnForAllIsUnchanged(t *testing.T) {
	native := qualSP222ShardNode(t, false)
	enabled := qualSP222ShardNode(t, true)
	require.NoError(t, enabled.handler.BeginExecution())
	ordinary := []byte(qualSP225Ordinary)
	stranger := func(n *qualSP222Shard) *vmcommon.ContractCallInput {
		input := n.call(core.BuiltInFunctionESDTLocalBurn, n.another, ordinary, big.NewInt(1).Bytes())
		input.CallerAddr = bytes.Clone(n.another)
		return input
	}
	steps := []struct {
		name    string
		build   func(n *qualSP222Shard) *vmcommon.ContractCallInput
		succeed bool
	}{
		{"transfer to an account without roles", func(n *qualSP222Shard) *vmcommon.ContractCallInput { return n.routes(qualSP225Ordinary)["transfer"] }, true},
		{"its burn without burn-for-all", stranger, false},
		{"enable from the ESDT system contract", func(n *qualSP222Shard) *vmcommon.ContractCallInput {
			return qualSP233FromESDT(n, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, ordinary)
		}, true},
		{"its burn with burn-for-all", stranger, true},
		{"type from the ESDT system contract", func(n *qualSP222Shard) *vmcommon.ContractCallInput {
			return qualSP233FromESDT(n, core.ESDTSetTokenType, ordinary, []byte(core.FungibleESDT))
		}, true},
		{"disable from the ESDT system contract", func(n *qualSP222Shard) *vmcommon.ContractCallInput {
			return qualSP233FromESDT(n, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, ordinary)
		}, true},
		{"its burn after the disable", stranger, false},
		{"enable from a user", func(n *qualSP222Shard) *vmcommon.ContractCallInput {
			input := qualSP233FromESDT(n, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, ordinary)
			input.CallerAddr = bytes.Clone(n.sender)
			return input
		}, false},
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
}

// The metachain node of a DRWA deployment has the readiness owner and the
// convergence host with E10 bound into it; nothing else has.
func TestQualSP233ReadinessExistsOnlyOnTheMetachainOfADRWADeployment(t *testing.T) {
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
	require.False(t, isMeta)

	meta, _ := qualSP222Factory(t)
	meta.bootstrapComponents = &qualSP222Bootstrap{coordinator: &testscommon.ShardsCoordinatorMock{CurrentShard: core.MetachainShardId, NoShards: 3}}
	meta.coreData.(*factoryMock.CoreComponentsMock).EnableEpochsHandlerField = enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	meta.config.StateTriesConfig.MaxStateTrieLevelInMemory = 5
	meta.drwaConfigurationCandidate, _, _ = qualS1OverlayCandidate(t, 12)
	meta.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{Limits: limits}
	meta.drwaHeaderProofVerifier = &consensusMock.HeaderSigVerifierMock{}
	owner, err = meta.newDRWAFinalityImport(accounts, validator)
	require.NoError(t, err)
	installed := owner.(*drwaMetaFinalityImport)
	readiness, bound := installed.DRWABurnForAllReadiness(), installed.DRWABurnBoundConvergenceHost()
	require.NotNil(t, readiness)
	require.False(t, readiness.IsInterfaceNil())
	require.NotNil(t, bound)
	require.False(t, bound.IsInterfaceNil())
	require.Same(t, installed.DRWAConvergenceHost(), bound.ConvergenceHost)
	// Nothing was registered and nothing can be read: never ready.
	require.Error(t, readiness.Verify([]byte("TOKEN-abcdef")))
	_, err = readiness.Open(&vmcommon.VMOutput{}, drwa.BurnForAllReadinessRequest{TokenID: []byte("TOKEN-abcdef"),
		Family: []byte(core.FungibleESDT)}, 1000)
	require.Error(t, err)
	_, err = bound.Complete([]byte("not a binding"), make([]byte, 32))
	require.Error(t, err)

	// The construction step refuses what it cannot build on: no account store,
	// owners that are missing, a host of another store.
	effects, funding, host := installed.DRWAAdminEffects(), installed.DRWACarrierFunding(), installed.DRWAConvergenceHost()
	_, _, err = meta.newDRWABurnReadiness(nil, installed, host, effects, funding)
	require.Error(t, err)
	_, _, err = meta.newDRWABurnReadiness(accounts, installed, host, nil, funding)
	require.ErrorIs(t, err, drwa.ErrInvalidBurnForAllReadiness)
	_, _, err = meta.newDRWABurnReadiness(accounts, installed, nil, effects, funding)
	require.ErrorIs(t, err, drwa.ErrInvalidBurnForAllReadiness)
	again, rebound, err := meta.newDRWABurnReadiness(accounts, installed, host, effects, funding)
	require.NoError(t, err)
	require.NotNil(t, again)
	require.NotNil(t, rebound)

	// SP2-34: the owner of the protected type materialization exception.
	materialization, err := meta.newDRWATypeMaterialization(installed)
	require.NoError(t, err)
	require.False(t, materialization.IsInterfaceNil())
	_, _, err = materialization.Open(&vmcommon.VMOutput{}, drwa.TypeMaterializationRequest{TokenID: []byte("TOKEN-abcdef"),
		Family: []byte(core.FungibleESDT)}, 1000)
	require.ErrorIs(t, err, drwa.ErrInvalidTypeMaterialization, "the baseline of this node materializes no type")
	_, err = meta.newDRWATypeMaterialization(nil)
	require.ErrorIs(t, err, drwa.ErrInvalidTypeMaterialization)
	_, err = meta.newDRWATypeMaterialization(&drwaMetaFinalityImport{})
	require.ErrorIs(t, err, drwa.ErrInvalidTypeMaterialization)
}
