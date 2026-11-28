package processing

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/config"
	factoryMock "github.com/multiversx/mx-chain-go/factory/mock"
	"github.com/multiversx/mx-chain-go/testscommon"
	consensusMock "github.com/multiversx/mx-chain-go/testscommon/consensus"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/processMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
)

// SP2-78: the verifier of closure-bound origin SupplyState evidence exists on
// the metachain node of a DRWA deployment only, beside the convergence host,
// and is built from the deployment's own limits.
func TestQualSP278SupplyEvidenceVerifierExistsOnlyOnTheMetachainOfADRWADeployment(t *testing.T) {
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
	require.False(t, isMeta, "an execution shard has no verifier: it is the producer")

	meta, _ := qualSP222Factory(t)
	meta.bootstrapComponents = &qualSP222Bootstrap{coordinator: &testscommon.ShardsCoordinatorMock{CurrentShard: core.MetachainShardId}}
	meta.coreData.(*factoryMock.CoreComponentsMock).EnableEpochsHandlerField = enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	meta.config.StateTriesConfig.MaxStateTrieLevelInMemory = 5
	owner, err = meta.newDRWAFinalityImport(accounts, validator)
	require.NoError(t, err)
	require.Nil(t, owner, "an ordinary metachain node gets none")

	meta.drwaConfigurationCandidate, _, _ = qualS1OverlayCandidate(t, 12)
	meta.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{Limits: limits}
	meta.drwaHeaderProofVerifier = &consensusMock.HeaderSigVerifierMock{}
	owner, err = meta.newDRWAFinalityImport(accounts, validator)
	require.NoError(t, err)
	installed, isMeta := owner.(*drwaMetaFinalityImport)
	require.True(t, isMeta)
	verifier := installed.DRWASupplyEvidenceVerifier()
	require.NotNil(t, verifier)
	require.False(t, verifier.IsInterfaceNil())
	// No block is in execution and nothing was presented: it refuses.
	_, err = verifier.CumulativeIssued(drwaSupplyBindingForTest(), []byte("no evidence"))
	require.Error(t, err)
	_, err = verifier.ValidateCap(drwaSupplyBindingForTest(), big.NewInt(1), nil)
	require.Error(t, err)

	// The record bound of the deployment is required, not defaulted.
	changed := limits
	changed.RecordBytes = 0
	meta.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{Limits: changed}
	_, err = meta.newDRWAFinalityImport(accounts, validator)
	require.Error(t, err)
}

// INV-0 with this row's code in the node: on the production hooks of a DRWA
// deployment, ordinary built-in calls on the shard and ordinary System-SC
// calls on the metachain give the same output, error and committed state as on
// a node without DRWA. The certificate contract, the origin writer and the
// verifier (built on the metachain node, see the test above) are called by no
// production path and attach to no hook.
func TestQualSP278OrdinaryCallsUnchangedWithTheContractsInstalled(t *testing.T) {
	header := func(shard uint32) data.HeaderHandler { return qualSP224Header(shard, 12, 440, 1234567) }
	resolved := func() *qualSP225RegistrySource {
		return &qualSP225RegistrySource{regulated: map[string]bool{qualSP225Regulated: true}}
	}
	for route := range (&qualSP225Shard{}).routes(qualSP225Ordinary) {
		enabled, native := qualSP224ShardNode(t, true, resolved()), qualSP224ShardNode(t, false, nil)
		_, _, err := qualSP224Evaluate(t, enabled.hook, header(0))
		require.NoError(t, err)
		require.NoError(t, native.hook.SetEpochStartHeader(header(0)))
		require.NoError(t, native.hook.SetCurrentHeader(header(0)))
		for _, token := range []string{qualSP225Ordinary, "UNKNOWN-abcdef"} {
			expected, nativeErr := native.hook.ProcessBuiltInFunction(native.routes(token)[route])
			actual, enabledErr := enabled.hook.ProcessBuiltInFunction(enabled.routes(token)[route])
			require.Equal(t, nativeErr, enabledErr, "%s %s", route, token)
			require.Equal(t, expected, actual, "%s %s", route, token)
		}
		nativeRoot, err := native.store.Commit()
		require.NoError(t, err)
		enabledRoot, err := enabled.store.Commit()
		require.NoError(t, err)
		require.Equal(t, nativeRoot, enabledRoot, route)
	}

	enabled := qualSP224MetaNode(t, true, qualSP225GenesisStore(t, qualSP225Regulated))
	native := qualSP224MetaNode(t, false, qualSP225GenesisStore(t, qualSP225Regulated))
	_, _, err := qualSP224Evaluate(t, enabled.hook, header(core.MetachainShardId))
	require.NoError(t, err)
	require.NoError(t, native.hook.SetEpochStartHeader(header(core.MetachainShardId)))
	require.NoError(t, native.hook.SetCurrentHeader(header(core.MetachainShardId)))
	require.NoError(t, enabled.owner.BeginExecution())
	calls := 0
	run := func(input func() *vmcommon.ContractCallInput) *vmcommon.VMOutput {
		t.Helper()
		calls++
		expected, nativeErr := native.system.RunSmartContractCall(input())
		actual, enabledErr := enabled.system.RunSmartContractCall(input())
		require.Equal(t, nativeErr, enabledErr)
		require.Equal(t, expected, actual)
		return expected
	}
	issued := run(func() *vmcommon.ContractCallInput {
		input := qualSP225ESDTCall("issue", []byte("OrdinaryToken"), []byte("ORDINARY"), big.NewInt(1000).Bytes(), []byte{2},
			[]byte("canPause"), []byte("true"), []byte("canFreeze"), []byte("true"), []byte("canWipe"), []byte("true"), []byte("canChangeOwner"), []byte("true"))
		input.CallValue = big.NewInt(1000)
		return input
	})
	require.Equal(t, vmcommon.Ok, issued.ReturnCode, issued.ReturnMessage)
	for _, function := range qualSP225PublicMutations {
		run(func() *vmcommon.ContractCallInput { return qualSP225PublicCall(function, qualSP225Ordinary) })
	}
	run(func() *vmcommon.ContractCallInput {
		return qualSP225ESDTCall("getTokenProperties", []byte(qualSP225Ordinary))
	})
	require.Equal(t, len(qualSP225PublicMutations)+2, calls)
	nativeRoot, err := native.user.Commit()
	require.NoError(t, err)
	enabledRoot, err := enabled.user.Commit()
	require.NoError(t, err)
	require.Equal(t, nativeRoot, enabledRoot, "identical ordinary state delta")
}
