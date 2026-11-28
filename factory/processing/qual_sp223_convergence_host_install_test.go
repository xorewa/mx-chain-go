package processing

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/config"
	factoryMock "github.com/multiversx/mx-chain-go/factory/mock"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/testscommon"
	consensusMock "github.com/multiversx/mx-chain-go/testscommon/consensus"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/processMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/stretchr/testify/require"
)

// SP2-23: the production convergence host is built on the metachain node of a
// DRWA deployment only, from the deployment's own limits, and with no family
// owner: until the rows that own the producers install theirs, it refuses
// every transition. A shard node gets the bare import owner as before.
func TestQualSP223ConvergenceHostExistsOnlyOnTheMetachainOfADRWADeployment(t *testing.T) {
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
	require.False(t, isMeta, "an execution shard has no convergence host")

	meta, _ := qualSP222Factory(t)
	meta.bootstrapComponents = &qualSP222Bootstrap{coordinator: &testscommon.ShardsCoordinatorMock{CurrentShard: core.MetachainShardId}}
	meta.coreData.(*factoryMock.CoreComponentsMock).EnableEpochsHandlerField = enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	meta.config.StateTriesConfig.MaxStateTrieLevelInMemory = 5
	owner, err = meta.newDRWAFinalityImport(accounts, validator)
	require.NoError(t, err)
	require.Nil(t, owner, "an ordinary metachain node gets neither")

	meta.drwaConfigurationCandidate, _, _ = qualS1OverlayCandidate(t, 12)
	meta.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{Limits: limits}
	meta.drwaHeaderProofVerifier = &consensusMock.HeaderSigVerifierMock{}
	owner, err = meta.newDRWAFinalityImport(accounts, validator)
	require.NoError(t, err)
	installed, isMeta := owner.(*drwaMetaFinalityImport)
	require.True(t, isMeta)
	var handler process.DRWAFinalityImportHandler = installed
	require.False(t, handler.IsInterfaceNil())
	require.Same(t, meta.drwaFinalityImport, installed.FinalityImport)
	host := installed.DRWAConvergenceHost()
	require.NotNil(t, host)
	// No family owner is installed: a well-formed transition is refused.
	require.Error(t, host.VerifyTransition([]byte("any binding")))
	require.Error(t, host.SetFamilyOwner("PLANE", nil))

	for name, change := range map[string]func(*config.DRWAInitialProgrammeLimits){
		"no record budget": func(l *config.DRWAInitialProgrammeLimits) { l.Records = 0 },
		"no byte budget":   func(l *config.DRWAInitialProgrammeLimits) { l.RetainedBytes = 0 },
		"no epoch rate":    func(l *config.DRWAInitialProgrammeLimits) { l.NewRecordsPerEpoch = 0 },
		"no evidence":      func(l *config.DRWAInitialProgrammeLimits) { l.AggregateBytes = 0 },
	} {
		changed := limits
		change(&changed)
		meta.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{Limits: changed}
		_, err = meta.newDRWAFinalityImport(accounts, validator)
		require.Error(t, err, name+": refused, not defaulted")
	}
	var nilImport *drwaMetaFinalityImport
	require.True(t, nilImport.IsInterfaceNil())
	require.Error(t, host.SetFamilyOwner(drwa.ConvergenceFamilyRoot, nil))
}
