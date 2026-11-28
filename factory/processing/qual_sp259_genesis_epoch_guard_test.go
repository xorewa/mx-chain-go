package processing

import (
	"testing"

	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/stretchr/testify/require"
)

// Until native same-epoch resumability is qualified, persisted admission at
// genesis must remain a refusal, even when the retained identity is valid.
func TestQualSP259GenesisEpochRestartRemainsRefused(t *testing.T) {
	factory, _ := sp259CommittedGenesis(t)
	startup := factory.drwaInitialProgrammeStartup
	factory.coreData = &sp259UnavailableEpochProviderCore{factory.coreData.(*qualD18Core)}
	require.Equal(t, factory.config.EpochStartConfig.GenesisEpoch, factory.bootstrapComponents.EpochBootstrapParams().Epoch())
	require.NoError(t, CheckDRWARestartIdentity(startup.OriginalDatabasePath, factory.drwaDeploymentIdentity, startup, &factory.config))

	components, err := factory.Create()
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Nil(t, components)
	require.Nil(t, factory.drwaIdentityOwner.unit)
	require.NoError(t, CheckDRWARestartIdentity(startup.OriginalDatabasePath, factory.drwaDeploymentIdentity, startup, &factory.config))
}
