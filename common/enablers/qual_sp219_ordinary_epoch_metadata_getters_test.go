package enablers

import (
	"testing"

	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	"github.com/stretchr/testify/require"
)

// Verify the scheduled epoch metadata getters against the existing ordinary
// configuration fixture. No epoch is advanced and no flag or stake is activated.
func TestQualSP219OrdinaryEpochMetadataGetters(t *testing.T) {
	cfg := createEnableEpochsConfig()
	handler, err := NewEnableEpochsHandler(cfg, &epochNotifier.EpochNotifierStub{})
	require.NoError(t, err)
	require.NotNil(t, handler)

	// The inherited fixture independently assigns 97 to phase one and 98 to phase two.
	require.Equal(t, uint32(97), handler.StakingV4Step1EnableEpoch())
	require.Equal(t, uint32(98), handler.StakingV4Step2EnableEpoch())

	metadata := handler.GetAllEnableEpochs()
	require.Equal(t, uint32(97), metadata["StakingV4Step1EnableEpoch"])
	require.Equal(t, uint32(98), metadata["StakingV4Step2EnableEpoch"])
}
