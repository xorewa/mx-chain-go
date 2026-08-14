package enablers

import (
	"testing"

	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	builtInFunctions "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Characterizes the scheduling half of DRWA enforcement. This only proves
// epoch-flag activation; it intentionally does not claim that a regulated
// transfer path consumes the flag.
func TestCharacterization_DRWAEnforcementFlagActivatesAtConfiguredEpoch(t *testing.T) {
	cfg := createEnableEpochsConfig()
	cfg.DRWAEnforcementEnableEpoch = 3
	handler, err := NewEnableEpochsHandler(cfg, &epochNotifier.EpochNotifierStub{})
	require.NoError(t, err)

	handler.EpochConfirmed(2, 0)
	require.False(t, handler.IsFlagEnabled(builtInFunctions.DRWAEnforcementFlag))
	handler.EpochConfirmed(3, 0)
	require.True(t, handler.IsFlagEnabled(builtInFunctions.DRWAEnforcementFlag))
}
