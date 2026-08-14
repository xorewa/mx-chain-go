package processing_test

import (
	"testing"

	"github.com/multiversx/mx-chain-go/config"
)

// Proves that the genesis validation failure reaches the production process
// factory boundary and aborts node component creation; it is not confined to
// an isolated setup helper.
func TestCharacterization_ProcessFactoryPropagatesDRWAEnabledOnlyGenesisFailure(t *testing.T) {
	args := createMockProcessComponentsFactoryArgs()
	args.Config.DRWA = config.DRWAConfig{Enabled: true}

	testCreateWithArgs(t, args,
		`invalid DRWA key management model "": expected "multisig_3of5_contract"`)
}
