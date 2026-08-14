package intermediate

import (
	"encoding/hex"
	"testing"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Characterizes only the current generic genesis deployer's metadata. It does
// not decide whether a future DRWA contract should use this path; it proves
// that any such design must explicitly account for upgradeability.
func TestCharacterization_GenericInitialSmartContractMetadataIsUpgradeable(t *testing.T) {
	metadata, err := hex.DecodeString(codeMetadataHexForInitialSC)
	require.NoError(t, err)
	require.True(t, vmcommon.CodeMetadataFromBytes(metadata).Upgradeable)
	require.Equal(t, "0100", codeMetadataHexForInitialSC)
}
