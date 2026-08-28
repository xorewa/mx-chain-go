package builtInFunctions

import (
	"testing"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestS1AddendumNoTagDestinationBarrierIsExactPassThrough(t *testing.T) {
	destination, input, account, _ := newDRWADestinationFixture(t, true)
	require.NotNil(t, destination.qualificationBarrier)
	output, err := destination.ProcessBuiltinFunction(nil, account, input)
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, output.ReturnCode)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeSettlementReceipt, output.ProtocolExecution.Outcome)
	require.Len(t, output.OutputAccounts, 1)
}
