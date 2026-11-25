package disabled

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTxCoordinator_CreateMbsAndProcessTransactionsFromMeReturnsEmpty(t *testing.T) {
	t.Parallel()

	coordinator := &TxCoordinator{}
	miniBlocks, err := coordinator.CreateMbsAndProcessTransactionsFromMe(nil, nil)
	require.NoError(t, err)
	require.NotNil(t, miniBlocks)
	require.Empty(t, miniBlocks)
}
