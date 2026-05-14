package factory

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestP2PTopicsShouldRemainStable(t *testing.T) {
	require.Equal(t, "transactions", TransactionTopic)
	require.Equal(t, "unsignedTransactions", UnsignedTransactionTopic)
	require.Equal(t, "rewardsTransactions", RewardsTransactionTopic)
	require.Equal(t, "shardBlocks", ShardBlocksTopic)
	require.Equal(t, "txBlockBodies", MiniBlocksTopic)
	require.Equal(t, "peerChangeBlockBodies", PeerChBodyTopic)
	require.Equal(t, "metachainBlocks", MetachainBlocksTopic)
	require.Equal(t, "accountTrieNodes", AccountTrieNodesTopic)
	require.Equal(t, "validatorTrieNodes", ValidatorTrieNodesTopic)
}

func TestVirtualMachineIdentifiersShouldRemainStable(t *testing.T) {
	require.Equal(t, []byte{0, 1}, SystemVirtualMachine)
	require.Equal(t, []byte{1, 0}, IELEVirtualMachine)
	require.Equal(t, []byte{5, 0}, WasmVirtualMachine)
	require.Equal(t, []byte{255, 255}, InternalTestingVM)
}
