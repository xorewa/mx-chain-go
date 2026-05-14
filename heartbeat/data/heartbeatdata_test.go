package data

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPubKeyHeartbeatJSONTags(t *testing.T) {
	heartbeat := PubKeyHeartbeat{
		PublicKey:       "pubkey",
		TimeStamp:       time.Unix(1, 0).UTC(),
		IsActive:        true,
		ReceivedShardID: 1,
		ComputedShardID: 2,
		VersionNumber:   "v1",
		NodeDisplayName: "node",
		Identity:        "identity",
		PeerType:        "eligible",
		Nonce:           7,
		NumInstances:    1,
		PeerSubType:     3,
		PidString:       "peer",
	}

	encoded, err := json.Marshal(heartbeat)

	require.Nil(t, err)
	require.Contains(t, string(encoded), `"publicKey":"pubkey"`)
	require.Contains(t, string(encoded), `"computedShardID":2`)
	require.NotContains(t, string(encoded), "numTrieNodesReceived")
}
