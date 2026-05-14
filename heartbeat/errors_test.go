package heartbeat

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHeartbeatSentinelErrorsShouldRemainStable(t *testing.T) {
	require.Equal(t, "nil P2P Messenger", ErrNilMessenger.Error())
	require.Equal(t, "nil private key", ErrNilPrivateKey.Error())
	require.Equal(t, "nil marshaller", ErrNilMarshaller.Error())
	require.Equal(t, "nil AppStatusHandler", ErrNilAppStatusHandler.Error())
	require.Equal(t, "empty topic for sending messages", ErrEmptySendTopic.Error())
	require.Equal(t, "invalid time duration", ErrInvalidTimeDuration.Error())
	require.Equal(t, "nil heartbeat monitor", ErrNilHeartbeatMonitor.Error())
	require.Equal(t, "nil heartbeat sender info provider", ErrNilHeartbeatSenderInfoProvider.Error())
	require.Equal(t, "invalid configuration", ErrInvalidConfiguration.Error())
}
