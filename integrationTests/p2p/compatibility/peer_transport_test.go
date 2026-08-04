package compatibility

import (
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/integrationTests"
	"github.com/multiversx/mx-chain-go/p2p"
	"github.com/stretchr/testify/require"
)

const qualificationTopic = "mx-chain-go-transport-qualification"

type recordingProcessor struct {
	received chan []byte
	ack      []byte
	accept   func([]byte) bool
}

func (rp *recordingProcessor) ProcessReceivedMessage(message p2p.MessageP2P, fromConnectedPeer core.PeerID, source p2p.MessageHandler) ([]byte, error) {
	payload := append([]byte(nil), message.Data()...)
	if rp.accept != nil && !rp.accept(payload) {
		return []byte{}, nil
	}

	select {
	case rp.received <- payload:
	default:
	}

	if len(rp.ack) > 0 {
		if err := source.SendToConnectedPeer(qualificationTopic, rp.ack, fromConnectedPeer); err != nil {
			return nil, err
		}
	}

	return []byte{}, nil
}

func (rp *recordingProcessor) IsInterfaceNil() bool {
	return rp == nil
}

func requireNetworkQualification(t *testing.T, variable string) {
	t.Helper()
	if os.Getenv(variable) != "1" {
		t.Skipf("set %s=1 to run local peer-transport qualification", variable)
	}
}

func newQualifiedPeers(t *testing.T) (p2p.Messenger, p2p.Messenger) {
	t.Helper()
	sender := integrationTests.CreateMessengerWithNoDiscovery()
	receiver := integrationTests.CreateMessengerWithNoDiscovery()
	t.Cleanup(func() {
		if sender != nil && !sender.IsInterfaceNil() {
			_ = sender.Close()
		}
		if receiver != nil && !receiver.IsInterfaceNil() {
			_ = receiver.Close()
		}
	})
	if sender == nil || sender.IsInterfaceNil() || receiver == nil || receiver.IsInterfaceNil() {
		t.Skip("local socket binding is unavailable in this environment")
	}

	require.NoError(t, sender.CreateTopic(qualificationTopic, true))
	require.NoError(t, receiver.CreateTopic(qualificationTopic, true))
	require.NoError(t, sender.ConnectToPeer(integrationTests.GetConnectableAddress(receiver)))
	receiver.WaitForConnections(10*time.Second, 1)
	require.NotEmpty(t, receiver.ConnectedPeers(), "receiver did not establish a peer connection")

	return sender, receiver
}

// TestPeerTransportQualification verifies the selected TCP/libp2p path with a
// real local peer pair. It is opt-in because it opens local sockets and is not
// appropriate for every unit-test or CI environment.
func TestPeerTransportQualification(t *testing.T) {
	requireNetworkQualification(t, "MX_CHAIN_GO_RUN_NETWORK_QUALIFICATION")

	sender, receiver := newQualifiedPeers(t)
	receiverProcessor := &recordingProcessor{received: make(chan []byte, 1), ack: []byte("ack")}
	senderProcessor := &recordingProcessor{
		received: make(chan []byte, 1),
		accept: func(payload []byte) bool {
			return string(payload) == "ack"
		},
	}
	require.NoError(t, receiver.RegisterMessageProcessor(qualificationTopic, "receiver", receiverProcessor))
	require.NoError(t, sender.RegisterMessageProcessor(qualificationTopic, "sender", senderProcessor))

	sender.Broadcast(qualificationTopic, []byte("qualification"))
	select {
	case payload := <-receiverProcessor.received:
		require.Equal(t, []byte("qualification"), payload)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for receiver to process the broadcast")
	}

	select {
	case payload := <-senderProcessor.received:
		require.Equal(t, []byte("ack"), payload)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for sender to process the acknowledgement")
	}
}

// TestPeerTransportQualificationSoak sends repeated messages for a bounded
// period and checks that the connection remains usable. It is deliberately
// separate from consensus/network soak tests: it validates transport and
// message dispatch only, not chain finality or protocol state.
func TestPeerTransportQualificationSoak(t *testing.T) {
	requireNetworkQualification(t, "MX_CHAIN_GO_RUN_NETWORK_SOAK")

	seconds := 30
	if value := os.Getenv("MX_CHAIN_GO_NETWORK_SOAK_SECONDS"); value != "" {
		parsed, err := strconv.Atoi(value)
		require.NoError(t, err, "MX_CHAIN_GO_NETWORK_SOAK_SECONDS must be an integer")
		require.Greater(t, parsed, 0)
		seconds = parsed
	}

	sender, receiver := newQualifiedPeers(t)
	receiverProcessor := &recordingProcessor{received: make(chan []byte, 1024)}
	require.NoError(t, receiver.RegisterMessageProcessor(qualificationTopic, "soak-receiver", receiverProcessor))

	deadline := time.NewTimer(time.Duration(seconds) * time.Second)
	defer deadline.Stop()
	sent := 0
	for {
		select {
		case <-deadline.C:
			require.Greater(t, sent, 0)
			require.Eventually(t, func() bool {
				return len(receiverProcessor.received) > 0
			}, 5*time.Second, 50*time.Millisecond, "receiver did not process any soak messages")
			return
		default:
		}

		sender.Broadcast(qualificationTopic, []byte(fmt.Sprintf("soak-%d", sent)))
		sent++
		time.Sleep(50 * time.Millisecond)
	}
}
