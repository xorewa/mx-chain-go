//go:build linux

package f1t

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const leakedDescriptorHelperEnvironment = "DRWA_F1T_LEAKED_DESCRIPTOR_HELPER"

func TestSocketPairAuthenticatesEveryPacket(t *testing.T) {
	left, right, err := NewSocketPair()
	require.NoError(t, err)
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	identity, err := CaptureProcessIdentity(os.Getpid(), "target", true)
	require.NoError(t, err)
	t.Cleanup(func() { _ = identity.Close() })
	frame := validTestFrame(t)
	frame.PIDStartID = identity.StartID
	frame.ExecutableHash = identity.ExecutableHash
	packet, err := EncodeFrame(frame)
	require.NoError(t, err)
	require.NoError(t, left.Send(packet))
	decoded, received, err := right.ReceiveFrame(identity)
	require.NoError(t, err)
	require.Equal(t, packet, received)
	require.Equal(t, "target", decoded.Role)

	require.NoError(t, right.Send(packet))
	_, err = left.Receive(os.Getpid() + 1)
	require.ErrorIs(t, err, ErrChannelIdentity)

	startID, err := ProcessStartIdentity(os.Getpid())
	require.NoError(t, err)
	require.NotEmpty(t, startID)
	_, executableHash, err := ExecutableIdentity(os.Getpid())
	require.NoError(t, err)
	require.Len(t, executableHash, 64)
	pidfd, err := OpenPIDFD(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, unix.Close(pidfd))
	_, err = RawMonotonicNanoseconds()
	require.NoError(t, err)
}

func TestReceiveFrameRejectsBoundIdentityMutation(t *testing.T) {
	left, right, err := NewSocketPair()
	require.NoError(t, err)
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	identity, err := CaptureProcessIdentity(os.Getpid(), "target", false)
	require.NoError(t, err)
	frame := validTestFrame(t)
	frame.PIDStartID = identity.StartID
	frame.ExecutableHash = identity.ExecutableHash
	packet, err := EncodeFrame(frame)
	require.NoError(t, err)
	require.NoError(t, left.Send(packet))
	identity.StartID += "-mutated"
	_, _, err = right.ReceiveFrame(identity)
	require.ErrorIs(t, err, ErrChannelIdentity)
}

func TestLeakedDescriptorSenderPIDIsRejected(t *testing.T) {
	left, right, err := NewSocketPair()
	require.NoError(t, err)
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	dupFD, err := right.DupFD()
	require.NoError(t, err)
	file := os.NewFile(uintptr(dupFD), "f1t-leaked-descriptor")
	command := exec.Command(os.Args[0], "-test.run=TestLeakedDescriptorHelperProcess")
	command.Env = append(os.Environ(), leakedDescriptorHelperEnvironment+"=1")
	command.ExtraFiles = []*os.File{file}
	require.NoError(t, command.Start())
	require.NoError(t, file.Close())
	_, err = left.Receive(os.Getpid())
	require.ErrorIs(t, err, ErrChannelIdentity)
	require.NoError(t, command.Wait())
}

func TestLeakedDescriptorHelperProcess(t *testing.T) {
	if os.Getenv(leakedDescriptorHelperEnvironment) != "1" {
		return
	}
	endpoint, err := EndpointFromFD(3)
	require.NoError(t, err)
	require.NoError(t, endpoint.Send([]byte("leaked-sender")))
	require.NoError(t, endpoint.Close())
}

func TestWaitPIDFDExitObservesExactChildExit(t *testing.T) {
	command := exec.Command("true")
	require.NoError(t, command.Start())
	pidfd, err := OpenPIDFD(command.Process.Pid)
	require.NoError(t, err)
	require.NoError(t, WaitPIDFDExit(pidfd))
	require.NoError(t, unix.Close(pidfd))
	require.NoError(t, command.Wait())
}
