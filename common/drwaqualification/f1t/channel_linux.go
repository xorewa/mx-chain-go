//go:build linux

package f1t

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

var ErrChannelIdentity = errors.New("F1-T channel identity failure")

type Endpoint struct {
	fd int
}

type ProcessIdentity struct {
	PID              int
	StartID          string
	ExecutablePath   string
	ExecutableDevice uint64
	ExecutableInode  uint64
	ExecutableHash   string
	Role             string
	PIDFD            int
}

func NewSocketPair() (*Endpoint, *Endpoint, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	for _, fd := range fds {
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
			_ = unix.Close(fds[0])
			_ = unix.Close(fds[1])
			return nil, nil, err
		}
	}
	return &Endpoint{fd: fds[0]}, &Endpoint{fd: fds[1]}, nil
}

func EndpointFromFD(fd int) (*Endpoint, error) {
	if fd < 0 {
		return nil, ErrChannelIdentity
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		return nil, err
	}
	return &Endpoint{fd: fd}, nil
}

func (endpoint *Endpoint) FD() int { return endpoint.fd }

func (endpoint *Endpoint) DupFD() (int, error) {
	if endpoint == nil || endpoint.fd < 0 {
		return -1, ErrChannelIdentity
	}
	return unix.FcntlInt(uintptr(endpoint.fd), unix.F_DUPFD_CLOEXEC, 3)
}

func (endpoint *Endpoint) Send(packet []byte) error {
	if endpoint == nil || endpoint.fd < 0 || len(packet) == 0 || len(packet) > MaxFrameSize+4 {
		return ErrInvalidFrame
	}
	n, err := unix.SendmsgN(endpoint.fd, packet, nil, nil, unix.MSG_NOSIGNAL)
	if err != nil {
		return err
	}
	if n != len(packet) {
		return fmt.Errorf("%w: short send", ErrInvalidFrame)
	}
	return nil
}

func (endpoint *Endpoint) Receive(expectedPID int) ([]byte, error) {
	if endpoint == nil || endpoint.fd < 0 || expectedPID <= 0 {
		return nil, ErrChannelIdentity
	}
	packet := make([]byte, MaxFrameSize+5)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred)*2)
	n, oobn, flags, _, err := unix.Recvmsg(endpoint.fd, packet, oob, 0)
	if err != nil {
		return nil, err
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n == 0 {
		return nil, fmt.Errorf("%w: truncated packet", ErrInvalidFrame)
	}
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(messages) != 1 {
		return nil, fmt.Errorf("%w: credential cardinality", ErrChannelIdentity)
	}
	credentials, err := unix.ParseUnixCredentials(&messages[0])
	if err != nil || int(credentials.Pid) != expectedPID {
		return nil, fmt.Errorf("%w: sender pid", ErrChannelIdentity)
	}
	return append([]byte(nil), packet[:n]...), nil
}

func (endpoint *Endpoint) ReceiveFrame(expected ProcessIdentity) (Frame, []byte, error) {
	if err := expected.Validate(); err != nil {
		return Frame{}, nil, err
	}
	packet, err := endpoint.Receive(expected.PID)
	if err != nil {
		return Frame{}, nil, err
	}
	frame, err := DecodeFrame(packet)
	if err != nil {
		return Frame{}, nil, err
	}
	if frame.Role != expected.Role || frame.PIDStartID != expected.StartID || frame.ExecutableHash != expected.ExecutableHash {
		return Frame{}, nil, fmt.Errorf("%w: frame process binding", ErrChannelIdentity)
	}
	if err = expected.VerifyLive(); err != nil {
		return Frame{}, nil, err
	}
	return frame, packet, nil
}

// WaitForPeerClose succeeds only on an orderly seqpacket EOF with no payload
// or ancillary data. It is used after the collector has durably sealed and
// closed the evidence interval; process cancellation is never treated as drain.
func (endpoint *Endpoint) WaitForPeerClose() error {
	if endpoint == nil || endpoint.fd < 0 {
		return ErrChannelIdentity
	}
	packet := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	n, oobn, flags, _, err := unix.Recvmsg(endpoint.fd, packet, oob, 0)
	if err != nil {
		return err
	}
	if n != 0 || oobn != 0 || flags != 0 {
		return ErrInvalidFrame
	}
	return nil
}

func (endpoint *Endpoint) Close() error {
	if endpoint == nil || endpoint.fd < 0 {
		return nil
	}
	err := unix.Close(endpoint.fd)
	endpoint.fd = -1
	return err
}

func RawMonotonicNanoseconds() (uint64, error) {
	var timestamp unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &timestamp); err != nil {
		return 0, err
	}
	if timestamp.Sec < 0 || timestamp.Nsec < 0 {
		return 0, errors.New("negative monotonic time")
	}
	seconds := uint64(timestamp.Sec)
	if seconds > (^uint64(0)-uint64(timestamp.Nsec))/1_000_000_000 {
		return 0, errors.New("monotonic time overflow")
	}
	return seconds*1_000_000_000 + uint64(timestamp.Nsec), nil
}

func OpenPIDFD(pid int) (int, error) {
	if pid <= 0 {
		return -1, ErrChannelIdentity
	}
	return unix.PidfdOpen(pid, 0)
}

func WaitPIDFDExit(pidfd int) error {
	if pidfd < 0 {
		return ErrChannelIdentity
	}
	descriptors := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	for {
		count, err := unix.Poll(descriptors, -1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if count != 1 || descriptors[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) == 0 {
			return ErrChannelIdentity
		}
		return nil
	}
}

func CaptureProcessIdentity(pid int, role string, holdPIDFD bool) (ProcessIdentity, error) {
	if pid <= 0 || role == "" {
		return ProcessIdentity{}, ErrChannelIdentity
	}
	identity := ProcessIdentity{PID: pid, Role: role, PIDFD: -1}
	var err error
	if holdPIDFD {
		identity.PIDFD, err = OpenPIDFD(pid)
		if err != nil {
			return ProcessIdentity{}, err
		}
	}
	fail := func(cause error) (ProcessIdentity, error) {
		_ = identity.Close()
		return ProcessIdentity{}, cause
	}
	identity.StartID, err = ProcessStartIdentity(pid)
	if err != nil {
		return fail(err)
	}
	identity.ExecutablePath, identity.ExecutableDevice, identity.ExecutableInode, identity.ExecutableHash, err = executableIdentity(pid)
	if err != nil {
		return fail(err)
	}
	return identity, nil
}

func (identity ProcessIdentity) Validate() error {
	if identity.PID <= 0 || identity.Role == "" || identity.StartID == "" || identity.ExecutablePath == "" ||
		identity.ExecutableDevice == 0 || identity.ExecutableInode == 0 || !isHexDigest(identity.ExecutableHash) {
		return ErrChannelIdentity
	}
	return nil
}

func (identity ProcessIdentity) VerifyLive() error {
	if err := identity.Validate(); err != nil {
		return err
	}
	startID, err := ProcessStartIdentity(identity.PID)
	if err != nil || startID != identity.StartID {
		return fmt.Errorf("%w: process start identity", ErrChannelIdentity)
	}
	path, device, inode, digest, err := executableIdentity(identity.PID)
	if err != nil || path != identity.ExecutablePath || device != identity.ExecutableDevice || inode != identity.ExecutableInode || digest != identity.ExecutableHash {
		return fmt.Errorf("%w: executable identity", ErrChannelIdentity)
	}
	if identity.PIDFD >= 0 {
		if err = unix.PidfdSendSignal(identity.PIDFD, 0, nil, 0); err != nil {
			return fmt.Errorf("%w: pidfd", ErrChannelIdentity)
		}
	}
	return nil
}

func (identity *ProcessIdentity) Close() error {
	if identity == nil || identity.PIDFD < 0 {
		return nil
	}
	err := unix.Close(identity.PIDFD)
	identity.PIDFD = -1
	return err
}

func ProcessStartIdentity(pid int) (string, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", err
	}
	closing := strings.LastIndexByte(string(data), ')')
	if closing < 0 {
		return "", ErrChannelIdentity
	}
	fields := strings.Fields(string(data[closing+1:]))
	if len(fields) < 20 {
		return "", ErrChannelIdentity
	}
	return strconv.Itoa(pid) + ":" + fields[19], nil
}

func ExecutableIdentity(pid int) (string, string, error) {
	path, _, _, digest, err := executableIdentity(pid)
	return path, digest, err
}

func executableIdentity(pid int) (string, uint64, uint64, string, error) {
	procPath := "/proc/" + strconv.Itoa(pid) + "/exe"
	path, err := os.Readlink(procPath)
	if err != nil {
		return "", 0, 0, "", err
	}
	file, err := os.Open(procPath)
	if err != nil {
		return "", 0, 0, "", err
	}
	defer file.Close()
	var stat unix.Stat_t
	if err = unix.Fstat(int(file.Fd()), &stat); err != nil {
		return "", 0, 0, "", err
	}
	hasher := sha256.New()
	if _, err = io.Copy(hasher, file); err != nil {
		return "", 0, 0, "", err
	}
	return path, uint64(stat.Dev), stat.Ino, hex.EncodeToString(hasher.Sum(nil)), nil
}
