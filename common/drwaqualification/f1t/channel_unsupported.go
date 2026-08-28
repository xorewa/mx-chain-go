//go:build !linux

package f1t

import "errors"

var ErrChannelIdentity = errors.New("F1-T channel unsupported on non-Linux")

type Endpoint struct{}
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

func NewSocketPair() (*Endpoint, *Endpoint, error) { return nil, nil, ErrChannelIdentity }
func EndpointFromFD(int) (*Endpoint, error)        { return nil, ErrChannelIdentity }
func (*Endpoint) FD() int                          { return -1 }
func (*Endpoint) DupFD() (int, error)              { return -1, ErrChannelIdentity }
func (*Endpoint) Send([]byte) error                { return ErrChannelIdentity }
func (*Endpoint) Receive(int) ([]byte, error)      { return nil, ErrChannelIdentity }
func (*Endpoint) ReceiveFrame(ProcessIdentity) (Frame, []byte, error) {
	return Frame{}, nil, ErrChannelIdentity
}
func (*Endpoint) WaitForPeerClose() error      { return ErrChannelIdentity }
func (*Endpoint) Close() error                 { return nil }
func RawMonotonicNanoseconds() (uint64, error) { return 0, ErrChannelIdentity }
func OpenPIDFD(int) (int, error)               { return -1, ErrChannelIdentity }
func WaitPIDFDExit(int) error                  { return ErrChannelIdentity }
func CaptureProcessIdentity(int, string, bool) (ProcessIdentity, error) {
	return ProcessIdentity{}, ErrChannelIdentity
}
func (ProcessIdentity) Validate() error        { return ErrChannelIdentity }
func (ProcessIdentity) VerifyLive() error      { return ErrChannelIdentity }
func (*ProcessIdentity) Close() error          { return nil }
func ProcessStartIdentity(int) (string, error) { return "", ErrChannelIdentity }
func ExecutableIdentity(int) (string, string, error) {
	return "", "", ErrChannelIdentity
}
