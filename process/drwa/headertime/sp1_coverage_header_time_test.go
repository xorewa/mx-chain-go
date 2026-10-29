package headertime_test

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	nodeErrors "github.com/multiversx/mx-chain-go/errors"
	ht "github.com/multiversx/mx-chain-go/process/drwa/headertime"
	"github.com/multiversx/mx-chain-go/testscommon"
	epochs "github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func sp1Dependencies(t *testing.T) (*epochs.EnableEpochsHandlerStub, *marshallerMock.MarshalizerStub, *testscommon.HasherStub) {
	t.Helper()
	flags := epochs.NewEnableEpochsHandlerStub()
	flags.IsFlagEnabledInEpochCalled = func(flag core.EnableEpochFlag, epoch uint32) bool { return flag == common.SupernovaFlag && epoch >= 10 }
	flags.GetCurrentEpochCalled = func() uint32 { t.Fatal("notification epoch substituted for evaluated epoch"); return 0 }
	marsh := &marshallerMock.MarshalizerStub{MarshalCalled: func(interface{}) ([]byte, error) { return []byte("synthetic evaluated header encoding"), nil }}
	hash := &testscommon.HasherStub{SizeCalled: func() int { return 32 }, ComputeCalled: func(s string) []byte { x := sha256.Sum256([]byte(s)); return x[:] }}
	return flags, marsh, hash
}
func sp1Clock(t *testing.T) *ht.EvaluatedHeaderTime {
	t.Helper()
	f, m, h := sp1Dependencies(t)
	p, err := ht.NewEvaluatedHeaderTime(f, m, h)
	require.NoError(t, err)
	return p
}
func sp1Begin(t *testing.T, p *ht.EvaluatedHeaderTime) *ht.HeaderTimeContext {
	t.Helper()
	c, err := p.BeginBound(&block.HeaderV3{Epoch: 10, ShardID: 1, TimestampMs: 1234567}, func() (func(), error) { return func() {}, nil }, func() error { return nil })
	require.NoError(t, err)
	return c
}
func TestSP1CoverageHeaderTimeDependencies(t *testing.T) {
	f, m, h := sp1Dependencies(t)
	p, err := ht.NewEvaluatedHeaderTime(nil, m, h)
	require.Nil(t, p)
	require.ErrorIs(t, err, nodeErrors.ErrNilEnableEpochsHandler)
	p, err = ht.NewEvaluatedHeaderTime(f, nil, h)
	require.Nil(t, p)
	require.ErrorIs(t, err, nodeErrors.ErrNilMarshalizer)
	p, err = ht.NewEvaluatedHeaderTime(f, m, nil)
	require.Nil(t, p)
	require.ErrorIs(t, err, nodeErrors.ErrNilHasher)
	var absent *ht.EvaluatedHeaderTime
	require.True(t, absent.IsInterfaceNil())
	_, err = absent.EvaluatedHeaderTimeContext()
	require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
	p = sp1Clock(t)
	require.False(t, p.IsInterfaceNil())
	_, err = p.EvaluatedHeaderTimeContext()
	require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
}

// Architecture L550-568: the evaluated header supplies epoch, identity and raw ms.
func TestSP1CoverageHeaderTimeCoordinate(t *testing.T) {
	for _, header := range []data.HeaderHandler{&block.HeaderV3{Epoch: 10, ShardID: 1, TimestampMs: 1234567}, &block.MetaBlockV3{Epoch: 10, TimestampMs: 1234567}} {
		p := sp1Clock(t)
		acquired, released := 0, 0
		c, err := p.BeginBound(header, func() (func(), error) { acquired++; return func() { released++ }, nil }, func() error { return nil })
		require.NoError(t, err)
		current, err := p.EvaluatedHeaderTimeContext()
		require.NoError(t, err)
		require.Same(t, c, current)
		ms, epoch, release, err := c.Lease()
		require.NoError(t, err)
		require.Equal(t, ht.HeaderMilliseconds(1234567), ms)
		require.Equal(t, uint32(10), epoch)
		require.Equal(t, 0, released)
		release()
		require.Equal(t, 1, acquired)
		require.Equal(t, 1, released)
		ms, err = c.Milliseconds()
		require.NoError(t, err)
		require.Equal(t, ht.HeaderMilliseconds(1234567), ms)
		require.Equal(t, 2, released)
		identity, shard := c.HeaderIdentity()
		want := sha256.Sum256([]byte("synthetic evaluated header encoding"))
		require.Equal(t, want[:], identity)
		require.Equal(t, header.GetShardID(), shard)
		identity[0] ^= 255
		again, _ := c.HeaderIdentity()
		require.Equal(t, want[:], again)
		p.Reset()
		_, err = c.Milliseconds()
		require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
		require.Equal(t, 3, released)
	}
	var absent *ht.HeaderTimeContext
	hash, shard := absent.HeaderIdentity()
	require.Nil(t, hash)
	require.Zero(t, shard)
	for _, c := range []*ht.HeaderTimeContext{nil, {}} {
		_, err := c.Milliseconds()
		require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
	}
}
func TestSP1CoverageHeaderTimeDeniedInstallation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header data.HeaderHandler
		want   error
	}{
		{"nil", nil, common.ErrNilHeaderHandler}, {"legacy", &block.Header{Epoch: 10, TimeStamp: 1234}, ht.ErrUnavailableHeaderTime},
		{"pre activation", &block.HeaderV3{Epoch: 9, TimestampMs: 1234567}, ht.ErrUnavailableHeaderTime},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := sp1Clock(t)
			old := sp1Begin(t, p)
			c, err := p.BeginBound(tc.header, func() (func(), error) { return func() {}, nil }, func() error { return nil })
			require.Nil(t, c)
			require.ErrorIs(t, err, tc.want)
			_, err = old.Milliseconds()
			require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
		})
	}
	f, m, h := sp1Dependencies(t)
	sentinel := errors.New("marshal unavailable")
	m.MarshalCalled = func(interface{}) ([]byte, error) { return nil, sentinel }
	p, err := ht.NewEvaluatedHeaderTime(f, m, h)
	require.NoError(t, err)
	_, err = p.BeginBound(&block.HeaderV3{Epoch: 10}, func() (func(), error) { return func() {}, nil }, func() error { return nil })
	require.ErrorIs(t, err, sentinel)
	for _, missingAcquire := range []bool{true, false} {
		p := sp1Clock(t)
		old := sp1Begin(t, p)
		acquire := func() (func(), error) { return func() {}, nil }
		validate := func() error { return nil }
		if missingAcquire {
			acquire = nil
		} else {
			validate = nil
		}
		_, err := p.BeginBound(&block.HeaderV3{Epoch: 10}, acquire, validate)
		require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
		_, err = old.Milliseconds()
		require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
	}
}
func TestSP1CoverageHeaderTimeLeaseFailure(t *testing.T) {
	for _, failure := range []string{"acquire", "validate", "activation", "replacement"} {
		t.Run(failure, func(t *testing.T) {
			f, m, h := sp1Dependencies(t)
			p, err := ht.NewEvaluatedHeaderTime(f, m, h)
			require.NoError(t, err)
			sentinel := errors.New("native lease failure")
			armed := false
			releases := 0
			c, err := p.BeginBound(&block.HeaderV3{Epoch: 10, TimestampMs: 1234567}, func() (func(), error) {
				if armed && failure == "acquire" {
					return nil, sentinel
				}
				return func() { releases++ }, nil
			}, func() error {
				if armed && failure == "validate" {
					return sentinel
				}
				return nil
			})
			require.NoError(t, err)
			armed = true
			want := sentinel
			if failure == "activation" {
				f.IsFlagEnabledInEpochCalled = func(core.EnableEpochFlag, uint32) bool { return false }
				want = ht.ErrUnavailableHeaderTime
			}
			if failure == "replacement" {
				sp1Begin(t, p)
				want = ht.ErrInactiveHeaderTime
			}
			ms, epoch, release, err := c.Lease()
			require.ErrorIs(t, err, want)
			require.Zero(t, ms)
			require.Zero(t, epoch)
			require.Nil(t, release)
			if failure == "acquire" {
				require.Zero(t, releases)
			} else {
				require.Equal(t, 1, releases)
			}
		})
	}
}
func TestSP1CoverageWithHeaderTime(t *testing.T) {
	sentinel := errors.New("execution failed")
	for _, mode := range []string{"nil source", "nil context", "empty source", "different context", "acquire", "execute error", "reset", "success"} {
		t.Run(mode, func(t *testing.T) {
			p := sp1Clock(t)
			c := sp1Begin(t, p)
			var source ht.HeaderTimeSource = p
			expected := ht.ErrInactiveHeaderTime
			switch mode {
			case "nil source":
				source = nil
			case "nil context":
				c = nil
			case "empty source":
				p.Reset()
			case "different context":
				sp1Begin(t, p)
			case "acquire":
				var err error
				c, err = p.BeginBound(&block.HeaderV3{Epoch: 10, TimestampMs: 1234567}, func() (func(), error) { return nil, sentinel }, func() error { return nil })
				require.NoError(t, err)
				expected = sentinel
			case "execute error":
				expected = sentinel
			case "success":
				expected = nil
			}
			calls := 0
			out := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}
			got, err := ht.WithHeaderTime(source, c, func() (*vmcommon.VMOutput, error) {
				calls++
				if mode == "reset" {
					p.Reset()
				}
				if mode == "execute error" {
					return out, sentinel
				}
				return out, nil
			})
			require.ErrorIs(t, err, expected)
			if mode == "success" || mode == "execute error" {
				require.Same(t, out, got)
			} else {
				require.Nil(t, got)
			}
			if mode == "success" || mode == "execute error" || mode == "reset" {
				require.Equal(t, 1, calls)
			} else {
				require.Zero(t, calls)
			}
		})
	}
}
