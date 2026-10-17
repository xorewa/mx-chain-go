package drwa

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/stretchr/testify/require"
)

// T05 unwired production construction. Fixture epoch 10 is not a selected DRWA
// activation profile. These tests exercise the unbound primitive; native-hook
// ownership and actual record dataflow are exercised by the T42 qualifiers.
func qualHeaderTimeOwner(t *testing.T) *EvaluatedHeaderTime {
	t.Helper()
	p, _ := qualHeaderTimeOwnerAndFlags(t)
	return p
}

func qualHeaderTimeOwnerAndFlags(t *testing.T) (*EvaluatedHeaderTime, *enableEpochsHandlerMock.EnableEpochsHandlerStub) {
	t.Helper()
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	flags.IsFlagEnabledInEpochCalled = func(flag core.EnableEpochFlag, epoch uint32) bool {
		return flag == common.SupernovaFlag && epoch >= 10
	}
	flags.GetCurrentEpochCalled = func() uint32 { t.Fatal("notification epoch is not the evaluated header epoch"); return 0 }
	p, err := NewEvaluatedHeaderTime(flags, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b())
	require.NoError(t, err)
	return p, flags
}

func TestQualDRWAProductionHeaderTime(t *testing.T) {
	for _, locus := range []string{"shard", "meta"} {
		for _, name := range []string{"valid", "zero", "max_uint64", "end", "reset", "ABA", "failed_begin", "legacy_header", "before_supernova", "input_mutation", "equal_coordinates", "activation_lost"} {
			t.Run(locus+"/"+name, func(t *testing.T) {
				p, flags := qualHeaderTimeOwnerAndFlags(t)
				var header data.HeaderHandler = &block.HeaderV3{Epoch: 10, ShardID: 1, TimestampMs: 1234567, ChainID: []byte("fixture-A")}
				if locus == "meta" {
					header = &block.MetaBlockV3{Epoch: 10, TimestampMs: 1234567, ChainID: []byte("fixture-A")}
				}
				if name == "zero" {
					require.NoError(t, header.SetTimeStamp(0))
				}
				if name == "max_uint64" {
					require.NoError(t, header.SetTimeStamp(^uint64(0)))
				}
				context, err := p.Begin(header)
				require.NoError(t, err)
				value, err := context.Milliseconds()
				require.NoError(t, err)
				require.Equal(t, HeaderMilliseconds(header.GetTimeStamp()), value)
				expectedIdentity, err := core.CalculateHash(&marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), header)
				require.NoError(t, err)
				identity, shard := context.HeaderIdentity()
				require.Equal(t, expectedIdentity, identity)
				require.Equal(t, header.GetShardID(), shard)
				identity[0] ^= 1
				identity, _ = context.HeaderIdentity()
				require.Equal(t, expectedIdentity, identity, "identity ownership cannot leak through returned bytes")
				switch name {
				case "valid", "zero", "max_uint64":
					return
				case "end":
					p.End(context)
					p.End(context)
				case "reset":
					p.Reset()
				case "ABA":
					second := header.ShallowClone()
					require.NoError(t, second.SetTimeStamp(7654321))
					_, err = p.Begin(second)
					require.NoError(t, err)
					next, beginErr := p.Begin(header)
					require.NoError(t, beginErr)
					p.End(context)
					_, err = next.Milliseconds()
					require.NoError(t, err, "old End cannot close a new operation")
				case "failed_begin":
					next, beginErr := p.Begin(nil)
					require.ErrorIs(t, beginErr, common.ErrNilHeaderHandler)
					require.Nil(t, next)
				case "legacy_header":
					_, err = p.Begin(&block.Header{Epoch: 10, TimeStamp: 1234})
					require.ErrorIs(t, err, ErrUnavailableHeaderTime)
				case "before_supernova":
					next := header.ShallowClone()
					require.NoError(t, next.SetEpoch(9))
					_, err = p.Begin(next)
					require.ErrorIs(t, err, ErrUnavailableHeaderTime)
				case "activation_lost":
					flags.IsFlagEnabledInEpochCalled = func(core.EnableEpochFlag, uint32) bool { return false }
					_, err = context.Milliseconds()
					require.ErrorIs(t, err, ErrUnavailableHeaderTime)
					return
				case "input_mutation":
					// The component owns immutable header coordinates and identity,
					// rather than exposing an alias of the input to its consumer.
					require.NoError(t, header.SetTimeStamp(7654321))
					require.NoError(t, header.SetChainID([]byte("mutated")))
					value, err = context.Milliseconds()
					require.NoError(t, err)
					require.Equal(t, HeaderMilliseconds(1234567), value)
					identity, _ = context.HeaderIdentity()
					require.Equal(t, expectedIdentity, identity)
					return
				case "equal_coordinates":
					next := header.ShallowClone()
					require.NoError(t, next.SetChainID([]byte("fixture-B")))
					nextContext, beginErr := p.Begin(next)
					require.NoError(t, beginErr)
					nextIdentity, _ := nextContext.HeaderIdentity()
					require.False(t, bytes.Equal(expectedIdentity, nextIdentity))
				}
				_, err = context.Milliseconds()
				require.ErrorIs(t, err, ErrInactiveHeaderTime)
			})
		}
	}
}

func TestQualDRWAProductionHeaderTimeConcurrentReset(t *testing.T) {
	p := qualHeaderTimeOwner(t)
	context, err := p.Begin(&block.HeaderV3{Epoch: 10, TimestampMs: 1234567})
	require.NoError(t, err)
	var wg sync.WaitGroup
	errorsSeen := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			value, readErr := context.Milliseconds()
			if readErr != nil && !errors.Is(readErr, ErrInactiveHeaderTime) {
				errorsSeen <- readErr
				return
			}
			if readErr == nil && value != 1234567 {
				errorsSeen <- errors.New("mixed coordinate")
				return
			}
		}
	}()
	p.Reset()
	wg.Wait()
	close(errorsSeen)
	for readErr := range errorsSeen {
		require.NoError(t, readErr)
	}
	_, err = context.Milliseconds()
	require.ErrorIs(t, err, ErrInactiveHeaderTime)
	var missing *HeaderTimeContext
	_, err = missing.Milliseconds()
	require.ErrorIs(t, err, ErrInactiveHeaderTime)
}
