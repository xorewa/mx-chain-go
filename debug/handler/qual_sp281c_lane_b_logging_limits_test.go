package handler

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	cachetest "github.com/multiversx/mx-chain-go/testscommon/cache"
)

// Exercise local diagnostic bookkeeping only; neither a resolver nor a
// network connection is needed to check the existing identifier length rule.
func TestQualSP281CLoggingIdentifierLimit(t *testing.T) {
	t.Parallel()

	const localTopic = "local diagnostic"
	const stamp = int64(17)
	atLimit := bytes.Repeat([]byte("a"), maxDebugIdentifierSize)
	overLimit := bytes.Repeat([]byte("b"), maxDebugIdentifierSize+1)

	t.Run("received", func(t *testing.T) {
		getCalls := 0
		entry := &event{}
		handler := &interceptorDebugHandler{
			cache: &cachetest.CacherStub{
				GetCalled: func([]byte) (interface{}, bool) {
					getCalls++
					return entry, true
				},
			},
			timestampHandler: func() int64 { return stamp },
		}
		handler.logReceivedHash(localTopic, overLimit)
		require.Zero(t, getCalls)
		require.Zero(t, entry.numReceived)
		require.Zero(t, entry.timestamp)

		handler.logReceivedHash(localTopic, atLimit)
		require.Equal(t, 1, getCalls)
		require.Equal(t, 1, entry.numReceived)
		require.Equal(t, stamp, entry.timestamp)
	})

	t.Run("processed", func(t *testing.T) {
		getCalls, removeCalls := 0, 0
		entry := &event{}
		handler := &interceptorDebugHandler{
			cache: &cachetest.CacherStub{
				GetCalled: func([]byte) (interface{}, bool) {
					getCalls++
					return entry, true
				},
				RemoveCalled: func([]byte) { removeCalls++ },
			},
			timestampHandler: func() int64 { return stamp },
		}
		handler.logProcessedHash(localTopic, overLimit, nil)
		require.Zero(t, getCalls)
		require.Zero(t, removeCalls)
		require.Zero(t, entry.numProcessed)

		note := errors.New("local diagnostic note")
		handler.logProcessedHash(localTopic, atLimit, note)
		require.Equal(t, 1, getCalls)
		require.Zero(t, removeCalls)
		require.Equal(t, 1, entry.numProcessed)
		require.Equal(t, stamp, entry.timestamp)
		require.EqualError(t, entry.lastErr, note.Error())

		handler.logProcessedHash(localTopic, atLimit, nil)
		require.Equal(t, 2, getCalls)
		require.Equal(t, 1, removeCalls)
	})

	t.Run("resolved", func(t *testing.T) {
		removeCalls := 0
		handler := &interceptorDebugHandler{
			cache: &cachetest.CacherStub{
				RemoveCalled: func([]byte) { removeCalls++ },
			},
		}
		handler.LogSucceededToResolveData(localTopic, overLimit)
		require.Zero(t, removeCalls)

		handler.LogSucceededToResolveData(localTopic, atLimit)
		require.Equal(t, 1, removeCalls)
	})
}
