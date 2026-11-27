package logging

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/testscommon"
	logger "github.com/multiversx/mx-chain-logger-go"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryErrorLogRecord(t *testing.T) {
	err := errors.New("sample report error")
	wantArgs := []interface{}{"label", "example", "count", 7, "err", err.Error()}
	calls := 0
	log := &testscommon.LoggerStub{
		LogCalled: func(level logger.LogLevel, message string, args ...interface{}) {
			calls++
			require.Equal(t, logger.LogError, level)
			require.Equal(t, "sample report", message)
			require.Equal(t, wantArgs, args)
		},
	}

	LogErrAsErrorExceptAsDebugIfClosingError(log, err, "sample report", "label", "example", "count", 7, "err", err.Error())
	require.Equal(t, 1, calls)
}
