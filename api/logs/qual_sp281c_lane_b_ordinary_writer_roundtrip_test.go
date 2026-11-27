package logs_test

import (
	"testing"

	"github.com/multiversx/mx-chain-go/api/logs"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryLogWriterDistinctPayloadOrder(t *testing.T) {
	t.Parallel()

	writer := logs.NewLogWriter()
	first := []byte("first")
	second := []byte("second-label")

	for _, payload := range [][]byte{first, second} {
		n, err := writer.Write(payload)
		require.NoError(t, err)
		require.Equal(t, len(payload), n)
	}

	for _, expected := range [][]byte{first, second} {
		payload, ok := writer.ReadBlocking()
		require.True(t, ok)
		require.Equal(t, expected, payload)
	}
}
