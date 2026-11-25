package middleware

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281CTrieOperationsInterfaceNil(t *testing.T) {
	t.Parallel()

	t.Run("throttler", func(t *testing.T) {
		var nilReceiver *trieOperationsThrottler
		require.True(t, nilReceiver.IsInterfaceNil())
		require.False(t, (&trieOperationsThrottler{}).IsInterfaceNil())
	})

	t.Run("transport", func(t *testing.T) {
		var nilReceiver *trieOperationsTransport
		require.True(t, nilReceiver.IsInterfaceNil())
		require.False(t, (&trieOperationsTransport{}).IsInterfaceNil())
	})
}
