package txcache

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A plain local Go value has no cached-transaction representation.
func TestQualSP281CCacheValueTypeHandling(t *testing.T) {
	t.Parallel()

	value := struct{ label string }{label: "local sample"}
	decoded, receipt, ok := unwrapCachedTransaction(value)

	require.Nil(t, decoded)
	require.Nil(t, receipt)
	require.False(t, ok)
}
