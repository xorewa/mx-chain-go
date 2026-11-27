package transactionAPI

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryRepeatedDisplayLabels(t *testing.T) {
	t.Parallel()

	expected := map[string]struct{}{"value": {}, "nonce": {}}
	require.Equal(t, expected, sliceToMap([]string{"value", "nonce", "value"}))
}

// Only the local ordinary display-label set is exercised.
func TestQualSP281COrdinaryUnrequestedDisplayLabels(t *testing.T) {
	t.Parallel()

	empty := newFieldsHandler("")
	require.True(t, empty.IsFieldSet(hashField))
	require.False(t, empty.IsFieldSet("value"))
	require.False(t, empty.IsFieldSet("nonce"))

	value := newFieldsHandler("value")
	require.True(t, value.IsFieldSet(hashField))
	require.True(t, value.IsFieldSet("value"))
	require.False(t, value.IsFieldSet("nonce"))

	nonce := newFieldsHandler("nonce")
	require.True(t, nonce.IsFieldSet(hashField))
	require.True(t, nonce.IsFieldSet("nonce"))
	require.False(t, nonce.IsFieldSet("value"))
}
