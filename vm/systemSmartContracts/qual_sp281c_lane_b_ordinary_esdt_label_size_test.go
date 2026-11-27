package systemSmartContracts

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryESDTTypeLabelSizes(t *testing.T) {
	t.Parallel()

	// Opaque display text only, not a token type selection or operation.
	require.Equal(t, 14, (&ESDTDataV1{TokenType: []byte("sample")}).Size())
	require.Equal(t, 15, (&ESDTDataV2{TokenType: []byte("display")}).Size())
}
