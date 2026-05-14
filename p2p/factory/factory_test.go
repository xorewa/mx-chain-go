package factory

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewPeersHolderShouldRejectInvalidPreferredAddress(t *testing.T) {
	holder, err := NewPeersHolder([]string{"invalid peer address"})

	require.Nil(t, holder)
	require.Error(t, err)
}

func TestNewP2PKeyConverterShouldReturnUsableInstance(t *testing.T) {
	converter := NewP2PKeyConverter()

	require.NotNil(t, converter)
	require.False(t, converter.IsInterfaceNil())
}
