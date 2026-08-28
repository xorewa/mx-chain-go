package genericMocks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/dataRetriever"
)

func TestChainStorerMockDRWAIdentityZeroValueFailsClosed(t *testing.T) {
	t.Parallel()

	store := &ChainStorerMock{}
	_, err := store.Get(dataRetriever.DRWANetworkIdentityUnit, []byte("key"))
	require.ErrorIs(t, err, dataRetriever.ErrStorerNotFound)
}

func TestChainStorerMockDRWAIdentityConstructorProvidesMissingKeyStore(t *testing.T) {
	t.Parallel()

	store := NewChainStorerMock(0)
	_, err := store.Get(dataRetriever.DRWANetworkIdentityUnit, []byte("key"))
	require.Error(t, err)
	require.NotErrorIs(t, err, dataRetriever.ErrStorerNotFound)
}
