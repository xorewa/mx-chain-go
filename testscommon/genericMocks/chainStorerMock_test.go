package genericMocks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/dataRetriever"
)

func TestChainStorerMockPrototypeIdentityZeroValueFailsClosed(t *testing.T) {
	t.Parallel()

	store := &ChainStorerMock{}
	_, err := store.Get(dataRetriever.PrototypeNetworkIdentityUnit, []byte("key"))
	require.ErrorIs(t, err, dataRetriever.ErrStorerNotFound)
}

func TestChainStorerMockPrototypeIdentityConstructorProvidesMissingKeyStore(t *testing.T) {
	t.Parallel()

	store := NewChainStorerMock(0)
	_, err := store.Get(dataRetriever.PrototypeNetworkIdentityUnit, []byte("key"))
	require.Error(t, err)
	require.NotErrorIs(t, err, dataRetriever.ErrStorerNotFound)
}
