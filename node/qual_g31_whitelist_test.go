package node

import (
	"testing"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
)

func TestQualG31VerifiedWhitelistConstruction(t *testing.T) {
	cfg := &config.Config{WhiteListerVerifiedTxs: config.CacheConfig{Type: "LRU", Capacity: 10}}
	verifier, err := createWhiteListerVerifiedTxs(cfg)
	require.NoError(t, err)
	key := []byte("verified transaction")
	require.False(t, verifier.IsWhiteListedAtLeastOne([][]byte{key}))
	verifier.Add([][]byte{key})
	require.True(t, verifier.IsWhiteListedAtLeastOne([][]byte{key}))
	verifier.Remove([][]byte{key})
	require.False(t, verifier.IsWhiteListedAtLeastOne([][]byte{key}))
	cfg.WhiteListerVerifiedTxs.Type = "G31 invalid cache type"
	verifier, err = createWhiteListerVerifiedTxs(cfg)
	require.Error(t, err)
	require.Nil(t, verifier)
}
