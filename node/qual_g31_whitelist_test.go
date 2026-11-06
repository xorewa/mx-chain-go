package node

import (
	"testing"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
)

// R7 source label for producer-selected fixture inputs bound throughout this file:
// Experimental R7 fixture inputs: LRU cache capacity 10, synthetic transaction key and invalid cache-type
// marker. Register: XV-SP2-81B3C-SWEEP-NODE-NODE-QUAL-G31-WHITELIST; owner replaces or confirms before
// testnet admission.
// Native constants, structural indices/counters and derived assertions retain their source-defined meaning.

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
