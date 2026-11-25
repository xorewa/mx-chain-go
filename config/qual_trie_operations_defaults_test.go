package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualTrieOperationsConfigWithDefaults(t *testing.T) {
	// These are the shipped [TrieOperations] limits in cmd/node/config/config.toml.
	defaults := TrieOperationsConfig{
		MaxBytes:                10485760,
		MaxLeaves:               10000,
		MaxConcurrentRequests:   2,
		HTTPTimeoutMilliseconds: 5000,
		MaxRequestBodyBytes:     2097152,
	}
	// Use the bounds from the existing node and HTTP trie fixtures.
	explicit := TrieOperationsConfig{
		MaxBytes:                132,
		MaxLeaves:               1,
		MaxConcurrentRequests:   1,
		HTTPTimeoutMilliseconds: 20,
		MaxRequestBodyBytes:     4,
	}

	t.Run("fills zero values", func(t *testing.T) {
		require.Equal(t, defaults, (TrieOperationsConfig{}).WithDefaults())
	})

	t.Run("preserves explicit values", func(t *testing.T) {
		require.Equal(t, explicit, explicit.WithDefaults())
	})

	t.Run("fills only omitted values", func(t *testing.T) {
		input := TrieOperationsConfig{MaxConcurrentRequests: explicit.MaxConcurrentRequests}
		expected := defaults
		expected.MaxConcurrentRequests = explicit.MaxConcurrentRequests

		require.Equal(t, expected, input.WithDefaults())
	})
}
