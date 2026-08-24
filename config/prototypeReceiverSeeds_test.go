package config

import (
	"testing"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-core-go/core"
)

func TestPrototypeDRWAReceiverSeedsStockConfigIsExplicitlyEmpty(t *testing.T) {
	t.Parallel()

	cfg := &Config{}
	require.NoError(t, core.LoadTomlFile(cfg, "../cmd/node/config/config.toml"))
	require.Empty(t, cfg.BuiltInFunctions.PrototypeDRWAReceiverSeeds)
}

func TestPrototypeDRWAReceiverSeedsTOMLDecoding(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		tomlInput string
		expected  []PrototypeDRWAReceiverSeedConfig
	}{
		"empty": {
			tomlInput: `[BuiltInFunctions]
`,
		},
		"populated": {
			tomlInput: `[BuiltInFunctions]
[[BuiltInFunctions.PrototypeDRWAReceiverSeeds]]
HolderAddress = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
TokenIdentifier = "TOKEN-abcdef"
InitialBalance = "1000000"
InitialFrozen = true
CEBEpoch = 7
Admitted = true
ValidThroughRound = 1234
`,
			expected: []PrototypeDRWAReceiverSeedConfig{{
				HolderAddress:     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
				TokenIdentifier:   "TOKEN-abcdef",
				InitialBalance:    "1000000",
				InitialFrozen:     true,
				CEBEpoch:          7,
				Admitted:          true,
				ValidThroughRound: 1234,
			}},
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := &Config{}
			require.NoError(t, toml.Unmarshal([]byte(test.tomlInput), cfg))
			require.Equal(t, test.expected, cfg.BuiltInFunctions.PrototypeDRWAReceiverSeeds)
		})
	}
}
