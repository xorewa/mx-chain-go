package core

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core/pubkeyConverter"
	"github.com/multiversx/mx-chain-go/common"
	converterFactory "github.com/multiversx/mx-chain-go/common/factory"
	"github.com/stretchr/testify/require"
)

// T09-M39: encoding of the loaded public hardfork trigger key is a native
// startup prerequisite even with the trigger disabled. No signing key, key
// ownership, hardfork authority, whole startup or mode admission is proven.
func TestQualDRWALoadedHardforkPublicKeyDenials(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		want error
	}{
		{"empty", "", pubkeyConverter.ErrWrongSize},
		{"short", strings.Repeat("ab", 95), pubkeyConverter.ErrWrongSize},
		{"long", strings.Repeat("ab", 97), pubkeyConverter.ErrWrongSize},
		{"odd_hex", strings.Repeat("a", 191), hex.ErrLength},
		{"invalid_hex", "zz" + strings.Repeat("ab", 95), hex.InvalidByteError('z')},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths, overlay := qualDRWALoadedFiles(t)
			cfg, err := common.LoadMainConfig(paths.MainConfig)
			require.NoError(t, err)
			require.Equal(t, "hex", cfg.ValidatorPubkeyConverter.Type)
			require.Equal(t, 96, cfg.ValidatorPubkeyConverter.Length)
			cfg.Hardfork.EnableTrigger = false
			cfg.Hardfork.PublicKeyToListenFrom = tc.key
			qualDRWAEncodeLoaded(t, paths.MainConfig, cfg)
			loaded, err := common.LoadMainConfig(paths.MainConfig)
			require.NoError(t, err, "native TOML loading alone does not decode this key")
			require.Equal(t, tc.key, loaded.Hardfork.PublicKeyToListenFrom)
			converter, err := converterFactory.NewPubkeyConverter(loaded.ValidatorPubkeyConverter)
			require.NoError(t, err)
			decoded, err := converter.Decode(loaded.Hardfork.PublicKeyToListenFrom)
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, decoded)
			candidate, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true})
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, candidate)
		})
	}
}

func TestQualDRWALoadedHardforkPublicKeyControls(t *testing.T) {
	for _, variant := range []string{"configured", "lowercase_literal", "uppercase_literal"} {
		t.Run(variant, func(t *testing.T) {
			paths, overlay := qualDRWALoadedFiles(t)
			cfg, err := common.LoadMainConfig(paths.MainConfig)
			require.NoError(t, err)
			cfg.Hardfork.EnableTrigger = false
			if variant == "lowercase_literal" {
				cfg.Hardfork.PublicKeyToListenFrom = strings.Repeat("ab", 96)
			} else if variant == "uppercase_literal" {
				cfg.Hardfork.PublicKeyToListenFrom = strings.Repeat("AB", 96)
			}
			qualDRWAEncodeLoaded(t, paths.MainConfig, cfg)
			converter, err := converterFactory.NewPubkeyConverter(cfg.ValidatorPubkeyConverter)
			require.NoError(t, err)
			decoded, err := converter.Decode(cfg.Hardfork.PublicKeyToListenFrom)
			require.NoError(t, err)
			require.Len(t, decoded, 96)
			if variant != "configured" {
				require.Equal(t, bytes.Repeat([]byte{0xab}, 96), decoded)
			}
			candidate, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true})
			require.NoError(t, err)
			require.NotNil(t, candidate)
		})
	}
}
