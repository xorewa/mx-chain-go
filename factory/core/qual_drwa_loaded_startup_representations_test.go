package core

import (
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core/pubkeyConverter"
	hashFactory "github.com/multiversx/mx-chain-core-go/hashing/factory"
	"github.com/multiversx/mx-chain-core-go/marshal"
	marshalFactory "github.com/multiversx/mx-chain-core-go/marshal/factory"
	"github.com/multiversx/mx-chain-go/common"
	converterFactory "github.com/multiversx/mx-chain-go/common/factory"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

// T09-M24: native representation factories are prerequisites too. No key is
// appointed, no native signing algorithm/codec is qualified by these controls.
func TestQualDRWALoadedStartupRepresentationDenials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*config.Config)
		want   error
	}{
		{"hasher", func(c *config.Config) { c.Hasher.Type = "unknown" }, hashFactory.ErrNoHasherInConfig},
		{"tx_sign_hasher", func(c *config.Config) { c.TxSignHasher.Type = "unknown" }, hashFactory.ErrNoHasherInConfig},
		{"internal_marshalizer", func(c *config.Config) { c.Marshalizer.Type = "unknown" }, marshal.ErrUnknownMarshalizer},
		{"vm_marshalizer", func(c *config.Config) { c.VmMarshalizer.Type = "unknown" }, marshal.ErrUnknownMarshalizer},
		{"tx_marshalizer", func(c *config.Config) { c.TxSignMarshalizer.Type = "unknown" }, marshal.ErrUnknownMarshalizer},
		{"address_converter_type", func(c *config.Config) { c.AddressPubkeyConverter.Type = "unknown" }, state.ErrInvalidPubkeyConverterType},
		{"validator_converter_type", func(c *config.Config) { c.ValidatorPubkeyConverter.Type = "unknown" }, state.ErrInvalidPubkeyConverterType},
		{"address_converter_zero_length", func(c *config.Config) { c.AddressPubkeyConverter.Length = 0 }, pubkeyConverter.ErrInvalidAddressLength},
		{"validator_converter_zero_length", func(c *config.Config) { c.ValidatorPubkeyConverter.Length = 0 }, pubkeyConverter.ErrInvalidAddressLength},
		{"address_converter_odd_length", func(c *config.Config) { c.AddressPubkeyConverter.Length = 31 }, pubkeyConverter.ErrInvalidAddressLength},
		{"validator_converter_odd_length", func(c *config.Config) { c.ValidatorPubkeyConverter.Length = 95 }, pubkeyConverter.ErrInvalidAddressLength},
		{"address_converter_empty_hrp", func(c *config.Config) { c.AddressPubkeyConverter.Hrp = "" }, pubkeyConverter.ErrInvalidHrpPrefix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths, overlay := qualDRWALoadedFiles(t)
			cfg, err := common.LoadMainConfig(paths.MainConfig)
			require.NoError(t, err)
			tc.mutate(cfg)
			qualDRWAEncodeLoaded(t, paths.MainConfig, cfg)
			candidate, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true})
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, candidate)
		})
	}
}

func TestQualDRWALoadedStartupRepresentationNativeControls(t *testing.T) {
	cfg, err := common.LoadMainConfig(qualDRWACandidateGenesisPath(t, "config.toml"))
	require.NoError(t, err)
	require.Equal(t, "blake2b", cfg.Hasher.Type)
	require.Equal(t, "keccak", cfg.TxSignHasher.Type)
	require.Equal(t, "gogo protobuf", cfg.Marshalizer.Type)
	require.Equal(t, "json", cfg.VmMarshalizer.Type)
	require.Equal(t, "json", cfg.TxSignMarshalizer.Type)
	for _, name := range []string{cfg.Hasher.Type, cfg.TxSignHasher.Type} {
		hasher, err := hashFactory.NewHasher(name)
		require.NoError(t, err)
		require.Equal(t, 32, hasher.Size())
	}
	internal, err := marshalFactory.NewMarshalizer(cfg.Marshalizer.Type)
	require.NoError(t, err)
	require.IsType(t, &marshal.GogoProtoMarshalizer{}, internal)
	vm, err := marshalFactory.NewMarshalizer(cfg.VmMarshalizer.Type)
	require.NoError(t, err)
	require.IsType(t, &marshal.JsonMarshalizer{}, vm)
	tx, err := marshalFactory.NewMarshalizer(cfg.TxSignMarshalizer.Type)
	require.NoError(t, err)
	require.IsType(t, &marshal.JsonMarshalizer{}, tx)
	address, err := converterFactory.NewPubkeyConverter(cfg.AddressPubkeyConverter)
	require.NoError(t, err)
	require.Equal(t, 32, address.Len())
	identityPoint := make([]byte, 32)
	identityPoint[0] = 1
	encoded, err := address.Encode(identityPoint)
	require.NoError(t, err)
	require.Equal(t, "erd1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqquwsrdr", encoded)
	validator, err := converterFactory.NewPubkeyConverter(cfg.ValidatorPubkeyConverter)
	require.NoError(t, err)
	require.Equal(t, 96, validator.Len())
	encoded, err = validator.Encode(make([]byte, 96))
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("00", 96), encoded)
}
