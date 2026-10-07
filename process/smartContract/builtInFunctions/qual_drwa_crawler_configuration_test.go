package builtInFunctions

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/pubkeyConverter"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/stretchr/testify/require"
)

// L35 candidate for three shards, not configuration admission. These are
// native-verifier-rejected small-order encodings, rather than unknown keys.
// Native crypto-go v1.3.3 singlesig/ed25519.go rejects these before inspecting
// either the message or signature. No claim of off-curve encoding is made.
func TestQualDRWACrawlerConfigurationNativeRejectedAddresses(t *testing.T) {
	encodings := []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	}
	addresses := make([][]byte, len(encodings))
	for i, encoded := range encodings {
		var err error
		addresses[i], err = hex.DecodeString(encoded)
		require.NoError(t, err)
	}
	converter, err := pubkeyConverter.NewBech32PubkeyConverter(32, "erd")
	require.NoError(t, err)
	keyGenerator := signing.NewKeyGenerator(ed25519.NewEd25519())
	signer := &singlesig.Ed25519Signer{}
	for shardID, address := range addresses {
		t.Run(fmt.Sprint(shardID), func(t *testing.T) {
			require.Len(t, address, 32)
			require.False(t, core.IsSmartContractAddress(address))
			require.False(t, core.IsSystemAccountAddress(address))
			coordinator, err := sharding.NewMultiShardCoordinator(3, uint32(shardID))
			require.NoError(t, err)
			require.Equal(t, uint32(shardID), coordinator.ComputeId(address))
			allowed, err := GetAllowedAddress(coordinator, addresses)
			require.NoError(t, err)
			require.Equal(t, address, allowed)
			encoded, err := converter.Encode(address)
			require.NoError(t, err)
			decoded, err := converter.Decode(encoded)
			require.NoError(t, err)
			require.Equal(t, address, decoded)
			publicKey, err := keyGenerator.PublicKeyFromByteArray(address)
			require.NoError(t, err, "native public-key decoding is only a length check here")
			for _, message := range [][]byte{nil, []byte("crawler configuration proof")} {
				for _, signature := range [][]byte{nil, make([]byte, 64), bytes.Repeat([]byte{0xff}, 64)} {
					require.ErrorIs(t, signer.Verify(publicKey, message, signature), crypto.ErrInvalidPublicKey)
				}
			}
			t.Logf("L35 candidate shard=%d hex=%x bech32=%s native rejection=ErrInvalidPublicKey", shardID, address, encoded)
		})
	}
}
