package drwa

import (
	"encoding/binary"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

func TestQualSP234OrdinaryNativeTypeMapping(t *testing.T) {
	t.Parallel()

	version := make([]byte, 4)
	binary.BigEndian.PutUint32(version, supplyPositionVersion)
	for _, sample := range []struct {
		name string
		kind core.ESDTType
	}{
		{"fungible", core.Fungible},
		{"non_fungible", core.NonFungibleV2},
		{"dynamic_nft", core.DynamicNFT},
		{"semi_fungible", core.SemiFungible},
		{"meta_fungible", core.MetaFungible},
		{"dynamic_sft", core.DynamicSFT},
		{"dynamic_meta", core.DynamicMeta},
	} {
		t.Run(sample.name, func(t *testing.T) {
			encodedType := make([]byte, 4)
			binary.BigEndian.PutUint32(encodedType, uint32(sample.kind))
			decodedType, err := recordFamily(version, []byte("SAMPLE-abcdef"), encodedType)
			require.NoError(t, err)
			require.Equal(t, sample.kind, decodedType)
		})
	}
}
