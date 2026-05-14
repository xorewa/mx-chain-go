package epochStart

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"
)

func TestCreateMetaRegistryHandlerShouldMatchHeaderVersion(t *testing.T) {
	handler := CreateMetaRegistryHandler(&block.MetaBlock{})
	require.IsType(t, &block.MetaTriggerRegistry{}, handler)

	handler = CreateMetaRegistryHandler(&block.MetaBlockV3{})
	require.IsType(t, &block.MetaTriggerRegistryV3{}, handler)
}
