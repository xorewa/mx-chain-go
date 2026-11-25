package initial

import (
	"context"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/api"
	"github.com/stretchr/testify/require"
)

func TestQualInitialNodeFacadeIterateKeysWhileStarting(t *testing.T) {
	t.Parallel()

	inf := &initialNodeFacade{}
	values, nextKeys, blockInfo, err := inf.IterateKeys(context.Background(), "", 0, nil, api.AccountQueryOptions{})

	require.Equal(t, errNodeStarting, err)
	require.Nil(t, values)
	require.Nil(t, nextKeys)
	require.Equal(t, api.BlockInfo{}, blockInfo)
}
