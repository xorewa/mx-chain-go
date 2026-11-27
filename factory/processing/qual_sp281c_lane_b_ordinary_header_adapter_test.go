package processing

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	testsMocks "github.com/multiversx/mx-chain-go/integrationTests/mock"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/mainFactoryMocks"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryHeaderAdapterError(t *testing.T) {
	header := &block.MetaBlock{Nonce: 1, Round: 2}
	adapterErr := errors.New("ordinary header adapter error")
	var calls int
	f := &processComponentsFactory{
		bootstrapComponents: &mainFactoryMocks.BootstrapComponentsStub{
			ShCoordinator: &testscommon.ShardsCoordinatorMock{CurrentShard: core.MetachainShardId},
		},
		data: &testsMocks.DataComponentsStub{
			BlockChain: &testscommon.ChainHandlerStub{
				SetGenesisHeaderCalled: func(value data.HeaderHandler) error {
					calls++
					require.Same(t, header, value)
					return adapterErr
				},
			},
		},
	}
	actual, stats, err := f.finalizeGenesisHeaders(map[uint32]data.HeaderHandler{core.MetachainShardId: header})
	require.ErrorIs(t, err, adapterErr)
	require.Nil(t, actual)
	require.Nil(t, stats)
	require.Equal(t, 1, calls)
}
