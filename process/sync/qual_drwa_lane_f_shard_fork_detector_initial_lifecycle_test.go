package sync_test

import (
	"testing"

	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/sync"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/chainParameters"
	dataRetrieverMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/stretchr/testify/require"
)

func TestQualDrwaShardForkDetectorInitialLifecycle(t *testing.T) {
	var providers []func() uint64
	tracker := &mock.BlockTrackerMock{
		SetSettledNonceProviderCalled: func(provider func() uint64) {
			providers = append(providers, provider)
		},
	}
	detector, err := sync.NewShardForkDetector(
		&mock.RoundHandlerMock{},
		&testscommon.TimeCacheStub{},
		tracker,
		0,
		0,
		&enableEpochsHandlerMock.EnableEpochsHandlerStub{},
		&testscommon.EnableRoundsHandlerStub{},
		&dataRetrieverMock.ProofsPoolMock{},
		&chainParameters.ChainParametersHandlerStub{},
		testscommon.GetDefaultProcessConfigsHandler(),
		0,
	)
	require.NoError(t, err)
	require.NotNil(t, detector)
	require.Len(t, providers, 1)
	require.NotNil(t, providers[0])
	require.Equal(t, uint64(0), providers[0]())

	// A fresh, empty detector can repeat its initial lifecycle reset.
	// No block, consensus event, or non-genesis state is introduced.
	detector.RestoreToGenesis()
	require.Len(t, providers, 2)
	require.NotNil(t, providers[1])
	require.Equal(t, uint64(0), providers[1]())
}
