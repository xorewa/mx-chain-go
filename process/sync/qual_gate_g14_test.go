package sync_test

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/sync"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/chainParameters"
	"github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/stretchr/testify/require"
)

func TestQualGateG14RoundBounds(t *testing.T) {
	for _, c := range []struct {
		name        string
		current     int64
		headerRound uint64
		err         error
	}{
		{"negative_current", -2, 1, sync.ErrHigherRoundInBlock},
		{"valid_next_round", 0, 1, nil},
		{"unsigned_high_bit", 0, 1 << 63, sync.ErrHigherRoundInBlock},
	} {
		t.Run(c.name, func(t *testing.T) {
			clock := &mock.RoundHandlerMock{IndexForCurrentTimeCalled: func() int64 { return c.current }}
			f, err := sync.NewShardForkDetector(clock, &testscommon.TimeCacheStub{}, &mock.BlockTrackerMock{}, 0, 0,
				&enableEpochsHandlerMock.EnableEpochsHandlerStub{}, &testscommon.EnableRoundsHandlerStub{},
				&dataRetriever.ProofsPoolMock{}, &chainParameters.ChainParametersHandlerStub{},
				testscommon.GetDefaultProcessConfigsHandler(), 0)
			require.NoError(t, err)
			err = f.CheckBlockValidity(&block.Header{Nonce: 1, Round: c.headerRound, PubKeysBitmap: []byte("X")}, []byte("hash"))
			require.ErrorIs(t, err, c.err)
		})
	}
}
