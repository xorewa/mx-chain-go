package common_test

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/stretchr/testify/require"
)

// Compare ordinary supplied header DTOs only; no evaluated context or native owner.
func TestQualSP224OrdinaryHeaderDTOTimeParity(t *testing.T) {
	const epoch = uint32(7)
	for _, tc := range []struct {
		name    string
		in      uint64
		modern  bool
		seconds uint64
		millis  uint64
	}{
		{name: "seconds", in: 314, seconds: 314, millis: 314000},
		{name: "milliseconds", in: 314159, modern: true, seconds: 314, millis: 314159},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := &enableEpochsHandlerMock.EnableEpochsHandlerStub{
				IsFlagEnabledInEpochCalled: func(flag core.EnableEpochFlag, queriedEpoch uint32) bool {
					require.Equal(t, common.SupernovaFlag, flag)
					require.Equal(t, epoch, queriedEpoch)
					return tc.modern
				},
			}
			for _, header := range []data.HeaderHandler{
				&block.Header{Epoch: epoch, TimeStamp: tc.in},
				&block.MetaBlock{Epoch: epoch, TimeStamp: tc.in},
			} {
				seconds, millis, err := common.GetHeaderTimestamps(header, flags)
				require.NoError(t, err)
				require.Equal(t, tc.seconds, seconds)
				require.Equal(t, tc.millis, millis)
			}
		})
	}
}
