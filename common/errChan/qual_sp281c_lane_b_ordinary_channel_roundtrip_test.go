package errChan_test

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/common/errChan"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryErrChanPublicRoundTripReuse(t *testing.T) {
	t.Parallel()

	channel := errChan.NewErrChanWrapper()
	require.Zero(t, channel.Len())

	for _, value := range []error{errors.New("first label"), errors.New("second label")} {
		channel.WriteInChanNonBlocking(value)
		require.Equal(t, 1, channel.Len())
		require.Same(t, value, channel.ReadFromChanNonBlocking())
		require.Zero(t, channel.Len())
	}
}
