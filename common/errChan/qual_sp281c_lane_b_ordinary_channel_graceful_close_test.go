package errChan_test

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/common/errChan"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryErrChanGracefulCloseRetainsValue(t *testing.T) {
	t.Parallel()

	channel := errChan.NewErrChanWrapper()
	value := errors.New("local label")
	channel.WriteInChanNonBlocking(value)
	require.Equal(t, 1, channel.Len())

	channel.Close()
	require.Equal(t, 1, channel.Len())
	require.Same(t, value, channel.ReadFromChanNonBlocking())
	require.Zero(t, channel.Len())
}
